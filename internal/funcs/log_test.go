package funcs

import (
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/aws/smithy-go/logging"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const loggedSecret = "GcpPw9LoggedSecret"

type fakeSecretManager struct {
	secretmanagerpb.UnimplementedSecretManagerServiceServer
}

func (fakeSecretManager) AccessSecretVersion(context.Context, *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	return &secretmanagerpb.AccessSecretVersionResponse{
		Name:    "projects/p/secrets/s/versions/1",
		Payload: &secretmanagerpb.SecretPayload{Data: []byte(loggedSecret)},
	}, nil
}

// captureStderr returns what f writes to os.Stderr.
func captureStderr(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan []byte)
	go func() {
		b, _ := io.ReadAll(r)
		done <- b
	}()
	orig := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = orig }()
	f()
	os.Stderr = orig
	_ = w.Close()
	return string(<-done)
}

// TestSDKLogs checks that the cloud SDK clients do not write to
// os.Stderr, which would bypass the output sink, even when their debug
// logging is turned on, and that what they log through SetLogOutput
// leaves out the debug messages that quote secret payloads. The
// subtests change process-wide state and do not run in parallel.
func TestSDKLogs(t *testing.T) {
	lis, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	secretmanagerpb.RegisterSecretManagerServiceServer(srv, fakeSecretManager{})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	tests := []struct {
		name      string
		setOutput bool
	}{
		{name: "before SetLogOutput"},
		{name: "after SetLogOutput", setOutput: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv(gcpLoggingLevel, "debug")
			t.Setenv("AWS_REGION", "us-east-1")
			t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
			t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
			var buf bytes.Buffer
			if tt.setOutput {
				SetLogOutput(&buf)
				t.Cleanup(func() {
					logOutput.Store(nil)
					log.SetOutput(os.Stderr)
				})
			}
			stderr := captureStderr(t, func() {
				g, err := dialGCPSecretManager(t.Context(),
					option.WithEndpoint(lis.Addr().String()),
					option.WithoutAuthentication(),
					option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())))
				if err != nil {
					t.Error(err)
					return
				}
				if v, aerr := g.AccessSecretVersion(t.Context(), "projects/p/secrets/s/versions/1"); aerr != nil || v != loggedSecret {
					t.Errorf("AccessSecretVersion = %q, %v", v, aerr)
				}
				a, err := newAWSSecretsManager(t.Context())
				if err != nil {
					t.Error(err)
					return
				}
				a.(*awsSecretsManager).c.Options().Logger.Logf(logging.Warn, "aws probe")
				if tt.setOutput {
					log.Print("std probe")
				}
			})
			for name, out := range map[string]string{"stderr": stderr, "SetLogOutput": buf.String()} {
				// The payload as is and as protojson prints it (base64).
				for _, s := range []string{loggedSecret, "R2NwUHc5TG9nZ2VkU2VjcmV0"} {
					if strings.Contains(out, s) {
						t.Errorf("%s shows the secret payload:\n%s", name, out)
					}
				}
			}
			if strings.Contains(stderr, "probe") {
				t.Errorf("an SDK logged to os.Stderr:\n%s", stderr)
			}
			if tt.setOutput {
				for _, s := range []string{"aws probe", "std probe"} {
					if !strings.Contains(buf.String(), s) {
						t.Errorf("SetLogOutput output lacks %q:\n%s", s, buf.String())
					}
				}
			}
		})
	}
}
