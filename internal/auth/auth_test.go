package auth

import (
	"context"
	"errors"
	"strings"
	"testing"

	"cloud.google.com/go/auth"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/mazrean/dbfence/internal/model"
)

func TestStatic(t *testing.T) {
	t.Parallel()
	got, err := New(model.Connection{Auth: model.AuthPassword, Password: "pw"})(t.Context())
	if err != nil || got != "pw" {
		t.Errorf("New(password)() = %q, %v; want pw", got, err)
	}
}

func TestAWSIAM(t *testing.T) {
	t.Parallel()
	creds := credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "secret", "")
	tests := []struct {
		name, region, cfgRegion, want, wantErr string
	}{
		{name: "region of the block", region: "ap-northeast-1", cfgRegion: "us-east-1", want: "ap-northeast-1"},
		{name: "region of the AWS configuration", cfgRegion: "eu-west-1", want: "eu-west-1"},
		{name: "no region", wantErr: "no AWS region"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			conn := model.Connection{Auth: model.AuthAWSIAM, Host: "db.example.com", Port: 3306, User: "app", AWSRegion: tt.region}
			loads := 0
			src := awsIAM(conn, func(context.Context) (aws.Config, error) {
				loads++
				return aws.Config{Region: tt.cfgRegion, Credentials: creds}, nil
			})
			for range 2 {
				token, err := src(t.Context())
				if tt.wantErr != "" {
					if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
						t.Fatalf("err = %v, want %q", err, tt.wantErr)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				for _, w := range []string{"db.example.com:3306?Action=connect", "DBUser=app", "X-Amz-Credential=AKIDEXAMPLE%2F", "%2F" + tt.want + "%2Frds-db%2F"} {
					if !strings.Contains(token, w) {
						t.Errorf("token %q lacks %q", token, w)
					}
				}
			}
			if loads != 1 {
				t.Errorf("AWS configuration loaded %d times, want once", loads)
			}
		})
	}
}

type fakeTokenProvider struct{ calls int }

func (f *fakeTokenProvider) Token(context.Context) (*auth.Token, error) {
	f.calls++
	return &auth.Token{Value: "ya29.token"}, nil
}

func TestGCPIAM(t *testing.T) {
	t.Parallel()
	p := &fakeTokenProvider{}
	detects := 0
	src := gcpIAM(func() (auth.TokenProvider, error) {
		detects++
		return p, nil
	})
	for range 2 {
		if got, err := src(t.Context()); err != nil || got != "ya29.token" {
			t.Fatalf("token = %q, %v", got, err)
		}
	}
	if detects != 1 || p.calls != 2 {
		t.Errorf("credentials detected %d times and asked %d times, want 1 and 2", detects, p.calls)
	}

	failing := gcpIAM(func() (auth.TokenProvider, error) { return nil, errors.New("no credentials") })
	if _, err := failing(t.Context()); err == nil || !strings.Contains(err.Error(), "gcp_iam: find Google Cloud credentials: no credentials") {
		t.Errorf("err = %v", err)
	}
}

func TestOnceRetriesFailures(t *testing.T) {
	t.Parallel()
	calls := 0
	f := once(func(context.Context) (int, error) {
		calls++
		if calls == 1 {
			return 0, errors.New("transient")
		}
		return calls, nil
	})
	if _, err := f(t.Context()); err == nil {
		t.Fatal("first call succeeded")
	}
	for range 2 {
		if v, err := f(t.Context()); err != nil || v != 2 {
			t.Errorf("f() = %d, %v; want 2", v, err)
		}
	}
}
