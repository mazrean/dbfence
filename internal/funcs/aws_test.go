package funcs

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/sivchari/kumo"
	"github.com/zclconf/go-cty/cty"
)

// TestAWS runs the real AWS backends against the kumo emulator. The SDK
// picks the emulator up through the standard AWS_ENDPOINT_URL variables,
// so subtests cannot run in parallel with other tests.
func TestAWS(t *testing.T) {
	srv := kumo.NewServer()
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	for k, v := range map[string]string{
		"AWS_ENDPOINT_URL":            srv.URL,
		"AWS_ENDPOINT_URL_S3":         srv.URL,
		"AWS_ACCESS_KEY_ID":           "test",
		"AWS_SECRET_ACCESS_KEY":       "test",
		"AWS_REGION":                  "us-east-1",
		"AWS_CONFIG_FILE":             filepath.Join(dir, "config"),
		"AWS_SHARED_CREDENTIALS_FILE": filepath.Join(dir, "credentials"),
		"AWS_PROFILE":                 "",
	} {
		t.Setenv(k, v)
	}
	seed(t, srv.URL)

	tests := []struct {
		name    string
		expr    string
		want    cty.Value
		wantErr string
	}{
		{"secret plain", `aws_secretsmanager("plain")`, cty.StringVal("hunter2"), ""},
		{"secret json key", `aws_secretsmanager("db/admin", "password")`, cty.StringVal("p@ss"), ""},
		{"secret json number", `aws_secretsmanager("db/admin", "port")`, cty.StringVal("5432"), ""},
		{"secret jsondecode", `jsondecode(aws_secretsmanager("db/admin")).username`, cty.StringVal("admin"), ""},
		{"secret missing key", `aws_secretsmanager("db/admin", "nope")`, cty.NilVal, `key "nope" not found`},
		{"secret not json", `aws_secretsmanager("plain", "k")`, cty.NilVal, "not a JSON object"},
		{"secret missing", `aws_secretsmanager("missing")`, cty.NilVal, `get secret "missing"`},
		{"tfstate s3 attribute", `tfstate("s3://tfstate/prod/terraform.tfstate", "aws_db_instance.main.address")`, cty.StringVal("main.rds.amazonaws.com"), ""},
		{"tfstate s3 output", `tfstate("s3://tfstate/prod/terraform.tfstate", "output.db_host")`, cty.StringVal("db.internal"), ""},
		{"tfstate s3 missing object", `tfstate("s3://tfstate/none.tfstate", "output.db_host")`, cty.NilVal, "failed to read tfstate"},
	}
	r := NewRegistry(t.Context())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := eval(t, r, tt.expr)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !got.RawEquals(tt.want) {
				t.Errorf("got %#v, want %#v", got, tt.want)
			}
		})
	}

	t.Run("secrets are cached", func(t *testing.T) {
		r := NewRegistry(t.Context())
		if _, err := eval(t, r, `aws_secretsmanager("rotating")`); err != nil {
			t.Fatal(err)
		}
		putSecret(t, srv.URL, "rotating", "v2", false)
		got, err := eval(t, r, `aws_secretsmanager("rotating")`)
		if err != nil {
			t.Fatal(err)
		}
		if got.AsString() != "v1" {
			t.Errorf("second call = %q, want cached v1", got.AsString())
		}
	})
}

func awsConfig(endpoint string) aws.Config {
	return aws.Config{
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider("test", "test", ""),
		BaseEndpoint: aws.String(endpoint),
	}
}

func putSecret(t *testing.T, endpoint, name, value string, create bool) {
	t.Helper()
	c := secretsmanager.NewFromConfig(awsConfig(endpoint))
	var err error
	if create {
		_, err = c.CreateSecret(t.Context(), &secretsmanager.CreateSecretInput{Name: aws.String(name), SecretString: aws.String(value)})
	} else {
		_, err = c.PutSecretValue(t.Context(), &secretsmanager.PutSecretValueInput{SecretId: aws.String(name), SecretString: aws.String(value)})
	}
	if err != nil {
		t.Fatalf("put secret %s: %v", name, err)
	}
}

func seed(t *testing.T, endpoint string) {
	t.Helper()
	putSecret(t, endpoint, "plain", "hunter2", true)
	putSecret(t, endpoint, "db/admin", `{"username":"admin","password":"p@ss","port":5432}`, true)
	putSecret(t, endpoint, "rotating", "v1", true)

	c := s3.NewFromConfig(awsConfig(endpoint), func(o *s3.Options) { o.UsePathStyle = true })
	if _, err := c.CreateBucket(t.Context(), &s3.CreateBucketInput{Bucket: aws.String("tfstate")}); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	body, err := testdata.ReadFile("testdata/terraform.tfstate")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.PutObject(t.Context(), &s3.PutObjectInput{
		Bucket: aws.String("tfstate"), Key: aws.String("prod/terraform.tfstate"), Body: strings.NewReader(string(body)),
	}); err != nil {
		t.Fatalf("put tfstate: %v", err)
	}
}
