package config

import (
	"testing"

	"github.com/mazrean/dbfence/internal/model"
)

func TestLoadRoleAWSIAM(t *testing.T) {
	t.Parallel()
	for _, conn := range []string{pgConn, myConn} {
		cfg, err := load(t, conn+"user \"app\" {\n  aws_iam {}\n}\nrole \"r\" {\n  login = true\n  aws_iam {}\n}\nuser \"p\" {}\n")
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]model.AuthMethod{}
		for _, r := range cfg.Desired.Roles {
			got[r.ID.Name] = r.IAM
		}
		if got["app"] != model.AuthAWSIAM || got["r"] != model.AuthAWSIAM || got["p"] != "" {
			t.Errorf("IAM = %v, want app and r with aws_iam", got)
		}
	}
}

func TestLoadRoleAWSIAMErrors(t *testing.T) {
	t.Parallel()
	runDiagCases(t, []diagCase{
		{
			name:  "with password",
			src:   pgConn + "user \"a\" {\n  password = \"hunter2secret\"\n  aws_iam {}\n}\n",
			want:  []string{"Conflicting authentication", `user "a" cannot set both aws_iam and password`, "dbfence.hcl line 7"},
			deny:  []string{"hunter2secret"},
			count: 1,
		},
		{
			name:  "with auth_plugin",
			src:   myConn + "user \"a\" {\n  auth_plugin = \"auth_socket\"\n  aws_iam {}\n}\n",
			want:  []string{"Conflicting authentication", "aws_iam and auth_plugin"},
			count: 1,
		},
		{
			name:  "role without login",
			src:   pgConn + "role \"a\" {\n  aws_iam {}\n}\n",
			want:  []string{"IAM authentication without login", `role "a" has aws_iam but cannot log in`},
			count: 1,
		},
		{
			name:  "attribute in the block",
			src:   pgConn + "user \"a\" {\n  aws_iam {\n    region = \"x\"\n  }\n}\n",
			want:  []string{"Unsupported argument"},
			count: 1,
		},
		{
			name:  "twice",
			src:   pgConn + "user \"a\" {\n  aws_iam {}\n  aws_iam {}\n}\n",
			want:  []string{"Duplicate aws_iam block"},
			count: 1,
		},
		{
			name:  "other nested block",
			src:   pgConn + "user \"a\" {\n  gcp_iam {}\n}\n",
			want:  []string{"Unsupported block type"},
			count: 1,
		},
	})
}
