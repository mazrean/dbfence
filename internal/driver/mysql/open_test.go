package mysql

import (
	"strings"
	"testing"
	"time"
)

func TestParseDSN(t *testing.T) {
	t.Parallel()
	tests := []struct {
		dsn         string
		wantErr     string
		wantTimeout time.Duration
	}{
		{dsn: "root:pw@tcp(127.0.0.1:3306)/", wantTimeout: defaultTimeout},
		{dsn: "root:pw@tcp(127.0.0.1:3306)/?timeout=3s", wantTimeout: 3 * time.Second},
		{dsn: "mysql://root:pw@127.0.0.1:3306/db", wantErr: "user:password@tcp(host:3306)/"},
		{dsn: "root:pw@127.0.0.1:3306/db", wantErr: "user:password@tcp(host:3306)/"},
	}
	for _, tt := range tests {
		cfg, err := parseDSN(tt.dsn)
		switch {
		case tt.wantErr != "":
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("parseDSN(%q) error = %v, want %q", tt.dsn, err, tt.wantErr)
			}
			if err != nil && strings.Contains(err.Error(), "pw") {
				t.Errorf("parseDSN(%q) error leaks the password: %v", tt.dsn, err)
			}
		case err != nil:
			t.Errorf("parseDSN(%q): %v", tt.dsn, err)
		case cfg.Timeout != tt.wantTimeout:
			t.Errorf("parseDSN(%q) timeout = %v, want %v", tt.dsn, cfg.Timeout, tt.wantTimeout)
		}
	}
}

func TestCheckCharset(t *testing.T) {
	t.Parallel()
	for cs, ok := range map[string]bool{"utf8mb4": true, "latin1": true, "utf8mb3": true, "binary": true, "sjis": false, "GBK": false, "big5": false, "cp932": false, "gb18030": false} {
		if err := checkCharset(cs); (err == nil) != ok {
			t.Errorf("checkCharset(%q) = %v, want ok=%v", cs, err, ok)
		}
	}
}
