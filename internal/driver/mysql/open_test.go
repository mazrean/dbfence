package mysql

import (
	"net"
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
		{dsn: "root:p/w@tcp(127.0.0.1:3306)/", wantTimeout: defaultTimeout},
		// The driver quotes parts of the DSN in its errors.
		{dsn: "admin:pwS3cret/", wantErr: "invalid DSN"},
		{dsn: "admin:pwS3/cret@tcp(db:3306)", wantErr: "invalid DSN"},
		{dsn: "admin:S3/cr%zzpw@tcp(db:3306)", wantErr: "invalid DSN"},
		{dsn: "admin:pwS3/cr?tls=pw@tcp(db:3306)", wantErr: "invalid DSN"},
		// These parse, with part of the password as the network.
		{dsn: "admin:pwS3(et)/x@tcp(db:3306)", wantErr: "the network must be"},
		{dsn: "admin:pwS3(et)/x@tcp(db:3306)?timeout=1s", wantErr: "the network must be"},
		{dsn: "root:pw@udp(127.0.0.1:3306)/", wantErr: "the network must be"},
		{dsn: "root:pw@tcp6([::1]:3306)/", wantTimeout: defaultTimeout},
		{dsn: "root:pw@unix(/tmp/mysql.sock)/", wantTimeout: defaultTimeout},
		{dsn: "/", wantTimeout: defaultTimeout},
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

// TestOpenTimesOutWithoutHandshake checks that Open gives up on a server
// that accepts the connection but never sends the handshake.
func TestOpenTimesOutWithoutHandshake(t *testing.T) {
	t.Parallel()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	start := time.Now()
	_, err = Open(t.Context(), "root:pw@tcp("+ln.Addr().String()+")/?timeout=300ms")
	if err == nil || !strings.Contains(err.Error(), "timed out after 300ms") {
		t.Errorf("Open() error = %v, want a timeout", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("Open() took %v", d)
	}
}

// TestOpenKeepsPasswordOutOfErrors checks that a DSN misparsed at a '/'
// in the password does not reach the dial, whose error names the network.
func TestOpenKeepsPasswordOutOfErrors(t *testing.T) {
	t.Parallel()
	tests := []string{
		"admin:S3cr(et)/pw@tcp(127.0.0.1:1)?timeout=1s",
		"admin:S3cr(et)/pw@tcp(127.0.0.1:1)",
	}
	for _, dsn := range tests {
		_, err := Open(t.Context(), dsn)
		if err == nil || strings.Contains(err.Error(), "S3cr") {
			t.Errorf("Open(%q) error = %v, want an error without the password", dsn, err)
		}
	}
}
