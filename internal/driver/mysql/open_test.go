package mysql

import (
	"net"
	"strings"
	"testing"
	"time"

	gomysql "github.com/go-sql-driver/mysql"
	"github.com/mazrean/dbfence/internal/model"
)

func TestNewConfig(t *testing.T) {
	t.Parallel()
	tests := []struct {
		wantAddr string
		wantTLS  string
		conn     model.Connection
	}{
		{conn: model.Connection{Host: "db", Port: 3306, TLS: model.TLSDisable}, wantAddr: "db:3306", wantTLS: "false"},
		{conn: model.Connection{Host: "::1", Port: 3307, TLS: model.TLSPrefer}, wantAddr: "[::1]:3307", wantTLS: "preferred"},
		{conn: model.Connection{Host: "db", Port: 3306, TLS: model.TLSRequire}, wantAddr: "db:3306", wantTLS: "skip-verify"},
		{conn: model.Connection{Host: "db", Port: 3306, TLS: model.TLSVerifyFull}, wantAddr: "db:3306", wantTLS: "true"},
	}
	for _, tt := range tests {
		tt.conn.User, tt.conn.Password, tt.conn.Database, tt.conn.ConnectTimeout = "u", "p/w@x", "app", 3*time.Second
		cfg := newConfig(tt.conn)
		switch {
		case cfg.Net != "tcp" || cfg.Addr != tt.wantAddr || cfg.TLSConfig != tt.wantTLS:
			t.Errorf("newConfig(%+v) net = %q, addr = %q, tls = %q, want tcp, %q, %q", tt.conn, cfg.Net, cfg.Addr, cfg.TLSConfig, tt.wantAddr, tt.wantTLS)
		case cfg.User != "u" || cfg.Passwd != "p/w@x" || cfg.DBName != "app" || cfg.Timeout != 3*time.Second:
			t.Errorf("newConfig(%+v) = %+v", tt.conn, cfg)
		case cfg.MultiStatements || cfg.AllowAllFiles:
			t.Errorf("newConfig(%+v) multiStatements = %v, allowAllFiles = %v, want both off", tt.conn, cfg.MultiStatements, cfg.AllowAllFiles)
		}
		// The driver accepts the configuration.
		if _, err := gomysql.NewConnector(cfg); err != nil {
			t.Errorf("NewConnector(newConfig(%+v)): %v", tt.conn, err)
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
	_, err = Open(t.Context(), model.Connection{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, User: "root", Password: "pw",
		TLS: model.TLSDisable, ConnectTimeout: 300 * time.Millisecond})
	if err == nil || !strings.Contains(err.Error(), "timed out after 300ms") {
		t.Errorf("Open() error = %v, want a timeout", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("Open() took %v", d)
	}
}
