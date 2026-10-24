package mysql

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gomysql "github.com/go-sql-driver/mysql"
	"github.com/mazrean/dbfence/internal/auth"
	"github.com/mazrean/dbfence/internal/driver/internal/tlstest"
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
		tt.conn.User, tt.conn.Database, tt.conn.ConnectTimeout = "u", "app", 3*time.Second
		cfg, err := newConfig(tt.conn, auth.Static("p/w@x"))
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case cfg.Net != "tcp" || cfg.Addr != tt.wantAddr || cfg.TLSConfig != tt.wantTLS:
			t.Errorf("newConfig(%+v) net = %q, addr = %q, tls = %q, want tcp, %q, %q", tt.conn, cfg.Net, cfg.Addr, cfg.TLSConfig, tt.wantAddr, tt.wantTLS)
		case cfg.User != "u" || cfg.DBName != "app" || cfg.Timeout != 3*time.Second:
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

func TestNewConfigOptions(t *testing.T) {
	t.Parallel()
	base := model.Connection{Engine: model.EngineMySQL, Host: "db", Port: 3306, User: "u", TLS: model.TLSDisable, ConnectTimeout: time.Second}

	sock := base
	sock.Socket = "/run/mysqld/mysqld.sock"
	cfg, err := newConfig(sock, auth.Static(""))
	if err != nil || cfg.Net != "unix" || cfg.Addr != sock.Socket {
		t.Errorf("socket: net = %q, addr = %q, err = %v", cfg.Net, cfg.Addr, err)
	}

	ca := base
	ca.TLS, ca.TLSCAFile = model.TLSVerifyFull, tlstest.CAFile(t)
	cfg, err = newConfig(ca, auth.Static(""))
	if err != nil || cfg.TLS == nil || cfg.TLS.RootCAs == nil || cfg.TLS.ServerName != "db" || cfg.TLS.InsecureSkipVerify {
		t.Errorf("tls_ca_file: TLS = %+v, err = %v", cfg.TLS, err)
	}
	ca.TLSCAFile = filepath.Join(t.TempDir(), "missing.pem")
	if _, err := newConfig(ca, auth.Static("")); err == nil || !strings.Contains(err.Error(), "tls_ca_file") {
		t.Errorf("missing tls_ca_file: err = %v", err)
	}

	for method, want := range map[model.AuthMethod]bool{model.AuthPassword: false, model.AuthAWSIAM: true, model.AuthGCPIAM: true} {
		c := base
		c.Auth = method
		cfg, err := newConfig(c, auth.Static(""))
		if err != nil || cfg.AllowCleartextPasswords != want {
			t.Errorf("%s: allowCleartextPasswords = %v, want %v (err %v)", method, cfg.AllowCleartextPasswords, want, err)
		}
	}
}

// TestOpenAsksForThePassword checks that Open takes the password of a
// connection from the source, and fails with its error.
func TestOpenAsksForThePassword(t *testing.T) {
	t.Parallel()
	conn := model.Connection{Engine: model.EngineMySQL, Host: "127.0.0.1", Port: 1, User: "u", TLS: model.TLSDisable, ConnectTimeout: time.Second}
	_, err := Open(t.Context(), conn, func(context.Context) (string, error) { return "", errors.New("no token today") })
	if err == nil || !strings.Contains(err.Error(), "no token today") {
		t.Errorf("Open() error = %v, want the password source error", err)
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
	_, err = Open(t.Context(), model.Connection{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, User: "root",
		TLS: model.TLSDisable, ConnectTimeout: 300 * time.Millisecond}, auth.Static("pw"))
	if err == nil || !strings.Contains(err.Error(), "timed out after 300ms") {
		t.Errorf("Open() error = %v, want a timeout", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("Open() took %v", d)
	}
}

// TestOpenDialsTheSocket checks that a socket connection dials the
// Unix-domain socket.
func TestOpenDialsTheSocket(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "mysqld.sock")
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan struct{})
	go func() {
		c, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		close(accepted)
		_ = c.Close()
	}()
	conn := model.Connection{Engine: model.EngineMySQL, Socket: path, User: "u", TLS: model.TLSDisable, ConnectTimeout: time.Second}
	if d, err := Open(t.Context(), conn, auth.Static("")); err == nil {
		_ = d.Close()
		t.Fatal("Open() succeeded against a closed connection")
	}
	select {
	case <-accepted:
	default:
		t.Error("Open() did not dial the socket")
	}
}
