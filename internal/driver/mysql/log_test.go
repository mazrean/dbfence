package mysql

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/mazrean/dbfence/internal/model"
	"github.com/mazrean/dbfence/internal/secret"
)

// evilPlugin is an authentication plugin name with terminal escapes,
// which go-sql-driver/mysql logs as an unknown plugin.
const evilPlugin = "\x1b]0;owned\x07\x1b[2Jevil"

// fakeHandshake is a MySQL protocol 10 handshake asking for plugin.
func fakeHandshake(plugin string) []byte {
	var p bytes.Buffer
	p.WriteByte(10)
	p.WriteString("8.0.0\x00")
	p.Write([]byte{1, 0, 0, 0})
	p.WriteString("abcdefgh")
	p.WriteByte(0)
	_ = binary.Write(&p, binary.LittleEndian, uint16(0x0001|0x0200|0x8000))
	p.WriteByte(45)
	p.Write([]byte{2, 0})
	_ = binary.Write(&p, binary.LittleEndian, uint16(0x0008))
	p.WriteByte(21)
	p.Write(make([]byte, 10))
	p.WriteString("ijklmnopqrst\x00")
	p.WriteString(plugin + "\x00")
	body := p.Bytes()
	return append([]byte{byte(len(body)), byte(len(body) >> 8), byte(len(body) >> 16), 0}, body...)
}

// openFake runs Open against a server that sends the handshake of
// fakeHandshake(evilPlugin) and hangs up.
func openFake(t *testing.T) {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = c.Write(fakeHandshake(evilPlugin))
		time.Sleep(200 * time.Millisecond)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if d, err := Open(ctx, model.Connection{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, User: "u", Password: "Pw9xYz12", TLS: model.TLSDisable, ConnectTimeout: 2 * time.Second}); err == nil {
		_ = d.Close()
		t.Fatal("Open succeeded against a fake server")
	}
}

// TestDriverLogDefault checks that, before SetLogOutput, nothing the
// driver logs reaches the process standard error, which would bypass
// the output sink.
func TestDriverLogDefault(t *testing.T) {
	if os.Getenv("DBFENCE_LOG_CHILD") == "1" {
		openFake(t)
		return
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestDriverLogDefault$")
	cmd.Env = append(os.Environ(), "DBFENCE_LOG_CHILD=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = io.Discard
	if err := cmd.Run(); err != nil {
		t.Fatalf("child: %v\n%s", err, stderr.String())
	}
	if strings.Contains(stderr.String(), "\x1b") || strings.Contains(stderr.String(), "[mysql]") {
		t.Errorf("driver logged to os.Stderr: %q", stderr.String())
	}
}

// TestSetLogOutput checks that the driver's messages go to the given
// writer, where the sink escapes them.
func TestSetLogOutput(t *testing.T) {
	var buf bytes.Buffer
	w := secret.NewWriter(&buf, secret.NewRegistry())
	if err := SetLogOutput(w); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = SetLogOutput(io.Discard) })
	openFake(t)
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, `[mysql] `) || !strings.Contains(got, `\x1b]0;owned\a\x1b[2Jevil`) {
		t.Errorf("log output = %q, want the plugin message with escapes", got)
	}
	if strings.Contains(got, "\x1b") {
		t.Errorf("log output = %q has raw control characters", got)
	}
}
