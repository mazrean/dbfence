package di

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/mazrean/dbfence/internal/driver/mysql"
	"github.com/mazrean/dbfence/internal/secret"
)

// mysqlHandshake is a MySQL protocol 10 handshake asking for an
// authentication plugin whose name holds terminal escapes, which
// go-sql-driver/mysql logs as unknown.
func mysqlHandshake() []byte {
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
	p.WriteString("\x1b]0;owned\x07\x1b[2Jevil\x00")
	body := p.Bytes()
	return append([]byte{byte(len(body)), byte(len(body) >> 8), byte(len(body) >> 16), 0}, body...)
}

// TestOutputCarriesMySQLLog checks that NewOutput routes the messages of
// go-sql-driver/mysql through the error stream, which escapes them.
func TestOutputCarriesMySQLLog(t *testing.T) {
	if os.Getenv("DBFENCE_DI_CHILD") == "1" {
		o := NewOutput()
		ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write(mysqlHandshake())
			time.Sleep(200 * time.Millisecond)
			_ = c.Close()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if d, err := mysql.Open(ctx, "u:Pw9xYz12@tcp("+ln.Addr().String()+")/?timeout=2s"); err == nil {
			_ = d.Close()
		}
		_ = o.Err.Flush()
		return
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestOutputCarriesMySQLLog$")
	cmd.Env = append(os.Environ(), "DBFENCE_DI_CHILD=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = io.Discard
	if err := cmd.Run(); err != nil {
		t.Fatalf("child: %v\n%s", err, stderr.String())
	}
	got := stderr.String()
	if strings.Contains(got, "\x1b") {
		t.Errorf("stderr = %q has raw control characters from the server", got)
	}
	if !strings.Contains(got, `[mysql] `) || !strings.Contains(got, `\x1b]0;owned`) {
		t.Errorf("stderr = %q, want the driver's message escaped", got)
	}
}

// TestOutputCarriesSDKLogs checks that NewOutput routes the standard log
// package (used by the HCP Terraform client) through the error stream
// and turns off the GCP SDK's default logger, which writes to os.Stderr.
func TestOutputCarriesSDKLogs(t *testing.T) {
	if os.Getenv("DBFENCE_DI_CHILD") == "1" {
		o := NewOutput()
		secret.Register("Sd9LogSecret")
		log.Print("tfe \x1b[2J Sd9LogSecret")
		if v := os.Getenv("GOOGLE_SDK_GO_LOGGING_LEVEL"); v != "" {
			t.Errorf("GOOGLE_SDK_GO_LOGGING_LEVEL = %q after NewOutput, want it unset", v)
		}
		_ = o.Err.Flush()
		return
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestOutputCarriesSDKLogs$")
	cmd.Env = append(os.Environ(), "DBFENCE_DI_CHILD=1", "GOOGLE_SDK_GO_LOGGING_LEVEL=debug")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = io.Discard
	if err := cmd.Run(); err != nil {
		t.Fatalf("child: %v\n%s", err, stderr.String())
	}
	got := stderr.String()
	if strings.Contains(got, "\x1b") || strings.Contains(got, "Sd9LogSecret") {
		t.Errorf("stderr = %q, want the message escaped and redacted", got)
	}
	if !strings.Contains(got, `tfe \x1b[2J `+secret.Placeholder) {
		t.Errorf("stderr = %q, want the log message", got)
	}
}
