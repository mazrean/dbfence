package mysql

import (
	"fmt"
	"io"
	"log"
	"sync/atomic"

	gomysql "github.com/go-sql-driver/mysql"
)

// logger receives the messages go-sql-driver/mysql logs, such as an
// unknown authentication plugin the server asked for. Its default
// writes to os.Stderr, which would bypass the output sink and print
// server-controlled text, control characters included, as is; until
// SetLogOutput is called the messages are dropped.
var logger atomic.Pointer[gomysql.Logger]

func init() {
	var nop gomysql.Logger = &gomysql.NopLogger{}
	logger.Store(&nop)
}

// SetLogOutput sends the messages of go-sql-driver/mysql to w, which
// is the program's error stream (a secret.Writer) so that they are
// escaped and redacted like all other output.
func SetLogOutput(w io.Writer) error {
	var l gomysql.Logger = log.New(w, "[mysql] ", 0)
	logger.Store(&l)
	// Configs parsed elsewhere start with the driver's default logger.
	if err := gomysql.SetLogger(l); err != nil {
		return fmt.Errorf("set mysql logger: %w", err)
	}
	return nil
}
