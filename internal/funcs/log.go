package funcs

import (
	"io"
	"log"
	"log/slog"
	"os"
	"sync/atomic"

	azlog "github.com/Azure/azure-sdk-for-go/sdk/azcore/log"
	"github.com/aws/smithy-go/logging"
)

// The cloud SDKs log to os.Stderr by default, which would bypass the
// output sink: the GCP client, with GOOGLE_SDK_GO_LOGGING_LEVEL=debug,
// logs whole responses, secret payloads and state files included. Until
// SetLogOutput is called their messages are dropped.

// gcpLoggingLevel is the variable that turns on the default logger of
// the GCP clients, which writes to os.Stderr.
const gcpLoggingLevel = "GOOGLE_SDK_GO_LOGGING_LEVEL"

// logOutput is where the SDK clients created from now on log; nil
// drops their messages.
var logOutput atomic.Pointer[io.Writer]

// SetLogOutput sends the messages that the cloud SDKs log to w, which is
// the program's error stream (a secret.Writer) so that they are escaped
// and redacted like all other output. Only warnings and errors are kept:
// debug messages quote requests and responses, whose secrets are not
// known yet when they are logged.
//
// The clients that tfstate-lookup creates take no logger, so their
// default loggers are turned off instead: GOOGLE_SDK_GO_LOGGING_LEVEL
// is unset, the Azure SDK's AZURE_SDK_GO_LOGGING listener is removed,
// and the standard log package (used by the HCP Terraform client) writes
// to w.
func SetLogOutput(w io.Writer) {
	logOutput.Store(&w)
	_ = os.Unsetenv(gcpLoggingLevel)
	azlog.SetListener(nil)
	log.SetOutput(w)
}

// SDKLogger returns the logger that the GCP clients log to.
func SDKLogger() *slog.Logger {
	w := logOutput.Load()
	if w == nil {
		return slog.New(slog.DiscardHandler)
	}
	return slog.New(slog.NewTextHandler(*w, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

// awsLogger returns the logger that the AWS clients log to. The AWS
// clients log requests and responses only when asked to in code
// (ClientLogMode), which dbfence never does.
func awsLogger() logging.Logger {
	w := logOutput.Load()
	if w == nil {
		return logging.Nop{}
	}
	return logging.NewStandardLogger(*w)
}
