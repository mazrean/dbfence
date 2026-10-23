// Package di is the wiring file that may use the process streams.
package di

import (
	"io"
	"os"
)

// Streams returns the process output streams.
func Streams() (io.Writer, io.Writer) { return os.Stdout, os.Stderr }
