package a

import (
	"fmt"
	"io"
	"os"
)

func f(w io.Writer) {
	fmt.Println("x")            // want `fmt.Println bypasses the redacting output sink`
	fmt.Printf("%d\n", 1)       // want `fmt.Printf bypasses the redacting output sink`
	fmt.Print("x")              // want `fmt.Print bypasses the redacting output sink`
	fmt.Fprintln(os.Stdout)     // want `os.Stdout bypasses the redacting output sink`
	_, _ = os.Stderr.Write(nil) // want `os.Stderr bypasses the redacting output sink`
	println("x")                // want `println bypasses the redacting output sink`
	print("x")                  // want `print bypasses the redacting output sink`
	p := fmt.Println            // want `fmt.Println bypasses the redacting output sink`
	_ = p

	// Allowed: explicit writers, formatting, and standard input.
	fmt.Fprintln(w, "x")
	_ = fmt.Sprintf("%d", 1)
	_ = os.Stdin
}

// Shadowed names are not the process streams.
func g() {
	println := func(string) {}
	println("x")
}
