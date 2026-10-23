package a

import (
	"fmt"
	"os"
)

// Test files may print.
func h() {
	fmt.Println("x")
	_ = os.Stdout
}
