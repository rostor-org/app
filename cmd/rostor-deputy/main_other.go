//go:build !windows

// rostor-deputy is a Windows service. This stub keeps `go vet` and tests
// working on other platforms; the real entry point is main_windows.go.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "rostor-deputy only runs on Windows")
	os.Exit(2)
}
