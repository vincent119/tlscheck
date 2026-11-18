package main

import (
	"os"
	"testing"
)

func TestMainVersionUsesUnifiedEntry(t *testing.T) {
	before := os.Args
	t.Cleanup(func() { os.Args = before })
	os.Args = []string{"tlscheck", "--version"}
	if code := run(); code != 0 {
		t.Fatal(code)
	}
}
