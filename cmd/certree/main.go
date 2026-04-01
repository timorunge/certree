// Entry point for the certree CLI.
package main

import (
	"os"

	"github.com/timorunge/certree/internal/cli"
)

// version is set at build time via ldflags.
var version = "dev"

func main() {
	os.Exit(int(cli.Run(os.Stdout, os.Stderr, os.Args[1:], version)))
}
