package main

import (
	"os"

	"github.com/PastureStack/vault-secrets-bridge/internal/broker"
	"github.com/PastureStack/vault-secrets-bridge/internal/cli"
)

var version = "dev"

func main() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "serve" {
		os.Exit(broker.RunServe(args[1:], os.Stdout, os.Stderr, version))
	}
	os.Exit(cli.Run(args, os.Stdin, os.Stdout, os.Stderr))
}
