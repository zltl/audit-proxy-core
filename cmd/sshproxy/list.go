package main

import (
	"fmt"
	"os"
)

func runList(args []string) {
	if len(args) == 0 {
		printError("usage: sshproxy ls <sessions|servers> [options]")
		os.Exit(1)
	}

	switch args[0] {
	case "sessions":
		runSessionsList(args[1:])
	case "servers":
		runServersList(args[1:])
	default:
		printError(fmt.Sprintf("unknown ls target: %s", args[0]))
		os.Exit(1)
	}
}
