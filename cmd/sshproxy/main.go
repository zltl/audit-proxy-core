// Package main implements the sshproxy CLI management tool.
//
// Usage: sshproxy <command> [options]
//
// Commands:
//
//	status      — show proxy and cluster status
//	sessions    — list/manage sessions
//	users       — manage users
//	servers     — manage servers
//	audit       — query audit logs
//	config      — manage configuration
//	cert        — manage SSH certificates
//	jit         — manage JIT access requests
//	threat      — view threat alerts
//	compliance  — generate compliance reports
//	version     — show version info
package main

import (
	"fmt"
	"os"
	"runtime"
)

// Build-time variables, set via -ldflags.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
	GoVersion = runtime.Version()
)

func main() {
	// Check for global --no-color before subcommand parsing
	for _, arg := range os.Args[1:] {
		if arg == "--no-color" {
			noColor = true
		}
	}

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	args := os.Args[2:]

	switch command {
	case "status":
		runStatus(args)
	case "sessions":
		runSessions(args)
	case "users":
		runUsers(args)
	case "servers":
		runServers(args)
	case "audit":
		runAudit(args)
	case "config":
		runConfig(args)
	case "cert":
		runCert(args)
	case "jit":
		runJIT(args)
	case "threat":
		runThreat(args)
	case "compliance":
		runCompliance(args)
	case "version":
		runVersion(args)
	case "help", "--help", "-h":
		printUsage()
	default:
		printError(fmt.Sprintf("unknown command: %s", command))
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	usage := `Usage: sshproxy <command> [options]

Commands:
  status      Show proxy and cluster status
  sessions    List/manage active sessions
  users       Manage users
  servers     Manage backend servers
  audit       Query audit logs
  config      Manage configuration
  cert        Manage SSH certificates
  jit         Manage JIT access requests
  threat      View threat alerts
  compliance  Generate compliance reports
  version     Show version information

Global flags:
  --json       Output in JSON format
  --no-color   Disable colored output

Run 'sshproxy <command> --help' for details on a specific command.`
	fmt.Println(usage)
}
