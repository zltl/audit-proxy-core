package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

func runSSH(args []string) {
	os.Exit(runWrappedSSH("ssh", args, os.Stdin, os.Stdout, os.Stderr))
}

func runSCP(args []string) {
	os.Exit(runWrappedSSH("scp", args, os.Stdin, os.Stdout, os.Stderr))
}

func runWrappedSSH(binary string, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(binary, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addr := fs.String("addr", "", "SSH proxy TCP address")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(stderr, "error: invalid %s arguments: %v\n", binary, err)
		return 2
	}
	if fs.NArg() == 0 {
		fmt.Fprintf(stderr, "error: usage: sshproxy %s [--addr host:port] <args...>\n", binary)
		return 1
	}

	cfg := loadConfig()
	targetAddr := *addr
	if targetAddr == "" {
		targetAddr = cfg.SSHAddr
	}
	if targetAddr == "" {
		fmt.Fprintln(stderr, "error: missing SSH proxy address; set --addr, ssh_addr in ~/.sshproxy/config.json, or SSHPROXY_SSH_ADDR")
		return 1
	}

	exePath, err := os.Executable()
	if err != nil {
		exePath = os.Args[0]
	}
	cmdArgs := wrappedSSHArgsWithIdentity(exePath, targetAddr, cfg.IdentityFile, fs.Args())
	cmd := exec.Command(binary, cmdArgs...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		fmt.Fprintf(stderr, "error: failed to execute %s: %v\n", binary, err)
		return 1
	}
	return 0
}

func wrappedSSHArgs(executablePath, addr string, userArgs []string) []string {
	return wrappedSSHArgsWithIdentity(executablePath, addr, "", userArgs)
}

func wrappedSSHArgsWithIdentity(executablePath, addr, identityFile string, userArgs []string) []string {
	args := []string{
		"-o",
		"ProxyCommand=" + buildProxyCommand(executablePath, addr),
	}
	if identityFile != "" && !userSpecifiedIdentity(userArgs) {
		args = append([]string{"-i", identityFile}, args...)
	}
	return append(args, userArgs...)
}

func userSpecifiedIdentity(userArgs []string) bool {
	for i, arg := range userArgs {
		switch {
		case arg == "-i":
			return true
		case strings.HasPrefix(arg, "-i") && len(arg) > 2:
			return true
		case arg == "-o" && i+1 < len(userArgs) && strings.HasPrefix(userArgs[i+1], "IdentityFile="):
			return true
		case strings.HasPrefix(arg, "-oIdentityFile="):
			return true
		}
	}
	return false
}

func buildProxyCommand(executablePath, addr string) string {
	return shellQuote(executablePath) + " proxycommand --addr " + shellQuote(addr)
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}
