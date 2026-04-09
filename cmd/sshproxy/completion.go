package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

func runCompletion(args []string) {
	fs := flag.NewFlagSet("completion", flag.ExitOnError)
	fs.Parse(args)

	if fs.NArg() == 0 {
		printError("usage: sshproxy completion <bash|zsh|fish>")
		os.Exit(1)
	}

	script, err := completionScript(fs.Arg(0))
	if err != nil {
		printError(err.Error())
		os.Exit(1)
	}
	fmt.Print(script)
}

func completionScript(shell string) (string, error) {
	switch strings.ToLower(shell) {
	case "bash":
		return bashCompletion, nil
	case "zsh":
		return zshCompletion, nil
	case "fish":
		return fishCompletion, nil
	default:
		return "", fmt.Errorf("unsupported shell: %s", shell)
	}
}

const bashCompletion = `_sshproxy()
{
  local cur prev words cword
  COMPREPLY=()
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"

  if [[ ${COMP_CWORD} -eq 1 ]]; then
    COMPREPLY=( $(compgen -W "status login ssh scp sessions ls users servers play audit config cert proxycommand completion jit threat compliance version help" -- "${cur}") )
    return 0
  fi

  case "${COMP_WORDS[1]}" in
    ls)
      COMPREPLY=( $(compgen -W "sessions servers" -- "${cur}") )
      ;;
    sessions)
      COMPREPLY=( $(compgen -W "list kill" -- "${cur}") )
      ;;
    users)
      COMPREPLY=( $(compgen -W "list create delete update" -- "${cur}") )
      ;;
    servers)
      COMPREPLY=( $(compgen -W "list add remove" -- "${cur}") )
      ;;
    config)
      COMPREPLY=( $(compgen -W "show edit reload history" -- "${cur}") )
      ;;
    cert)
      COMPREPLY=( $(compgen -W "sign" -- "${cur}") )
      ;;
    jit)
      COMPREPLY=( $(compgen -W "list request approve deny" -- "${cur}") )
      ;;
    threat)
      COMPREPLY=( $(compgen -W "alerts" -- "${cur}") )
      ;;
    compliance)
      COMPREPLY=( $(compgen -W "report" -- "${cur}") )
      ;;
    completion)
      COMPREPLY=( $(compgen -W "bash zsh fish" -- "${cur}") )
      ;;
  esac
}

complete -F _sshproxy sshproxy
`

const zshCompletion = `#compdef sshproxy

_sshproxy() {
  local -a commands
  commands=(
    'status:Show proxy and cluster status'
    'login:Sign in with OIDC and fetch an SSH certificate'
    'ssh:Run local ssh through the proxy'
    'scp:Run local scp through the proxy'
    'sessions:List or manage sessions'
    'ls:Shortcut for listing resources'
    'users:Manage users'
    'servers:Manage backend servers'
    'play:Replay a session recording'
    'audit:Query audit logs'
    'config:Manage configuration'
    'cert:Manage SSH certificates'
    'proxycommand:TCP bridge for SSH ProxyCommand'
    'completion:Generate shell completion'
    'jit:Manage JIT access requests'
    'threat:View threat alerts'
    'compliance:Generate compliance reports'
    'version:Show version information'
  )

  _arguments '1:command:->command' '*::arg:->arg'

  case $state in
    command)
      _describe 'command' commands
      ;;
    arg)
      case $words[2] in
        completion)
          _values 'shell' bash zsh fish
          ;;
        ls)
          _values 'resource' sessions servers
          ;;
      esac
      ;;
  esac
}

_sshproxy "$@"
`

const fishCompletion = `complete -c sshproxy -f
complete -c sshproxy -n '__fish_use_subcommand' -a 'status login ssh scp sessions ls users servers play audit config cert proxycommand completion jit threat compliance version help'
complete -c sshproxy -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish'
complete -c sshproxy -n '__fish_seen_subcommand_from ls' -a 'sessions servers'
complete -c sshproxy -n '__fish_seen_subcommand_from sessions' -a 'list kill'
complete -c sshproxy -n '__fish_seen_subcommand_from users' -a 'list create delete update'
complete -c sshproxy -n '__fish_seen_subcommand_from servers' -a 'list add remove'
complete -c sshproxy -n '__fish_seen_subcommand_from config' -a 'show edit reload history'
complete -c sshproxy -n '__fish_seen_subcommand_from cert' -a 'sign'
complete -c sshproxy -n '__fish_seen_subcommand_from jit' -a 'list request approve deny'
complete -c sshproxy -n '__fish_seen_subcommand_from threat' -a 'alerts'
complete -c sshproxy -n '__fish_seen_subcommand_from compliance' -a 'report'
`
