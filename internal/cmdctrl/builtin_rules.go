package cmdctrl

import "regexp"

// DefaultRules returns the built-in set of command control rules.
func DefaultRules() []*CommandRule {
	rules := []*CommandRule{
		{
			ID:       "block_rm_rf",
			Name:     "Block recursive delete of root paths",
			Pattern:  `rm\s+(-[rfRF]+\s+)?/`,
			Action:   ActionDeny,
			Severity: "critical",
			Message:  "Recursive delete of root paths blocked",
			Enabled:  true,
		},
		{
			ID:       "block_chmod_world",
			Name:     "Block world-writable permissions",
			Pattern:  `chmod\s+[0-7]*7[0-7]*`,
			Action:   ActionDeny,
			Severity: "critical",
			Message:  "World-writable permissions blocked",
			Enabled:  true,
		},
		{
			ID:       "block_shutdown",
			Name:     "Require approval for system shutdown",
			Pattern:  `(shutdown|reboot|halt|poweroff|init\s+[06])`,
			Action:   ActionApprove,
			Severity: "critical",
			Message:  "System shutdown requires approval",
			Enabled:  true,
		},
		{
			ID:       "audit_sudo",
			Name:     "Audit privileged commands",
			Pattern:  `sudo\s+`,
			Action:   ActionAudit,
			Severity: "warning",
			Message:  "Privileged command logged",
			Enabled:  true,
		},
		{
			ID:       "audit_passwd",
			Name:     "Audit user modifications",
			Pattern:  `(passwd|chpasswd|usermod)`,
			Action:   ActionAudit,
			Severity: "warning",
			Message:  "User modification logged",
			Enabled:  true,
		},
		{
			ID:       "block_wget_curl",
			Name:     "Block piped download execution",
			Pattern:  `(wget|curl)\s+.*\|.*sh`,
			Action:   ActionDeny,
			Severity: "critical",
			Message:  "Piped download execution blocked",
			Enabled:  true,
		},
		{
			ID:       "block_dd",
			Name:     "Block raw disk writes",
			Pattern:  `dd\s+.*of=/dev/`,
			Action:   ActionDeny,
			Severity: "critical",
			Message:  "Raw disk write blocked",
			Enabled:  true,
		},
		{
			ID:       "audit_ssh",
			Name:     "Audit lateral movement",
			Pattern:  `ssh\s+`,
			Action:   ActionAudit,
			Severity: "info",
			Message:  "Lateral movement logged",
			Enabled:  true,
		},
		{
			ID:       "block_history_clear",
			Name:     "Block history clearing",
			Pattern:  `(history\s+-c|>.*/\..*history)`,
			Action:   ActionDeny,
			Severity: "critical",
			Message:  "History clearing blocked",
			Enabled:  true,
		},
		{
			ID:       "block_iptables",
			Name:     "Require approval for firewall changes",
			Pattern:  `(iptables|nft|firewall-cmd)`,
			Action:   ActionApprove,
			Severity: "critical",
			Message:  "Firewall changes require approval",
			Enabled:  true,
		},
	}

	for _, r := range rules {
		r.compiled = regexp.MustCompile(r.Pattern)
	}

	return rules
}
