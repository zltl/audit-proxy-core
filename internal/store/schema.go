package store

import "github.com/ssh-proxy-core/ssh-proxy-core/internal/dbx"

// component is the migration key for this schema. It is separate from the
// control plane's own components so the two can evolve independently.
const component = "dataplane_store"

// SchemaVersion is the latest migration in this package. Bump it with every
// appended migration.
const SchemaVersion = 2

// migrations is forward-only. Never edit an applied migration: append a new one.
//
// Types are chosen to work under both SQLite and Postgres without dialect
// branching. Timestamps are stored as Unix seconds in BIGINT because SQLite has
// no native timestamp type and integer comparison is unambiguous across both.
// Structured fields such as tag maps and CIDR lists are stored as JSON text for
// the same reason.
var migrations = []dbx.Migration{
	{
		Version: 1,
		Statements: []string{
			// ---- Identity ------------------------------------------------
			`CREATE TABLE IF NOT EXISTS dp_users (
				id TEXT PRIMARY KEY,
				username TEXT NOT NULL UNIQUE,
				display_name TEXT NOT NULL DEFAULT '',
				email TEXT NOT NULL DEFAULT '',
				status TEXT NOT NULL DEFAULT 'active',
				source TEXT NOT NULL DEFAULT 'local',
				password_hash TEXT NOT NULL DEFAULT '',
				password_changed_at BIGINT NOT NULL DEFAULT 0,
				password_change_required BOOLEAN NOT NULL DEFAULT FALSE,
				mfa_type TEXT NOT NULL DEFAULT 'none',
				mfa_secret_ref TEXT NOT NULL DEFAULT '',
				mfa_pending BOOLEAN NOT NULL DEFAULT FALSE,
				created_at BIGINT NOT NULL DEFAULT 0,
				updated_at BIGINT NOT NULL DEFAULT 0,
				last_login_at BIGINT NOT NULL DEFAULT 0
			);`,
			`CREATE INDEX IF NOT EXISTS idx_dp_users_status ON dp_users(status);`,

			`CREATE TABLE IF NOT EXISTS dp_user_public_keys (
				id TEXT PRIMARY KEY,
				user_id TEXT NOT NULL,
				fingerprint TEXT NOT NULL UNIQUE,
				algorithm TEXT NOT NULL DEFAULT '',
				public_key TEXT NOT NULL,
				comment TEXT NOT NULL DEFAULT '',
				expires_at BIGINT NOT NULL DEFAULT 0,
				created_at BIGINT NOT NULL DEFAULT 0,
				last_used_at BIGINT NOT NULL DEFAULT 0
			);`,
			`CREATE INDEX IF NOT EXISTS idx_dp_user_keys_user ON dp_user_public_keys(user_id);`,

			// ---- Roles ---------------------------------------------------
			`CREATE TABLE IF NOT EXISTS dp_roles (
				name TEXT PRIMARY KEY,
				description TEXT NOT NULL DEFAULT '',
				builtin BOOLEAN NOT NULL DEFAULT FALSE,
				created_at BIGINT NOT NULL DEFAULT 0
			);`,
			`CREATE TABLE IF NOT EXISTS dp_role_bindings (
				id TEXT PRIMARY KEY,
				subject_kind TEXT NOT NULL DEFAULT 'user',
				subject TEXT NOT NULL,
				role TEXT NOT NULL,
				created_at BIGINT NOT NULL DEFAULT 0
			);`,
			`CREATE UNIQUE INDEX IF NOT EXISTS idx_dp_role_bindings_unique
				ON dp_role_bindings(subject_kind, subject, role);`,

			// ---- Targets -------------------------------------------------
			`CREATE TABLE IF NOT EXISTS dp_targets (
				id TEXT PRIMARY KEY,
				name TEXT NOT NULL UNIQUE,
				host TEXT NOT NULL,
				port INTEGER NOT NULL DEFAULT 22,
				group_name TEXT NOT NULL DEFAULT '',
				tags TEXT NOT NULL DEFAULT '{}',
				os TEXT NOT NULL DEFAULT '',
				enabled BOOLEAN NOT NULL DEFAULT TRUE,
				maintenance BOOLEAN NOT NULL DEFAULT FALSE,
				weight INTEGER NOT NULL DEFAULT 1,
				created_at BIGINT NOT NULL DEFAULT 0,
				updated_at BIGINT NOT NULL DEFAULT 0
			);`,
			`CREATE INDEX IF NOT EXISTS idx_dp_targets_host ON dp_targets(host, port);`,
			`CREATE INDEX IF NOT EXISTS idx_dp_targets_group ON dp_targets(group_name);`,

			// Pinned upstream host keys. Without these the proxy cannot tell a
			// target apart from an impostor, which would undermine every
			// recording it makes.
			`CREATE TABLE IF NOT EXISTS dp_target_host_keys (
				id TEXT PRIMARY KEY,
				target_id TEXT NOT NULL,
				algorithm TEXT NOT NULL,
				public_key TEXT NOT NULL,
				fingerprint TEXT NOT NULL,
				status TEXT NOT NULL DEFAULT 'trusted',
				source TEXT NOT NULL DEFAULT 'manual',
				first_seen_at BIGINT NOT NULL DEFAULT 0,
				trusted_at BIGINT NOT NULL DEFAULT 0,
				comment TEXT NOT NULL DEFAULT ''
			);`,
			`CREATE UNIQUE INDEX IF NOT EXISTS idx_dp_host_keys_unique
				ON dp_target_host_keys(target_id, fingerprint);`,
			`CREATE INDEX IF NOT EXISTS idx_dp_host_keys_status ON dp_target_host_keys(status);`,

			`CREATE TABLE IF NOT EXISTS dp_host_ca_keys (
				id TEXT PRIMARY KEY,
				name TEXT NOT NULL DEFAULT '',
				public_key TEXT NOT NULL,
				fingerprint TEXT NOT NULL UNIQUE,
				host_patterns TEXT NOT NULL DEFAULT '[]',
				created_at BIGINT NOT NULL DEFAULT 0
			);`,

			// ---- Secrets -------------------------------------------------
			// Envelope-encrypted material. Plaintext never lands here.
			`CREATE TABLE IF NOT EXISTS dp_secrets (
				id TEXT PRIMARY KEY,
				kind TEXT NOT NULL DEFAULT '',
				key_id TEXT NOT NULL DEFAULT '',
				nonce TEXT NOT NULL DEFAULT '',
				ciphertext TEXT NOT NULL DEFAULT '',
				aad TEXT NOT NULL DEFAULT '',
				version INTEGER NOT NULL DEFAULT 1,
				created_at BIGINT NOT NULL DEFAULT 0,
				rotated_at BIGINT NOT NULL DEFAULT 0
			);`,
			`CREATE INDEX IF NOT EXISTS idx_dp_secrets_key ON dp_secrets(key_id);`,

			`CREATE TABLE IF NOT EXISTS dp_target_credentials (
				id TEXT PRIMARY KEY,
				target_id TEXT NOT NULL DEFAULT '',
				target_selector TEXT NOT NULL DEFAULT '',
				login TEXT NOT NULL,
				kind TEXT NOT NULL,
				secret_ref TEXT NOT NULL DEFAULT '',
				rotate_after_seconds BIGINT NOT NULL DEFAULT 0,
				last_rotated_at BIGINT NOT NULL DEFAULT 0,
				created_at BIGINT NOT NULL DEFAULT 0,
				updated_at BIGINT NOT NULL DEFAULT 0
			);`,
			`CREATE INDEX IF NOT EXISTS idx_dp_credentials_target ON dp_target_credentials(target_id);`,

			// ---- Authorization -------------------------------------------
			`CREATE TABLE IF NOT EXISTS dp_access_rules (
				id TEXT PRIMARY KEY,
				name TEXT NOT NULL DEFAULT '',
				priority INTEGER NOT NULL DEFAULT 100,
				effect TEXT NOT NULL DEFAULT 'allow',
				subject_kind TEXT NOT NULL DEFAULT 'user',
				subject TEXT NOT NULL DEFAULT '*',
				target_selector TEXT NOT NULL DEFAULT '*',
				upstream_logins TEXT NOT NULL DEFAULT '[]',
				features BIGINT NOT NULL DEFAULT 0,
				denied_features BIGINT NOT NULL DEFAULT 0,
				source_cidrs TEXT NOT NULL DEFAULT '[]',
				time_windows TEXT NOT NULL DEFAULT '[]',
				max_session_seconds BIGINT NOT NULL DEFAULT 0,
				idle_timeout_seconds BIGINT NOT NULL DEFAULT 0,
				max_concurrent_sessions INTEGER NOT NULL DEFAULT 0,
				record_policy TEXT NOT NULL DEFAULT 'full',
				command_policy_id TEXT NOT NULL DEFAULT '',
				approval_required BOOLEAN NOT NULL DEFAULT FALSE,
				enabled BOOLEAN NOT NULL DEFAULT TRUE,
				created_at BIGINT NOT NULL DEFAULT 0,
				updated_at BIGINT NOT NULL DEFAULT 0
			);`,
			`CREATE INDEX IF NOT EXISTS idx_dp_access_rules_order
				ON dp_access_rules(enabled, priority);`,

			`CREATE TABLE IF NOT EXISTS dp_command_policies (
				id TEXT PRIMARY KEY,
				name TEXT NOT NULL UNIQUE,
				description TEXT NOT NULL DEFAULT '',
				created_at BIGINT NOT NULL DEFAULT 0,
				updated_at BIGINT NOT NULL DEFAULT 0
			);`,
			`CREATE TABLE IF NOT EXISTS dp_command_rules (
				id TEXT PRIMARY KEY,
				policy_id TEXT NOT NULL,
				priority INTEGER NOT NULL DEFAULT 100,
				pattern TEXT NOT NULL,
				action TEXT NOT NULL DEFAULT 'audit',
				rewrite TEXT NOT NULL DEFAULT '',
				severity TEXT NOT NULL DEFAULT 'medium',
				message TEXT NOT NULL DEFAULT '',
				enabled BOOLEAN NOT NULL DEFAULT TRUE,
				created_at BIGINT NOT NULL DEFAULT 0
			);`,
			`CREATE INDEX IF NOT EXISTS idx_dp_command_rules_policy
				ON dp_command_rules(policy_id, priority);`,

			`CREATE TABLE IF NOT EXISTS dp_ip_rules (
				id TEXT PRIMARY KEY,
				cidr TEXT NOT NULL,
				action TEXT NOT NULL DEFAULT 'deny',
				priority INTEGER NOT NULL DEFAULT 100,
				comment TEXT NOT NULL DEFAULT '',
				expires_at BIGINT NOT NULL DEFAULT 0,
				created_at BIGINT NOT NULL DEFAULT 0
			);`,
			`CREATE INDEX IF NOT EXISTS idx_dp_ip_rules_order ON dp_ip_rules(priority);`,

			// ---- Sessions ------------------------------------------------
			// Shared so that any node can enumerate and terminate a session
			// that another node is serving.
			`CREATE TABLE IF NOT EXISTS dp_sessions (
				id TEXT PRIMARY KEY,
				node_id TEXT NOT NULL DEFAULT '',
				username TEXT NOT NULL DEFAULT '',
				source_ip TEXT NOT NULL DEFAULT '',
				client_version TEXT NOT NULL DEFAULT '',
				target_id TEXT NOT NULL DEFAULT '',
				target_host TEXT NOT NULL DEFAULT '',
				target_port INTEGER NOT NULL DEFAULT 0,
				upstream_login TEXT NOT NULL DEFAULT '',
				status TEXT NOT NULL DEFAULT 'active',
				started_at BIGINT NOT NULL DEFAULT 0,
				last_seen_at BIGINT NOT NULL DEFAULT 0,
				closed_at BIGINT NOT NULL DEFAULT 0,
				bytes_in BIGINT NOT NULL DEFAULT 0,
				bytes_out BIGINT NOT NULL DEFAULT 0,
				recording_ref TEXT NOT NULL DEFAULT '',
				revoke_requested BOOLEAN NOT NULL DEFAULT FALSE,
				revoke_reason TEXT NOT NULL DEFAULT '',
				termination_info TEXT NOT NULL DEFAULT ''
			);`,
			`CREATE INDEX IF NOT EXISTS idx_dp_sessions_status ON dp_sessions(status, started_at DESC);`,
			`CREATE INDEX IF NOT EXISTS idx_dp_sessions_user ON dp_sessions(username);`,
			`CREATE INDEX IF NOT EXISTS idx_dp_sessions_node ON dp_sessions(node_id, status);`,
			`CREATE INDEX IF NOT EXISTS idx_dp_sessions_revoke ON dp_sessions(revoke_requested, status);`,
		},
	},
	{
		// Sessions carry the constraints they were granted. Storing the decision
		// alongside the session means a later question about the same session —
		// may it open this channel, run this command, has it been open too long —
		// can be answered from the row, without the deciding node having to keep
		// state in memory or the policy being re-evaluated against rules that may
		// since have changed under it.
		Version: 2,
		Statements: []string{
			`ALTER TABLE dp_sessions ADD COLUMN features BIGINT NOT NULL DEFAULT 0;`,
			`ALTER TABLE dp_sessions ADD COLUMN command_policy_id TEXT NOT NULL DEFAULT '';`,
			`ALTER TABLE dp_sessions ADD COLUMN record_policy TEXT NOT NULL DEFAULT 'full';`,
			`ALTER TABLE dp_sessions ADD COLUMN rule_id TEXT NOT NULL DEFAULT '';`,
			`ALTER TABLE dp_sessions ADD COLUMN max_session_seconds BIGINT NOT NULL DEFAULT 0;`,
			`ALTER TABLE dp_sessions ADD COLUMN idle_timeout_seconds BIGINT NOT NULL DEFAULT 0;`,
		},
	},
}
