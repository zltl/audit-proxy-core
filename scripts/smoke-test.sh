#!/usr/bin/env bash
#
# End-to-end smoke test of the quickstart in docs/architecture.md.
#
# The unit and integration tests cover each layer; this covers the thing they
# cannot, which is whether the documented instructions actually produce a
# working system. It builds the real binaries, starts a control plane and a
# data plane, configures a target through the admin API with real session and
# CSRF cookies, and connects with the system ssh client.
#
# Requires: go, ssh, openssl, curl, python3.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
WORK=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$WORK"' EXIT

cd "$ROOT"
echo "== building =="
go build -o "$WORK/control-plane" ./cmd/control-plane
go build -o "$WORK/dataplane" ./cmd/dataplane
go build -o "$WORK/audit-proxy" ./cmd/audit-proxy

mkdir -p "$WORK/data" "$WORK/audit" "$WORK/run" "$WORK/rec"
ssh-keygen -q -t ed25519 -f "$WORK/proxy_host_key" -N ""
ssh-keygen -q -t ed25519 -f "$WORK/target_host_key" -N ""

SECRETS_KEY=$(openssl rand -hex 32)
CHAIN_KEY=$(openssl rand -hex 32)
RECORDING_KEY=$(openssl rand -hex 32)
SESSION_SECRET=$(openssl rand -hex 32)

# A stand-in target: a real sshd would need root, so a tiny Go server is used.
cat > "$WORK/target.go" <<'GO'
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
)

func main() {
	keyPath, addrFile := os.Args[1], os.Args[2]
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		panic(err)
	}
	signer, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		panic(err)
	}
	cfg := &ssh.ServerConfig{PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
		return nil, nil
	}}
	cfg.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(addrFile, []byte(listener.Addr().String()), 0o600); err != nil {
		panic(err)
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
			if err != nil {
				return
			}
			defer sc.Close()
			go ssh.DiscardRequests(reqs)
			for nc := range chans {
				if nc.ChannelType() != "session" {
					_ = nc.Reject(ssh.UnknownChannelType, "")
					continue
				}
				ch, reqs, err := nc.Accept()
				if err != nil {
					continue
				}
				go func() {
					defer ch.Close()
					for req := range reqs {
						if req.Type == "exec" {
							var p struct{ Command string }
							_ = ssh.Unmarshal(req.Payload, &p)
							_ = req.Reply(true, nil)
							fmt.Fprintf(ch, "target executed: %s\n", p.Command)
							status := make([]byte, 4)
							binary.BigEndian.PutUint32(status, 0)
							_, _ = ch.SendRequest("exit-status", false, status)
							return
						}
						if req.WantReply {
							_ = req.Reply(false, nil)
						}
					}
					_ = io.EOF
				}()
			}
		}()
	}
}
GO

mkdir -p "$WORK/targetsrv"
mv "$WORK/target.go" "$WORK/targetsrv/main.go"
(cd "$ROOT" && go build -o "$WORK/target" "$WORK/targetsrv/main.go")
"$WORK/target" "$WORK/target_host_key" "$WORK/target.addr" &
sleep 1
TARGET_ADDR=$(cat "$WORK/target.addr")
TARGET_HOST=${TARGET_ADDR%:*}
TARGET_PORT=${TARGET_ADDR##*:}
echo "== target on $TARGET_ADDR =="

cat > "$WORK/control-plane.json" <<JSON
{
  "listen_addr": "127.0.0.1:18443",
  "session_secret": "$SESSION_SECRET",
  "admin_user": "admin",
  "data_dir": "$WORK/data",
  "audit_log_dir": "$WORK/audit",
  "recording_dir": "$WORK/rec",
  "pdp_listen_addr": "unix:$WORK/run/pdp.sock",
  "secrets_encryption_key": "$SECRETS_KEY",
  "audit_chain_key": "$CHAIN_KEY"
}
JSON

echo "== starting control plane =="
"$WORK/control-plane" -config "$WORK/control-plane.json" > "$WORK/cp.log" 2>&1 &
for _ in $(seq 1 40); do [ -S "$WORK/run/pdp.sock" ] && break; sleep 0.25; done
if [ ! -S "$WORK/run/pdp.sock" ]; then echo "FAIL: decision point socket never appeared"; cat "$WORK/cp.log"; exit 1; fi
echo "   decision point socket is up"

echo "== starting data plane =="
"$WORK/dataplane" \
  --node-id smoke-node \
  --listen 127.0.0.1:12222 \
  --host-keys "$WORK/proxy_host_key" \
  --pdp "unix:$WORK/run/pdp.sock" --pdp-insecure \
  --fail-mode closed \
  --audit-spool-dir "$WORK/data/spool" \
  --audit-chain-key "$CHAIN_KEY" \
  --recording-dir "$WORK/rec" \
  --recording-encryption-key "$RECORDING_KEY" \
  --metrics-addr 127.0.0.1:19100 > "$WORK/dp.log" 2>&1 &
sleep 2
if ! grep -q "listening on" "$WORK/dp.log"; then echo "FAIL: data plane did not start"; cat "$WORK/dp.log"; exit 1; fi
echo "   data plane is listening"

echo "== metrics and readiness =="
curl -sf http://127.0.0.1:19100/readyz > /dev/null || { echo "FAIL: not ready"; exit 1; }
curl -sf http://127.0.0.1:19100/metrics | grep -q audit_proxy_sessions_started_total || { echo "FAIL: no metrics"; exit 1; }
echo "   ready, metrics exposed"

echo "== configuring through the documented admin API =="
# Mint the session and CSRF cookies the middleware expects, so the smoke test
# exercises the same authenticated path an operator would use.
EXPIRY=$(( $(date +%s) + 3600 ))
SIG=$(printf '%s' "admin|admin|$EXPIRY" | openssl dgst -sha256 -hmac "$SESSION_SECRET" -hex | awk '{print $NF}')
SESSION_COOKIE="admin|admin|$EXPIRY|$SIG"
CSRF_RAW=$(openssl rand -hex 32)
CSRF_SIG=$(printf '%s' "$CSRF_RAW" | openssl dgst -sha256 -hmac "$SESSION_SECRET" -hex | awk '{print $NF}')
CSRF_TOKEN="$CSRF_RAW|$CSRF_SIG"

api() {
  local method=$1 path=$2 body=${3:-}
  curl -sS -X "$method" "http://127.0.0.1:18443$path" \
    -H "Content-Type: application/json" \
    -H "X-CSRF-Token: $CSRF_TOKEN" \
    --cookie "session=$SESSION_COOKIE; csrf_token=$CSRF_TOKEN" \
    ${body:+-d "$body"}
}

api POST /api/v2/dp/users '{"username":"alice","password":"alice-password-1"}' | grep -q '"success":true' \
  || { echo "FAIL: could not create the user"; api POST /api/v2/dp/users '{"username":"alice","password":"alice-password-1"}'; exit 1; }
api POST /api/v2/dp/targets "{\"name\":\"web-1\",\"host\":\"$TARGET_HOST\",\"port\":$TARGET_PORT}" | grep -q '"success":true' \
  || { echo "FAIL: could not create the target"; exit 1; }
api POST /api/v2/dp/credentials '{"target_name":"web-1","login":"deploy","kind":"password","secret":"anything"}' | grep -q '"success":true' \
  || { echo "FAIL: could not create the credential"; exit 1; }
api POST /api/v2/dp/rules '{"id":"smoke","name":"smoke","priority":10,"subject_kind":"user","subject":"alice","target_selector":"web-1","upstream_logins":["deploy"],"features":["shell","exec","pty","env"],"record_policy":"full"}' | grep -q '"success":true' \
  || { echo "FAIL: could not create the rule"; exit 1; }
echo "   user, target, credential, and rule created"

echo "== the policy preview answers before anything connects =="
api POST /api/v2/dp/rules/evaluate '{"username":"alice","target":"web-1","upstream_login":"deploy"}' | grep -q '"allowed":true' \
  || { echo "FAIL: the rule does not permit the connection"; exit 1; }
echo "   evaluate says the connection would be allowed"

echo "== the first connection is refused: the host key is not yet trusted =="
cat > "$WORK/askpass" <<'SH'
#!/bin/sh
echo alice-password-1
SH
chmod +x "$WORK/askpass"

do_ssh() {
  SSH_ASKPASS="$WORK/askpass" SSH_ASKPASS_REQUIRE=force DISPLAY=none \
    ssh -F /dev/null -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o PubkeyAuthentication=no -o PreferredAuthentications=password \
        -o NumberOfPasswordPrompts=1 -o LogLevel=ERROR \
        -p 12222 -l 'alice%deploy@web-1' 127.0.0.1 "$1" 2>&1
}

set +e
FIRST=$(do_ssh hostname)
FIRST_STATUS=$?
set -e
if [ $FIRST_STATUS -eq 0 ]; then
  echo "FAIL: the proxy connected to a target whose host key was never trusted"
  exit 1
fi
if ! grep -qi "host key" "$WORK/dp.log"; then
  echo "FAIL: the refusal was not about the host key"; tail -20 "$WORK/dp.log"; exit 1
fi
echo "   refused (client saw: ${FIRST:-connection closed}), as it should be"

echo "== approving the host key through the pending queue =="
FINGERPRINT=$(api GET /api/v2/dp/host-keys/pending | python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]; print(d[0]["Fingerprint"] if d else "")')
if [ -z "$FINGERPRINT" ]; then echo "FAIL: the key was not recorded for review"; exit 1; fi
api PUT "/api/v2/dp/targets/web-1/host-keys/$FINGERPRINT" '{"status":"trusted"}' | grep -q '"success":true' \
  || { echo "FAIL: could not trust the host key"; exit 1; }
echo "   trusted $FINGERPRINT"

echo "== connecting with the real ssh client =="
set +e
OUTPUT=$(do_ssh hostname)
STATUS=$?
set -e
echo "   ssh exit=$STATUS output=$OUTPUT"
if [ $STATUS -ne 0 ] || ! echo "$OUTPUT" | grep -q "target executed: hostname"; then
  echo "FAIL: the proxied command did not run"
  echo "--- data plane log ---"; tail -30 "$WORK/dp.log"
  exit 1
fi

echo "== audit events =="
sleep 2
if ! ls "$WORK/audit"/audit-*.jsonl > /dev/null 2>&1; then
  echo "FAIL: no audit log was written"; tail -30 "$WORK/dp.log"; exit 1
fi
grep -q '"event_type":"session.start"' "$WORK"/audit/audit-*.jsonl || { echo "FAIL: no session.start"; exit 1; }
grep -q '"integrity_hash"' "$WORK"/audit/audit-*.jsonl || { echo "FAIL: no integrity chain"; exit 1; }
echo "   audit events written with an integrity chain"

echo "== recording =="
RECORDING=$(ls "$WORK/rec"/*.cast* 2>/dev/null | head -1 || true)
if [ -z "$RECORDING" ]; then echo "FAIL: no recording"; exit 1; fi
case "$RECORDING" in
  *.enc) echo "   recording is encrypted: $(basename "$RECORDING")" ;;
  *) echo "FAIL: recording is not encrypted: $RECORDING"; exit 1 ;;
esac
if grep -aq "target executed" "$RECORDING"; then
  echo "FAIL: the recording contains plaintext on disk"; exit 1
fi
echo "   recording contains no plaintext"

echo
echo "SMOKE TEST PASSED"
