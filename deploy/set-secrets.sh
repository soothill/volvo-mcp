#!/usr/bin/env bash
# volvo-mcp secret setup — run ON mcp-hub (LXC 140), interactively.
#
#   ssh -t root@10.10.100.200 'pct exec 140 -- bash /root/set-secrets.sh'
#
# Prompts for each credential with hidden input (read -rs): nothing is echoed,
# nothing lands in shell history, chat, or logs. Also migrates the secrets out
# of /run (tmpfs — wiped on reboot) into /etc/volvo-mcp/secrets and repoints
# the env file + systemd unit. Idempotent: re-run any time to rotate a value.
set -euo pipefail

SECR=/etc/volvo-mcp/secrets
RUNUID=10001
[ "$(id -u)" = 0 ] || { echo "run as root (pct exec 140)" >&2; exit 1; }

mkdir -p "$SECR" && chmod 700 "$SECR"

# Save the API key that currently lives only in tmpfs.
if [ -f /run/secrets/volvo/vccapikey ] && [ ! -f "$SECR/vccapikey" ]; then
    cp /run/secrets/volvo/vccapikey "$SECR/vccapikey"
    echo "saved vccapikey from tmpfs into $SECR"
fi
chown "$RUNUID":1000 "$SECR/vccapikey" 2>/dev/null || true
chmod 600 "$SECR/vccapikey" 2>/dev/null || true

ask() {  # ask <file> <prompt>
    local v
    read -rs -p "$2: " v; echo
    [ -n "$v" ] || { echo "empty, aborting" >&2; exit 1; }
    printf '%s' "$v" > "$1"; unset v
    chmod 600 "$1"; chown "$RUNUID":1000 "$1"
}

ask "$SECR/username"      "Volvo ID email"
ask "$SECR/password"      "Volvo ID password"
ask "$SECR/otp_imap_user" "Apple ID email (IMAP user)"
ask "$SECR/otp_imap_pass" "iCloud app-specific password"

ENV=/etc/volvo-mcp/volvo-mcp.env
sed -i "s#^VOLVO_SECRET_DIR=.*#VOLVO_SECRET_DIR=$SECR#" "$ENV"
sed -i "s#/run/secrets/volvo#$SECR#g" "$ENV"
grep -q '^VOLVO_OTP_IMAP_HOST=' "$ENV" \
  || echo 'VOLVO_OTP_IMAP_HOST=imap.mail.me.com' >> "$ENV"

UNIT=/etc/systemd/system/volvo-mcp.service
if grep -q '/run/secrets/volvo' "$UNIT"; then
    sed -i "s#-v /run/secrets/volvo:/run/secrets/volvo:ro#-v $SECR:$SECR:ro#" "$UNIT"
    echo "service unit repointed to $SECR"
fi
systemctl daemon-reload

docker pull ghcr.io/soothill/volvo-mcp:latest
systemctl restart volvo-mcp
sleep 3
systemctl is-active volvo-mcp && echo "volvo-mcp restarted OK"
