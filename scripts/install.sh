#!/usr/bin/env bash
# Installs secretd as a launchd user agent, links the CLI, registers the MCP server
# with Claude Code, and installs the secret-vault skill.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE="$(command -v node)"
PLIST_LABEL="com.stefan.secretd"
PLIST="$HOME/Library/LaunchAgents/${PLIST_LABEL}.plist"
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
RESTORE=""
# --restore <file> migrates an exported vault from another machine instead of
# creating an empty one. Everything else about the install is identical.
while [ $# -gt 0 ]; do
  case "$1" in
    --restore) RESTORE="$2"; shift 2 ;;
    --restore=*) RESTORE="${1#*=}"; shift ;;
    -h|--help) echo "usage: install.sh [--restore <exported-vault.db>]"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
SECRETD_HOME="${SECRETD_HOME:-$HOME/.secretd}"
PORT="${SECRETD_PORT:-7777}"

say() { printf '\033[36m==>\033[0m %s\n' "$1"; }
warn() { printf '\033[33m==>\033[0m %s\n' "$1"; }

say "building"
cd "$REPO"
npm install --silent
npm run build --silent

if [ -n "$RESTORE" ]; then
  [ -f "$RESTORE" ] || { echo "no such file: $RESTORE" >&2; exit 1; }
  say "restoring vault from $RESTORE"
  node "$REPO/dist/cli/main.js" restore "$RESTORE"
elif [ ! -f "$SECRETD_HOME/vault.db" ]; then
  say "no vault yet — creating one (you will be asked for a password)"
  node "$REPO/dist/cli/main.js" init
else
  say "vault already exists at $SECRETD_HOME/vault.db"
fi

say "linking CLI into $BIN_DIR"
mkdir -p "$BIN_DIR"
ln -sf "$REPO/dist/cli/main.js" "$BIN_DIR/secrets"
chmod +x "$REPO/dist/cli/main.js" "$REPO/dist/daemon/main.js" "$REPO/dist/mcp/main.js"
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) warn "$BIN_DIR is not on your PATH — add it: fish_add_path $BIN_DIR" ;;
esac

say "installing launchd agent ($PLIST_LABEL)"
mkdir -p "$HOME/Library/LaunchAgents" "$SECRETD_HOME/logs"
cat > "$PLIST" <<PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${PLIST_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${NODE}</string>
    <string>--no-warnings</string>
    <string>${REPO}/dist/daemon/main.js</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>SECRETD_HOME</key><string>${SECRETD_HOME}</string>
    <key>SECRETD_HOST</key><string>0.0.0.0</string>
    <key>SECRETD_PORT</key><string>${PORT}</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>${SECRETD_HOME}/logs/secretd.log</string>
  <key>StandardErrorPath</key><string>${SECRETD_HOME}/logs/secretd.log</string>
  <key>ProcessType</key><string>Background</string>
</dict>
</plist>
PLIST_EOF

# bootout is expected to fail on a first install; the vault daemon is ours to restart.
launchctl bootout "gui/$(id -u)/${PLIST_LABEL}" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"
say "daemon loaded — logs at $SECRETD_HOME/logs/secretd.log"

say "waiting for daemon"
for _ in $(seq 1 40); do
  curl -sf "http://127.0.0.1:${PORT}/api/health" >/dev/null 2>&1 && break
  sleep 0.25
done
curl -sf "http://127.0.0.1:${PORT}/api/health" >/dev/null 2>&1 \
  && say "daemon healthy on port ${PORT}" \
  || warn "daemon did not come up — check $SECRETD_HOME/logs/secretd.log"

say "installing secret-vault skill"
mkdir -p "$HOME/.claude/skills"
ln -sfn "$REPO/skills/secret-vault" "$HOME/.claude/skills/secret-vault"

if command -v claude >/dev/null 2>&1; then
  say "registering MCP server with Claude Code"
  # No credential in the registration: the MCP server reads the vault password from
  # the login Keychain at call time, so rotating the password needs no re-registration.
  claude mcp remove secrets --scope user 2>/dev/null || true
  claude mcp add secrets --scope user \
    --env "SECRETD_URL=http://127.0.0.1:${PORT}" \
    -- "$NODE" --no-warnings "$REPO/dist/mcp/main.js"
else
  warn "claude CLI not found — register the MCP server manually (see README)"
fi

cat <<DONE

$(say "done")
  Web UI    http://localhost:${PORT}/   (sign in with your vault password)
  CLI       secrets --help
  Logs      secrets logs -f
  Restart   launchctl kickstart -k gui/$(id -u)/${PLIST_LABEL}

  One password does everything. On another machine: secrets login

DONE

if [ -n "$RESTORE" ]; then
  warn "restored vault is LOCKED — run 'secrets login' with the password from the old machine"
fi
