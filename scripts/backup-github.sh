#!/bin/bash
# Daily offsite backup: fresh snapshot -> commit -> push to the private repo csbogdan/secretd-backup.
# Run by launchd (com.stefan.secretd-backup, 04:00). `--install` writes/loads that launchd agent.
# Snapshots are encrypted; the vault passphrase is the only key. Only vault.db is ever pushed.
# ponytail: encrypted pages don't delta, so history grows ~2 MB/day (~700 MB/yr). GitHub warns at 1 GB;
# when that lands, squash history with `git checkout --orphan` + force push.
set -euo pipefail
export PATH="$HOME/.local/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"
SNAPS=$HOME/.secretd/backups
REPO=$HOME/.secretd/github
LABEL=com.stefan.secretd-backup

if [ "${1:-}" = "--install" ]; then
  PLIST=$HOME/Library/LaunchAgents/$LABEL.plist
  cat > "$PLIST" <<PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array><string>/bin/bash</string><string>$(cd "$(dirname "$0")" && pwd)/backup-github.sh</string></array>
  <key>StartCalendarInterval</key><dict><key>Hour</key><integer>4</integer><key>Minute</key><integer>0</integer></dict>
  <key>StandardOutPath</key><string>$HOME/.secretd/logs/github-backup.log</string>
  <key>StandardErrorPath</key><string>$HOME/.secretd/logs/github-backup.log</string>
</dict>
</plist>
PLIST_EOF
  launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
  launchctl bootstrap "gui/$(id -u)" "$PLIST"
  echo "installed $LABEL (daily 04:00). Run now: launchctl kickstart gui/$(id -u)/$LABEL"
  exit 0
fi

echo "== $(date '+%F %T')"
secrets backup || echo "snapshot failed (vault locked?), pushing the newest existing one" >&2
latest=$(ls -t "$SNAPS"/vault-*.db | head -1)
cp "$latest" "$REPO/vault.db"
cd "$REPO"
git add vault.db
git commit -qm "$(basename "$latest" .db)" || { echo "unchanged, nothing to push"; exit 0; }
git push -q origin main
echo "pushed $(basename "$latest") ($(du -k vault.db | cut -f1) KiB)"
