# claude_secrets

A single-user secrets service for a Mac mini. Encrypted SQLite vault behind an HTTP
daemon, with three clients on top: a **CLI**, a **web UI**, and an **MCP server** so
Claude Code can find and use credentials by name.

See [SPEC.md](SPEC.md) for the design and the accepted-risk register.

## Read this first

**This is a single-user tool for one trusted machine on a trusted network. It is not
hardened and it is not trying to be. It assumes a safe environment, and gives you very
little once that assumption is wrong.**

- **One operator, no multi-tenancy.** No users, no roles, no per-secret permissions, no
  rate limiting. Anyone who can reach the daemon with the password is you.
- **Plain HTTP on `0.0.0.0`.** No TLS, and the daemon is reachable from the whole LAN by
  default. Your password and your secret values cross the network in cleartext — and the
  password *is* the key, so sniffing it decrypts `vault.db` and every backup, offline and
  forever.
- **Your login session is the perimeter.** The passphrase is escrowed in the login
  Keychain so the daemon can unlock itself unattended after a reboot. Anything running as
  you can read it, and therefore every secret you own. That is already true of `~/.claude`.
- **Values reach Claude in plaintext.** Anything `get_secret` returns enters the
  transcript, goes to the API, and persists unencrypted in `~/.claude/projects/*.jsonl`.
- **The inventory is not secret.** Metadata is unencrypted so full-text search can index
  it. The DB file reveals every name, description, service and tag you have stored.
- **Lose the passphrase and everything is gone.** No recovery key, no escrow, no reset.

What it *does* buy you: values encrypted at rest with Argon2id + XChaCha20-Poly1305, so a
stolen `vault.db` or backup is useless on its own, and an audit log of every read. Treat
the audit log — not the crypto — as the practical boundary.

Do not put this on an untrusted network, a shared machine, or in front of anything whose
compromise costs more than your own convenience. Every point above is a deliberate trade
recorded in [SPEC.md](SPEC.md#accepted-risks), not an oversight to report.

## Install

```sh
./scripts/install.sh
```

Builds, creates the vault (prompts for a passphrase), installs a launchd agent that
starts at login, links `secrets` into `~/.local/bin`, installs the `secret-vault` skill,
and registers the MCP server with Claude Code.

> The passphrase is the **only** key. Lose it and every secret and every backup is
> unreadable. Write it down somewhere physical.

## Use

```sh
secrets set github/pat ghp_xxx --desc "GitHub PAT for CI" --service github --aliases gh
secrets search the stripe test key      # natural language
secrets get github/pat                  # bare value, for $( ) substitution
secrets ls
secrets logs -f                         # live activity feed
```

Ten types. Beyond keys and tokens there are the 1Password-shaped ones — `login`,
`card`, `bank_account`, `identity` — which have several fields and no single value, so
they take JSON:

```sh
secrets set atlassian/jira --type login --desc "Jira basic auth" \
  '{"username":"me@corp.com","password":"ATATT…","url":"https://corp.atlassian.net"}'

secrets totp atlassian/jira             # current 2FA code, if it has a totp seed
```

A `totp` field takes a bare base32 seed *or* the whole `otpauth://` URI from the QR code —
that URI already carries digits, period and algorithm. Codes are generated on demand and
the seed itself never leaves the vault.

Run something without the value ever touching your terminal or Claude's context:

```sh
secrets exec github/pat -- gh repo list
secrets exec deploy-key:file -- ssh -i {{deploy-key}} host
secrets exec myapp/env -- npm test      # env_bundle expands into every variable
secrets exec vpn/login:totp -- vpn-cli --otp $VPN_LOGIN   # injects a code, not the seed
```

`:totp` injects a *generated code*, which is only valid for its window — fine for a
command that authenticates immediately, wrong for one that reads the variable a minute
later. Use `:env` (the default) when you want the stored password.

```sh
secrets gen                             # 24 chars, no ambiguous l/1/I or 0/O
secrets gen --length 32 --symbols
```

`gen` stores nothing and never touches the vault — pipe it into `secrets set` yourself.

Secrets tagged `hidden` are left out of the web UI's list until you press **Show hidden**,
and every secret has a **Hide** button. It is a screen-sharing courtesy, not access
control — hidden secrets are still in the API, still in search, still readable over MCP
and the CLI. The toggle lives in `sessionStorage`, so a new tab starts hidden again.

```sh
secrets edit personal/thing --tags hidden      # same thing from the CLI
```

Web UI at `http://localhost:7777/` — full CRUD, version history, and the live feed.
It asks once for your vault password, and keeps it only for the life of the tab.

## From another machine

The daemon binds `0.0.0.0`, so it is reachable over LAN and Tailscale:

```sh
export SECRETD_URL=http://<mini-ip-or-tailscale-name>:7777
secrets login          # prompts once, remembers it in this machine's Keychain
secrets ls
```

Traffic is **plain HTTP** — your password and the secret values both cross the network
in cleartext. Note the shape of that: unlike a token, a sniffed password also decrypts
`vault.db` and every backup, offline and forever. Deliberate choice for a trusted LAN;
see SPEC.md.

## Move to another Mac

The whole vault is one encrypted file plus the password in your head. On the old machine:

```sh
secrets export ~/vault-export.db
```

That is a `VACUUM INTO` snapshot, not a file copy, so it is consistent even with the
daemon live and mid-write. It stays encrypted under your password — useless to anyone
who intercepts it, so AirDrop / scp / a USB stick are all fine.

Copy the repo too (skip `node_modules` and `dist`, they rebuild):

```sh
rsync -av --exclude node_modules --exclude dist --exclude .git \
  ~/IQ/claude_secrets/ newmac:~/IQ/claude_secrets/
scp ~/vault-export.db newmac:~/
```

Then on the new Mac, one command:

```sh
cd ~/IQ/claude_secrets && ./scripts/install.sh --restore ~/vault-export.db
secrets login          # the same password as the old machine
```

`--restore` installs the vault instead of creating an empty one; everything else —
build, launchd agent, CLI link, skill, MCP registration — is identical. The daemon comes
up **locked**, because the password lives in the old machine's Keychain and does not
travel. `secrets login` verifies it, unlocks, and stores it in the new machine's Keychain
so every later boot is unattended.

Secrets, metadata, aliases, and full version history all come across.

**Moving vs copying.** There is no sync. If you keep both machines running they become
two independent vaults that drift apart from the moment you write to either one. If this
is a move, decommission the old daemon afterwards:

```sh
launchctl bootout gui/$(id -u)/com.stefan.secretd    # on the OLD machine
```

**If you only want to *use* the vault from another Mac**, you don't need any of this —
leave the daemon on the mini and point a client at it (see *From another machine* above).

## Claude Code

The installer registers the MCP server. To do it by hand:

```sh
claude mcp add secrets --scope user \
  --env SECRETD_URL=http://127.0.0.1:7777 \
  -- node --no-warnings /path/to/claude_secrets/dist/mcp/main.js
```

No credential in that registration — the MCP server reads the vault password from your
login Keychain when it needs it, so changing the password never breaks it.

Thirteen tools: `search_secrets`, `list_secrets`, `get_secret`, `get_totp`,
`generate_password`, `create_secret`,
`update_secret`, `update_secret_metadata`, `delete_secret`, `list_versions`,
`rollback_secret`, `run_with_secrets`, `vault_status`.

`get_totp` returns a code, not a seed — an agent can complete a 2FA prompt without the
transcript ever containing something that generates codes forever.

The `secret-vault` skill teaches the workflow that makes this reliable: **search before
you get**, ask when a search is ambiguous rather than picking, and prefer
`run_with_secrets` over `get_secret` so values never enter the transcript.

## Operations

```sh
secrets status                                  # reachable? locked? how many?
secrets unlock                                  # after a reboot with no Keychain escrow
secrets audit --secret github/pat                # who read what, when, from where
secrets backup                                   # snapshot now (nightly is automatic)
secrets versions github/pat                      # history
secrets get github/pat --version 3               # view an old one WITHOUT restoring it
secrets rollback github/pat 3                    # restore it (writes a new version)
launchctl kickstart -k gui/$(id -u)/com.stefan.secretd   # restart the daemon
tail -f ~/.secretd/logs/secretd.log
```

Backups: nightly `VACUUM INTO` snapshot to `~/.secretd/backups/`, 30-day retention,
encrypted with the same master key.

## Layout

```
src/vault/     crypto (Argon2id + XChaCha20-Poly1305), schema, CRUD/search/versioning
src/daemon/    HTTP API, activity feed, Keychain unlock, OAuth refresh, exec, backup
src/cli/       the `secrets` command
src/mcp/       MCP stdio server
src/ui/        single-page web UI
skills/        the secret-vault Claude skill
```

Only the daemon holds keys. The CLI, UI and MCP server are HTTP clients — one unlock,
one audit log, one source of truth.

## Development

```sh
npm run build      # tsc + copy UI assets
npm test           # build, then 45 vault tests
npm run test:ui    # drives the real UI in headless Chromium against a throwaway vault
npm run typecheck
```
