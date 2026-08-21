---
name: secret-vault
description: Retrieve, create and rotate secrets (API keys, OAuth tokens, SSH keys, connection strings, .env bundles) from the local secretd vault using natural language. Use whenever a task needs a credential, mentions a service by name that likely has stored credentials, or asks to store/rotate/look up a secret.
---

# Secret vault

The `secrets` MCP server is the operator's personal credential vault. It holds API keys,
OAuth tokens, SSH/TLS key material, database connection strings, and `.env` bundles.

## The one rule that matters

**Search before you get.** Never guess a secret name.

Names are hierarchical (`stripe/test/sk`, `github/pat`, `postgres/prod`) and guessing
produces 404s and wasted turns. `search_secrets` matches against names, aliases,
descriptions, services, environments and tags — so plain English works:

```
search_secrets("the stripe test key")     -> stripe/test/sk
search_secrets("prod database")           -> postgres/prod
search_secrets("the thing that sends texts") -> twilio/auth-token
```

## Workflow

1. **`search_secrets`** with the user's own words. Do not paraphrase into a guessed name.
2. **Disambiguate.** If more than one result is plausible, *ask which one* — do not pick.
   Reading a production credential when a development one was meant is a far worse
   outcome than one extra question. `env` and `service` in the results are your signal.
3. **Retrieve**, choosing the right tool:
   - **`run_with_secrets`** when the secret only needs to reach a command. The value
     goes into the child process's environment (or a `0600` temp file, or its stdin)
     and never enters the conversation. **This is the default.**
   - **`get_secret`** only when the value itself must be reasoned about, transformed,
     or shown to the user.

## Prefer run_with_secrets

```
run_with_secrets(command="gh", args=["repo","list"], secrets=[{name:"github/pat"}])
run_with_secrets(command="psql", args=["$DATABASE_URL","-c","\\dt"],
                 secrets=[{name:"postgres/prod", as:"DATABASE_URL"}])
run_with_secrets(command="ssh", args=["-i","{{deploy-key}}","host"],
                 secrets=[{name:"deploy-key", mode:"file"}])
```

- `mode:"env"` (default) sets an environment variable. Default name is the secret name
  upper-snake-cased: `github/pat` becomes `GITHUB_PAT`. Override with `as`.
- `mode:"file"` writes a `0600` temp file and sets the variable to its **path** — this is
  what SSH keys, TLS certs and GPG keys need. The file is deleted when the command exits.
- `mode:"stdin"` pipes the value to the command's stdin.
- `{{secret-name}}` in args is substituted with the value (env mode) or the path (file mode).
- An `env_bundle` expands into *all* of its variables at once — perfect for
  "run the test suite with the project's env".

## When you must use get_secret

`get_secret` puts plaintext into the conversation, which means it reaches the transcript
and is written to `~/.claude/projects/*.jsonl` on disk. That is an accepted tradeoff the
operator chose, not a reason to refuse — but it *is* a reason to prefer the alternative
and to never make it worse:

- **Never write a retrieved value into a file, commit, comment, issue, PR, or log.**
- Never echo it back in a summary unless the user explicitly asked to see it.
- When showing that something worked, show a length or a prefix, not the value.

## Creating secrets

Metadata written now *is* search quality later. Always supply `description`, `service`,
and at least one natural-language `alias`:

```
create_secret(
  name="twilio/auth-token", type="api_key", value="...",
  description="Twilio auth token for outbound SMS",
  service="twilio", env="prod",
  tags=["sms","messaging"],
  aliases=["twilio", "sms-token", "text-sending"]
)
```

Aliases should be what a *human would say six months from now*, not a second copy of
the name. "the thing that sends texts" only resolves if someone wrote that alias down.

## Types

| type | for | value shape |
|---|---|---|
| `api_key` | static keys and tokens | bare string |
| `oauth` | tokens that expire | `{access_token, refresh_token, expires_at, token_url, client_id, client_secret}` |
| `key_file` | SSH/GPG keys, TLS certs | `{pem, passphrase?}` — use `mode:"file"` to consume |
| `connection_string` | database and service URLs | bare URL string |
| `env_bundle` | grouped project env | `.env` text, or a `{KEY: value}` object |
| `note` | anything else | bare string |

`oauth` secrets refresh themselves on read. If a response carries `warning: expired`,
tell the user their refresh token needs re-authorising — do not retry in a loop.

## Rotation

`update_secret` creates a new version; the old one is retained. Always pass a `note`
explaining why (`"rotated after leak"`). If a rotation turns out wrong, `list_versions`
then `rollback_secret` restores the previous value as a new version — history is never
destroyed. `delete_secret` **is** destructive and removes all history: confirm first.

## When things fail

- **"vault is locked"** — the operator must run `secrets unlock` on the host. You cannot
  fix this; say so and stop.
- **404 with candidates** — the error lists the closest names. Confirm with
  `search_secrets` before retrying; do not blind-retry a different guess.
- **"Unauthorised"** — `secrets-mcp` has a stale token. The operator needs to update
  `SECRETD_TOKEN` from `~/.secretd/token`.
