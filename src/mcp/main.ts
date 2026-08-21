#!/usr/bin/env -S node --no-warnings
import '../shared/quiet.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { SecretdClient, ApiError, defaultBaseUrl, defaultPassword } from '../shared/client.js';
import { SECRET_TYPES } from '../vault/types.js';

// stdout is the MCP protocol channel — every diagnostic must go to stderr.
const note = (msg: string): void => void process.stderr.write(`[secrets-mcp] ${msg}\n`);

const api = new SecretdClient(defaultBaseUrl(), defaultPassword(), 'mcp');

type ToolResult = {
  content: Array<{ type: 'text'; text: string }>;
  isError?: boolean;
};

const ok = (data: unknown): ToolResult => ({
  content: [{ type: 'text', text: typeof data === 'string' ? data : JSON.stringify(data, null, 2) }],
});

const fail = (message: string): ToolResult => ({
  content: [{ type: 'text', text: message }],
  isError: true,
});

/** Turns transport/API errors into text the model can actually act on. */
async function guard(fn: () => Promise<unknown>): Promise<ToolResult> {
  try {
    return ok(await fn());
  } catch (err) {
    if (err instanceof ApiError) {
      if (err.status === 404 && err.candidates.length) {
        return fail(`${err.message}\n\nClosest matches: ${err.candidates.join(', ')}\nUse search_secrets to confirm before retrying.`);
      }
      if (err.status === 423) {
        return fail('The vault is locked. The operator must run `secrets unlock` on the host.');
      }
      if (err.status === 401) {
        return fail('Unauthorised — secrets-mcp has a stale or missing bearer token (SECRETD_TOKEN).');
      }
      return fail(err.message);
    }
    return fail(err instanceof Error ? err.message : String(err));
  }
}

const server = new McpServer(
  { name: 'secrets', version: '0.1.0' },
  {
    instructions: [
      'This server is the operator\'s personal secrets vault.',
      '',
      'ALWAYS call search_secrets before get_secret. Secret names are hierarchical',
      '(e.g. "stripe/test/sk") and guessing them wastes turns and produces 404s.',
      '',
      'If a search returns more than one plausible match, ASK the operator which one',
      'rather than picking. Reading a production credential when a development one was',
      'meant is a worse failure than one extra question.',
      '',
      'Prefer run_with_secrets when a secret is only needed to run a command — it injects',
      'the value into the child process without the value entering the conversation.',
      'Use get_secret only when the value itself must be reasoned about or displayed.',
      '',
      'Never write a retrieved value into a file, commit, comment, issue, or log.',
    ].join('\n'),
  },
);

server.registerTool(
  'search_secrets',
  {
    title: 'Search secrets',
    description:
      'Find secrets by natural language. Searches names, aliases, descriptions, services, environments and tags — never the values themselves. Returns metadata only, no secret values. This is the correct first step for any secret-related request.',
    inputSchema: {
      query: z.string().describe('Natural language, e.g. "the stripe test key" or "prod database"'),
      limit: z.number().int().min(1).max(50).optional().describe('Max results, default 10'),
    },
  },
  async ({ query, limit }) =>
    guard(async () => {
      const items = await api.search(query, limit ?? 10);
      if (!items.length) {
        return `No secrets matched "${query}". Try list_secrets to see what exists.`;
      }
      return items.map((i) => ({
        name: i.name,
        type: i.type,
        description: i.description,
        service: i.service,
        env: i.env,
        tags: i.tags,
        aliases: i.aliases,
      }));
    }),
);

server.registerTool(
  'list_secrets',
  {
    title: 'List secrets',
    description:
      'List all secrets, optionally filtered. Returns metadata only, no values. Use when browsing or when search comes up empty.',
    inputSchema: {
      type: z.enum(SECRET_TYPES).optional(),
      tag: z.string().optional(),
      service: z.string().optional().describe('e.g. "github", "stripe"'),
      env: z.string().optional().describe('e.g. "prod", "dev"'),
    },
  },
  async (filter) =>
    guard(async () => {
      const items = await api.list(filter);
      return items.map((i) => ({
        name: i.name,
        type: i.type,
        description: i.description,
        env: i.env,
        tags: i.tags,
        aliases: i.aliases,
      }));
    }),
);

server.registerTool(
  'get_secret',
  {
    title: 'Get secret value',
    description:
      'Retrieve a secret\'s decrypted value. Accepts a name or an alias. This puts the plaintext into the conversation — prefer run_with_secrets when the value only needs to reach a command. OAuth secrets are refreshed automatically if expired, unless an older version was asked for.',
    inputSchema: {
      name: z.string().describe('Exact name or alias, ideally one returned by search_secrets'),
      version: z
        .number()
        .int()
        .min(1)
        .optional()
        .describe(
          'Read an older version instead of the current one, without restoring it. Use list_versions first. This is a read — it changes nothing.',
        ),
    },
  },
  async ({ name, version }) =>
    guard(async () => {
      const rec = await api.get(name, false, version);
      return {
        name: rec.name,
        type: rec.type,
        value: rec.value,
        version: rec.version,
        current_version: rec.current_version,
        ...(rec.stale ? { warning: 'This token is expired and could not be refreshed.' } : {}),
        ...(rec.refreshed ? { note: 'Token was auto-refreshed; a new version was stored.' } : {}),
      };
    }),
);

server.registerTool(
  'create_secret',
  {
    title: 'Create secret',
    description:
      'Store a new secret. Always supply description, service and at least one alias — search quality later depends entirely on the metadata written now.',
    inputSchema: {
      name: z.string().describe('Hierarchical, e.g. "stripe/test/sk"'),
      type: z.enum(SECRET_TYPES),
      value: z
        .union([z.string(), z.record(z.string(), z.unknown())])
        .describe('A bare string for simple types, or an object matching the type schema'),
      description: z.string().optional(),
      service: z.string().optional(),
      env: z.string().optional(),
      url: z.string().optional(),
      tags: z.array(z.string()).optional(),
      aliases: z.array(z.string()).optional().describe('Natural names a human would search for'),
    },
  },
  async (body) => guard(() => api.create(body)),
);

server.registerTool(
  'update_secret',
  {
    title: 'Update secret value',
    description:
      'Write a new value, creating a new version. The previous version is retained and can be restored with rollback_secret.',
    inputSchema: {
      name: z.string(),
      value: z.union([z.string(), z.record(z.string(), z.unknown())]),
      note: z.string().optional().describe('Why it changed, e.g. "rotated after leak"'),
    },
  },
  async ({ name, value, note }) => guard(() => api.update(name, value, note)),
);

server.registerTool(
  'update_secret_metadata',
  {
    title: 'Update secret metadata',
    description:
      'Edit description, tags, aliases, service, env or url without touching the value or creating a version. Use this to improve searchability.',
    inputSchema: {
      name: z.string(),
      description: z.string().optional(),
      service: z.string().optional(),
      env: z.string().optional(),
      url: z.string().optional(),
      tags: z.array(z.string()).optional(),
      aliases: z.array(z.string()).optional(),
    },
  },
  async ({ name, ...rest }) => guard(() => api.patch(name, rest)),
);

server.registerTool(
  'delete_secret',
  {
    title: 'Delete secret',
    description:
      'Permanently delete a secret and its entire version history. This cannot be undone. Confirm with the operator first.',
    inputSchema: { name: z.string() },
  },
  async ({ name }) => guard(() => api.remove(name)),
);

server.registerTool(
  'list_versions',
  {
    title: 'List versions',
    description: 'Version history for a secret — numbers, timestamps and notes. No values.',
    inputSchema: { name: z.string() },
  },
  async ({ name }) => guard(() => api.versions(name)),
);

server.registerTool(
  'rollback_secret',
  {
    title: 'Roll back secret',
    description:
      'Restore an earlier version by copying it forward as a new version. History is never destroyed.',
    inputSchema: { name: z.string(), version: z.number().int().min(1) },
  },
  async ({ name, version }) => guard(() => api.rollback(name, version)),
);

server.registerTool(
  'run_with_secrets',
  {
    title: 'Run a command with secrets injected',
    description:
      'Run a command with secrets injected into its environment, a 0600 temp file, or its stdin — WITHOUT the values entering this conversation. Prefer this over get_secret whenever the secret only needs to reach a program. Mode "env" sets an environment variable (default name is the secret name upper-snake-cased). Mode "file" writes a temp file and sets the variable to its path. `{{secret-name}}` in args is substituted with the value or path.',
    inputSchema: {
      command: z.string().describe('Executable, e.g. "gh" or "psql"'),
      args: z.array(z.string()).optional(),
      secrets: z
        .array(
          z.object({
            name: z.string(),
            as: z.string().optional().describe('Environment variable name'),
            mode: z.enum(['env', 'file', 'stdin']).optional(),
          }),
        )
        .describe('Secrets to inject'),
      cwd: z.string().optional(),
      timeoutMs: z.number().int().optional().describe('Default 120000'),
    },
  },
  async ({ command, args, secrets, cwd, timeoutMs }) =>
    guard(async () => {
      const r = await api.exec(command, args ?? [], secrets, { cwd, timeoutMs });
      return {
        exit_code: r.code,
        stdout: r.stdout,
        stderr: r.stderr,
        ...(r.truncated ? { truncated: true } : {}),
      };
    }),
);

server.registerTool(
  'vault_status',
  {
    title: 'Vault status',
    description: 'Whether the vault daemon is reachable, initialised and unlocked, and how many secrets it holds.',
    inputSchema: {},
  },
  async () => guard(() => api.health()),
);

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  note(`connected to ${defaultBaseUrl()}`);
}

main().catch((err: unknown) => {
  note(`fatal: ${err instanceof Error ? err.stack ?? err.message : String(err)}`);
  process.exit(1);
});
