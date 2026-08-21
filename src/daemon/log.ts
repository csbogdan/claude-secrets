import { EventEmitter } from 'node:events';

export type Level = 'info' | 'warn' | 'error';

export interface FeedEvent {
  ts: number;
  level: Level;
  msg: string;
  action?: string;
  secret?: string;
  caller?: string;
  source?: string;
  ok?: boolean;
  /** Present on long-running work so consumers can render a progress bar. */
  progress?: { current: number; total: number };
}

/**
 * The user-facing activity feed. Every operation lands here, is printed to stderr,
 * and is streamed to `secrets logs -f` and the web UI. Secret VALUES are never
 * written to it — names, callers and outcomes only.
 */
class Feed extends EventEmitter {
  private ring: FeedEvent[] = [];
  private readonly max = 1000;

  push(e: FeedEvent): void {
    this.ring.push(e);
    if (this.ring.length > this.max) this.ring.shift();
    this.emit('event', e);
  }

  recent(n = 100): FeedEvent[] {
    return this.ring.slice(-n);
  }
}

export const feed = new Feed();
// One listener per open SSE stream (CLI `logs -f`, each browser tab). The default
// cap of 10 would start dropping warnings we've deliberately silenced.
feed.setMaxListeners(200);

function hhmmss(ts: number): string {
  return new Date(ts).toISOString().slice(11, 19);
}

/** `08:31:04  read github/pat -> ok (mcp 127.0.0.1)` */
export function formatEvent(e: FeedEvent): string {
  const bits: string[] = [hhmmss(e.ts)];
  if (e.level === 'error') bits.push('ERROR');
  else if (e.level === 'warn') bits.push('WARN ');
  else bits.push('     ');
  bits.push(e.msg);
  if (e.progress) bits.push(`(${e.progress.current}/${e.progress.total})`);
  const who = [e.caller, e.source].filter(Boolean).join(' ');
  if (who) bits.push(`[${who}]`);
  return bits.join(' ');
}

function emit(level: Level, msg: string, meta: Partial<FeedEvent> = {}): FeedEvent {
  const e: FeedEvent = { ts: Date.now(), level, msg, ...meta };
  feed.push(e);
  process.stderr.write(`${formatEvent(e)}\n`);
  return e;
}

export const log = {
  info: (msg: string, meta?: Partial<FeedEvent>) => emit('info', msg, meta),
  warn: (msg: string, meta?: Partial<FeedEvent>) => emit('warn', msg, meta),
  error: (msg: string, meta?: Partial<FeedEvent>) => emit('error', msg, meta),

  /** Short operations: one line carrying the outcome. */
  op(action: string, ok: boolean, detail: string, meta: Partial<FeedEvent> = {}): void {
    emit(ok ? 'info' : 'warn', `${action} ${detail} ${ok ? '-> ok' : '-> FAILED'}`, {
      ...meta,
      action,
      ok,
    });
  },

  /** Long operations: steady incremental progress so the feed never looks dead. */
  progress(action: string, current: number, total: number, detail = ''): void {
    emit('info', `${action}${detail ? ` ${detail}` : ''}`, {
      action,
      progress: { current, total },
    });
  },
};
