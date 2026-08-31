import { randomInt } from 'node:crypto';

/**
 * Password generation.
 *
 * Ambiguous glyphs are left out of every set: a generated password is often read off a
 * screen and typed somewhere else, and `l/1/I` or `0/O` is where that goes wrong. The
 * lost entropy is bought back by length, which is free.
 */

export class GenerateError extends Error {}

const SETS = {
  lower: 'abcdefghijkmnopqrstuvwxyz',
  upper: 'ABCDEFGHJKLMNPQRSTUVWXYZ',
  digit: '23456789',
  symbol: '!@#$%^&*-_=+?',
} as const;

export interface GenerateOptions {
  length?: number;
  /** All default to on except symbols, which too many sites still reject. */
  upper?: boolean;
  digits?: boolean;
  symbols?: boolean;
}

export function generatePassword(o: GenerateOptions = {}): string {
  const length = o.length ?? 24;
  if (!Number.isInteger(length) || length < 8 || length > 256) {
    throw new GenerateError('length must be a whole number between 8 and 256');
  }

  const groups: string[] = [SETS.lower];
  if (o.upper !== false) groups.push(SETS.upper);
  if (o.digits !== false) groups.push(SETS.digit);
  if (o.symbols) groups.push(SETS.symbol);
  const all = groups.join('');

  // One character from each group up front, so the result always satisfies the
  // "must contain a digit" rules sites impose without having to retry until it does.
  const chars = groups.map((g) => g[randomInt(g.length)]!);
  while (chars.length < length) chars.push(all[randomInt(all.length)]!);

  // Then shuffle, or the first characters would always be one-per-group in order.
  // randomInt rejection-samples, so this is uniform; `% n` over random bytes is not.
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [chars[i], chars[j]] = [chars[j]!, chars[i]!];
  }
  return chars.join('');
}
