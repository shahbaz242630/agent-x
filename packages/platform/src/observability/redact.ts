// SEC-DATA-01, SEC-DATA-05 (Rule Book §8, ADR-011 §7, ADR-013): the logger
// does the redaction, so nobody has to remember to. The logger cleans each
// event's fields before pino sees them (logger.ts), and redactLine cleans every
// finished line again just before it's written (pino's streamWrite hook), so
// a line from any source, such as the web framework's, is covered too.
//
// A value under a sensitive field name is replaced whole, at any depth
// (names.ts). Every other string is scrubbed for sensitive text (scrub.ts).
// Sizes are capped, so one huge or deeply nested value can't flood the log
// store (AV-8).
import { ruleForName } from './names.ts';
import { isPlainConstant, scrub } from './scrub.ts';

export const REDACTED = '[redacted]';

/** Safety bounds on one log line. They cap memory and log volume; they aren't business settings. */
export const LIMITS = {
  depth: 8,
  fieldsPerObject: 50,
  itemsPerArray: 50,
  nodes: 1000,
  stringLength: 2048,
  /** Under the 16 KiB at which container runtimes split a log line in two. */
  lineBytes: 16_000,
  /** A raw line longer than this isn't parsed at all. */
  rawLineLength: 4_000_000,
} as const;

/**
 * A long string is cleaned over its first `stringLength` characters, then this
 * many more are dropped from the end of the cleaned text: a secret cut in two by
 * the window's edge could survive there unrecognised.
 */
const CUT_MARGIN = 256;

/** The logger's own fields: never cut when a line has too many fields, and kept when a line is shortened. */
const OWN_FIELDS = new Set([
  'time',
  'level',
  'service',
  'env',
  'release',
  'event',
  'correlationId',
  'orgId',
  'actor',
  'module',
]);

/** Own fields checked where they're set (the time, the level, and validated config), so they're written as they are. */
const CHECKED_AT_SOURCE = new Set(['time', 'level', 'service', 'env', 'release']);

type Json = string | number | boolean | null | Json[] | { [field: string]: Json };
type JsonObject = Record<string, Json>;

interface Walk {
  nodes: number;
}

function cleanString(text: string): string {
  if (text.length <= LIMITS.stringLength) return scrub(text);
  const cleaned = scrub(text.slice(0, LIMITS.stringLength));
  return `${cleaned.slice(0, Math.max(0, cleaned.length - CUT_MARGIN))}…[cut from ${text.length} characters]`;
}

function isSafeConstant(value: unknown): boolean {
  if (typeof value === 'string') return isPlainConstant(value);
  return typeof value === 'number' || typeof value === 'boolean' || value === null;
}

function cleanField(name: string, value: unknown, walk: Walk, depth: number): Json {
  const rule = ruleForName(name);
  if (rule === 'redact' || (rule === 'redact-unless-constant' && !isSafeConstant(value))) return REDACTED;
  return cleanValue(value, walk, depth + 1);
}

/**
 * Builds the object with Object.fromEntries, which defines each field as data:
 * a field named `__proto__` stays a field instead of replacing the prototype.
 * On the line itself, the logger's own fields don't count towards the field cap.
 */
function cleanObject(value: object, walk: Walk, depth: number): JsonObject {
  const entries = Object.entries(value);
  const own = depth === 0 ? entries.filter(([name]) => OWN_FIELDS.has(name) || name === 'err') : [];
  const rest = depth === 0 ? entries.filter(([name]) => !OWN_FIELDS.has(name) && name !== 'err') : entries;
  const cleaned: [string, Json][] = [
    ...own.map(([name, item]): [string, Json] => [
      name,
      CHECKED_AT_SOURCE.has(name) && typeof item === 'string' && item.length <= 64
        ? item
        : cleanField(name, item, walk, depth),
    ]),
    // A field name can carry personal data too, e.g. an email used as a key.
    ...rest
      .slice(0, LIMITS.fieldsPerObject)
      .map(([name, item]): [string, Json] => [cleanString(name), cleanField(name, item, walk, depth)]),
  ];
  if (rest.length > LIMITS.fieldsPerObject) cleaned.push(['[fields cut]', rest.length - LIMITS.fieldsPerObject]);
  return Object.fromEntries(cleaned);
}

function cleanValue(value: unknown, walk: Walk, depth: number): Json {
  walk.nodes += 1;
  if (walk.nodes > LIMITS.nodes) return '[too large]';
  if (typeof value === 'string') return cleanString(value);
  // JSON data holds only strings, numbers, booleans, null, arrays and objects.
  if (typeof value !== 'object' || value === null) {
    return typeof value === 'number' || typeof value === 'boolean' ? value : null;
  }
  if (depth >= LIMITS.depth) return '[too deep]';
  if (!Array.isArray(value)) return cleanObject(value, walk, depth);
  const items = value.slice(0, LIMITS.itemsPerArray).map((item: unknown) => cleanValue(item, walk, depth + 1));
  if (value.length > LIMITS.itemsPerArray) items.push(`[${value.length - LIMITS.itemsPerArray} more items cut]`);
  return items;
}

/** Redacts plain JSON data: an event's fields before pino sees them, or a parsed line. */
export function redactJson(value: unknown): Json {
  return cleanValue(value, { nodes: 0 }, 0);
}

function isObject(value: Json | undefined): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

const bytes = (line: JsonObject): number => Buffer.byteLength(JSON.stringify(line), 'utf8');

function shorten(text: Json | undefined, length: number): Json {
  return typeof text === 'string' && text.length > length ? `${text.slice(0, length)}…` : (text ?? null);
}

/** A field that should hold text, as text at most `length` long; anything else as empty text. */
function textOf(value: Json | undefined, length: number): string {
  if (typeof value !== 'string') return '';
  return value.length > length ? `${value.slice(0, length)}…` : value;
}

/** An error's key facts: its type, message and code, with its first stack positions and its causes' types. */
function errorSummary(err: Json, frames: number): Json {
  if (!isObject(err)) return shorten(err, 256);
  const causes: Json[] = [];
  for (let cause = err.cause; isObject(cause) && causes.length < 3; cause = cause.cause) {
    causes.push(`${textOf(cause.type, 64)}: ${textOf(cause.message, 128)}`);
  }
  return {
    type: shorten(err.type, 64),
    message: shorten(err.message, 512),
    ...(err.code === undefined ? {} : { code: shorten(err.code, 64) }),
    ...(frames > 0 && Array.isArray(err.stack) ? { stack: err.stack.slice(0, frames) } : {}),
    ...(causes.length > 0 ? { causes } : {}),
  };
}

function ownFields(line: JsonObject, length: number): JsonObject {
  const kept = Object.entries(line)
    .filter(([name, value]) => OWN_FIELDS.has(name) && typeof value === 'string')
    .map(([name, value]): [string, Json] => [name, shorten(value, length)]);
  return Object.fromEntries(kept);
}

/**
 * A line over the size limit is shortened in steps, keeping as much as fits:
 * first the error loses its causes' detail, then the other fields go, and last
 * everything is cut to its key facts, which always fit.
 */
function fit(line: JsonObject): JsonObject {
  if (bytes(line) <= LIMITS.lineBytes) return line;
  const { err } = line;
  const summary = (frames: number): JsonObject => (err === undefined ? {} : { err: errorSummary(err, frames) });
  const withSummary = { ...line, ...summary(5), lineCut: true };
  if (bytes(withSummary) <= LIMITS.lineBytes) return withSummary;
  const essentials = { ...ownFields(line, 1024), ...summary(5), lineCut: true };
  if (bytes(essentials) <= LIMITS.lineBytes) return essentials;
  return { ...ownFields(line, 256), ...summary(0), lineCut: true };
}

/** U+2028, U+2029 and U+0085 are valid inside JSON strings, but some tools treat them as line breaks. */
const LINE_BREAK_LOOKALIKES = /[\u2028\u2029\u0085]/g;
const escaped = (text: string): string =>
  text.replace(LINE_BREAK_LOOKALIKES, (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`);

function fixedLine(event: string, now: () => number): string {
  return `${JSON.stringify({ time: new Date(now()).toISOString(), level: 'error', event })}\n`;
}

/**
 * pino's streamWrite hook: takes one finished JSON line and returns it
 * redacted, still one JSON line. It never throws and never returns the input
 * unredacted: a line it can't read becomes a fixed error line instead.
 */
export function redactLine(line: string, now: () => number = Date.now): string {
  if (line.length > LIMITS.rawLineLength) return fixedLine('log.line_too_large', now);
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    return fixedLine('log.unreadable_line', now);
  }
  const cleaned = redactJson(parsed);
  return `${escaped(JSON.stringify(isObject(cleaned) ? fit(cleaned) : cleaned))}\n`;
}
