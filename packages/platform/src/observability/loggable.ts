// Turns whatever a caller logs into plain JSON data before pino sees it, so the
// data can then be redacted before it leaves the logger (logger.ts). Pino
// would otherwise write an error under any name but `err` with all its extra
// properties (a database error's `detail` holds the row's values), write the
// raw bytes of a Buffer, and round large bigints. It also never throws, so
// logging can't break the caller, even for an object whose getters throw.
import { serializeError } from './errors.ts';

/** Limits on the work for one log call; the output is cut further when redacted (redact.ts). */
export const LOGGABLE_LIMITS = { depth: 8, fieldsPerObject: 50, itemsPerArray: 50, nodes: 1000 } as const;

export const UNREADABLE = '[unreadable]';

type Loggable = string | number | boolean | null | Loggable[] | { [field: string]: Loggable };

interface Walk {
  nodes: number;
  /** The objects on the path to the current value, to spot a value that contains itself. */
  readonly ancestors: Set<object>;
}

function guarded<T>(read: () => T, fallback: T): T {
  try {
    return read();
  } catch {
    return fallback;
  }
}

function byteLength(value: object): number | undefined {
  if (ArrayBuffer.isView(value)) return value.byteLength;
  return value instanceof ArrayBuffer || value instanceof SharedArrayBuffer ? value.byteLength : undefined;
}

function toJsonMethod(value: object): (() => unknown) | undefined {
  const method: unknown = (value as { toJSON?: unknown }).toJSON;
  return typeof method === 'function' ? (method as () => unknown) : undefined;
}

function convertFields(value: object, walk: Walk, depth: number): Loggable {
  const names = Object.keys(value);
  const fields: [string, Loggable][] = [];
  for (const name of names.slice(0, LOGGABLE_LIMITS.fieldsPerObject)) {
    const item = guarded((): unknown => (value as Record<string, unknown>)[name], UNREADABLE);
    if (item !== undefined && typeof item !== 'function' && typeof item !== 'symbol') {
      fields.push([name, convert(item, walk, depth + 1)]);
    }
  }
  if (names.length > LOGGABLE_LIMITS.fieldsPerObject) {
    fields.push(['[fields cut]', names.length - LOGGABLE_LIMITS.fieldsPerObject]);
  }
  // Object.fromEntries defines each field as data, so a field named __proto__ stays a field.
  return Object.fromEntries(fields);
}

function convertContainer(value: object, walk: Walk, depth: number): Loggable {
  if (value instanceof Map) return convert([...value.entries()], walk, depth);
  if (value instanceof Set) return convert([...value.values()], walk, depth);
  if (Array.isArray(value)) {
    const items = value.slice(0, LOGGABLE_LIMITS.itemsPerArray).map((item: unknown) => convert(item, walk, depth + 1));
    if (value.length > LOGGABLE_LIMITS.itemsPerArray) {
      items.push(`[${value.length - LOGGABLE_LIMITS.itemsPerArray} more items cut]`);
    }
    return items;
  }
  const toJson = toJsonMethod(value);
  return toJson === undefined ? convertFields(value, walk, depth) : convert(toJson.call(value), walk, depth + 1);
}

function convertObject(value: object, walk: Walk, depth: number): Loggable {
  // serializeError keeps only the error's safe facts; its result is plain data.
  if (value instanceof Error) return convert(serializeError(value), walk, depth);
  const bytes = byteLength(value);
  if (bytes !== undefined) return { binaryBytes: bytes };
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value.toISOString();
  if (depth >= LOGGABLE_LIMITS.depth) return '[too deep]';
  if (walk.ancestors.has(value)) return '[circular]';
  walk.ancestors.add(value);
  try {
    return convertContainer(value, walk, depth);
  } finally {
    walk.ancestors.delete(value);
  }
}

function convert(value: unknown, walk: Walk, depth: number): Loggable {
  walk.nodes += 1;
  if (walk.nodes > LOGGABLE_LIMITS.nodes) return '[too large]';
  switch (typeof value) {
    case 'string':
    case 'boolean':
      return value;
    case 'number':
      return Number.isFinite(value) ? value : null;
    case 'bigint':
      // As text, so amounts in minor units keep every digit.
      return value.toString();
    case 'object':
      return value === null ? null : guarded(() => convertObject(value, walk, depth), UNREADABLE);
    case 'undefined':
    case 'function':
    case 'symbol':
      // No JSON form: a field holding one is left out, and a list item becomes null.
      return null;
  }
}

/** Plain JSON data for any value. It never throws. */
export function toLoggable(value: unknown): Loggable {
  return convert(value, { nodes: 0, ancestors: new Set() }, 0);
}
