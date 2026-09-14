// SEC-DATA-02 (ADR-013): how an error appears in the log. Only a fixed set of
// facts is kept: the type, the message, a safe error code, the stack
// positions, and the chain of causes. Anything else an error object carries,
// such as a database driver's `detail` holding the row's values, is left out.
// The message is still cleaned like every other string when the line is
// written (redact.ts).

export interface LoggedError {
  readonly type: string;
  readonly message: string;
  readonly code?: string;
  /** "at function (file:line:column)" positions only; the header line, which repeats the message, is dropped. */
  readonly stack?: readonly string[];
  readonly cause?: LoggedError;
  /** The errors inside an AggregateError. */
  readonly errors?: readonly LoggedError[];
  /** Set when the cause chain or the error list was cut. */
  readonly cut?: true;
}

/**
 * Safety bounds, so one error can't make a huge line. Messages aren't cut here:
 * the redaction step cuts every string, cleaning first so a cut can't leave a
 * fragment of a secret (redact.ts).
 */
const LIMITS = { frames: 20, causeDepth: 3, aggregated: 10 } as const;

/**
 * Error codes: a name starting with a capital (ECONNREFUSED, ERR_INVALID_URL)
 * or a five-character SQL state (23505, 42P01). Anything else might be data,
 * such as an account number.
 */
const SAFE_CODE = /^(?:[A-Z][A-Z0-9_]{1,63}|[0-9A-Z]{5})$/;
const STACK_FRAME = /^\s+at\s/;

/** Reads a property that might be a throwing getter, as some libraries' errors have. */
function read(target: object, property: string): unknown {
  try {
    return (target as Record<string, unknown>)[property];
  } catch {
    return undefined;
  }
}

function asText(value: unknown): string {
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') return String(value);
  return `(${typeof value})`;
}

function stackOf(error: Error): readonly string[] | undefined {
  const stack = read(error, 'stack');
  if (typeof stack !== 'string') return undefined;
  const frames = stack
    .split('\n')
    .filter((line) => STACK_FRAME.test(line))
    .slice(0, LIMITS.frames)
    .map((line) => line.trim());
  return frames.length > 0 ? frames : undefined;
}

function toLogged(value: unknown, depth: number): LoggedError {
  if (!(value instanceof Error)) {
    // Libraries sometimes throw plain objects or strings rather than Errors.
    const message = typeof value === 'object' && value !== null ? read(value, 'message') : value;
    return { type: 'NonError', message: asText(message) };
  }
  const name = read(value, 'name');
  const code = read(value, 'code');
  const stack = stackOf(value);
  const cause = read(value, 'cause');
  const inner = value instanceof AggregateError ? read(value, 'errors') : undefined;
  const list = Array.isArray(inner) ? (inner as unknown[]) : [];

  const nested = depth < LIMITS.causeDepth;
  const cut = (!nested && (cause !== undefined || list.length > 0)) || list.length > LIMITS.aggregated;
  return {
    type: typeof name === 'string' && name !== '' ? name : 'Error',
    message: asText(read(value, 'message')),
    ...(typeof code === 'string' && SAFE_CODE.test(code) ? { code } : {}),
    ...(stack === undefined ? {} : { stack }),
    ...(nested && cause !== undefined ? { cause: toLogged(cause, depth + 1) } : {}),
    ...(nested && list.length > 0
      ? { errors: list.slice(0, LIMITS.aggregated).map((item) => toLogged(item, depth + 1)) }
      : {}),
    ...(cut ? { cut: true } : {}),
  };
}

/** pino's serializer for the `err` field. It accepts anything, since JavaScript can throw anything. */
export function serializeError(value: unknown): LoggedError {
  return toLogged(value, 0);
}
