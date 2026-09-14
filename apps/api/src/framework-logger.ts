// ADR-013, logging standard §2: Fastify logs through pino's interface, an
// object of fields and then a message. Given pino itself, its lines would reach
// pino, and pino's diagnostics channel, before our cleaning, and its fields
// could overwrite the logger's own. So it gets this adapter instead: each of
// its lines becomes one `http.framework_log` event, written through our Logger
// and cleaned like any other. Only the message and the error are kept. Its
// other fields hold whole requests and replies, whose addresses, client IPs and
// headers must never be logged (ADR-011 §7). Some of its messages quote the
// address as sent, so paths are taken out of the message, and its own errors
// keep their code but not their message.
import type { EventName, Logger, LogFields } from '@agentx/platform/observability';
import type { FastifyBaseLogger } from 'fastify';

export const FRAMEWORK_EVENT: EventName = 'http.framework_log';

/** The binding Fastify gives each request's logger. It's the server's `requestIdLogLabel`. */
export const REQUEST_ID_BINDING = 'correlationId';

type Level = 'error' | 'warn' | 'info' | 'debug';

/**
 * A path, from its slash to the next space (a quote in a query doesn't stop it).
 * `//` isn't one, so `http://host` stays.
 */
const PATH = /(^|[\s"'(=,:])\/(?!\/)\S*/g;
const PATH_REMOVED = '$1[path]';

/** Fastify's own errors' codes: their messages can quote the address as sent. */
const FASTIFY_CODE_PREFIX = 'FST_';

/**
 * The error, whether passed alone (`log.error(err)`) or as the `err` field.
 * Only a plain data field is read: a getter isn't run, so it can't throw.
 */
function errorOf(first: unknown): unknown {
  if (first instanceof Error) return first;
  if (typeof first !== 'object' || first === null) return undefined;
  const descriptor = Object.getOwnPropertyDescriptor(first, 'err');
  return descriptor === undefined ? undefined : (descriptor.value as unknown);
}

/** A Fastify error, with its code as its message; any other error as it is. */
function withoutAddress(err: unknown): unknown {
  if (!(err instanceof Error)) return err;
  const code: unknown = (err as { code?: unknown }).code;
  if (typeof code !== 'string' || !code.startsWith(FASTIFY_CODE_PREFIX)) return err;
  // The stack's first line repeats the message, but the logger keeps only the frames below it.
  return Object.assign(new Error(code), { name: err.name, code, stack: err.stack, cause: err.cause });
}

/** pino's call shapes: `(message)`, or `(fields or error, message?)`. Any format arguments are left out. */
function fieldsOf(args: readonly unknown[]): LogFields {
  const [first, second] = args;
  const message = typeof first === 'string' ? first : second;
  const err = typeof first === 'string' ? undefined : errorOf(first);
  return {
    ...(typeof message === 'string' ? { detail: message.replace(PATH, PATH_REMOVED) } : {}),
    ...(err === undefined ? {} : { err: withoutAddress(err) }),
  };
}

/** Only the correlation ID is carried into a request's lines; other bindings are left out. */
function bindingsOf(bindings: Readonly<Record<string, unknown>>): { correlationId?: string } {
  const id: unknown = bindings[REQUEST_ID_BINDING];
  return typeof id === 'string' ? { correlationId: id } : {};
}

/** A logger in the shape Fastify expects, writing through `logger`. `level` is shown to Fastify only. */
export function frameworkLogger(logger: Logger, level: string): FastifyBaseLogger {
  const at =
    (to: Level) =>
    (...args: unknown[]): void => {
      logger[to](FRAMEWORK_EVENT, fieldsOf(args));
    };
  return {
    level,
    // We have four levels (logging standard §2): fatal is an error, trace is debug.
    fatal: at('error'),
    error: at('error'),
    warn: at('warn'),
    info: at('info'),
    debug: at('debug'),
    trace: at('debug'),
    silent: () => undefined,
    child: (bindings) => frameworkLogger(logger.child(bindingsOf(bindings)), level),
  };
}
