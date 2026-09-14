// The logging standard §2 (ADR-013): the app's one telemetry path. Every
// runtime writes one JSON line per event to stdout and sends nothing anywhere
// else. The platform collects stdout: Azure Log Analytics for our SaaS, a
// customer's own tools when they host it.
//
// Each event's fields are turned into plain data and redacted before pino sees
// them, so nothing unredacted reaches pino, or anything listening to it (pino
// publishes each line on a diagnostics channel before writing it). On the way
// out, pino hooks cap each event per minute (volume-guard.ts) and redact the
// finished line again (redact.ts), for every logger made from this one.
import pino from 'pino';

import type { Config, LogLevel } from '../config/index.ts';
import { toLoggable } from './loggable.ts';
import { redactJson, redactLine } from './redact.ts';
import { createVolumeGuard, MINUTE_MS } from './volume-guard.ts';

/** Lowercase words joined by dots, e.g. `spend_request.decided`. A name never changes once used. */
export type EventName = `${string}.${string}`;
const EVENT_NAME = /^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$/;

/** Event names starting `log.` are the logger's own. */
const LOGGER_EVENTS = 'log.';
export const SUPPRESSED_EVENT = 'log.suppressed';
export const INVALID_EVENT = 'log.invalid_event';

/**
 * Fields the logger writes itself. A caller can't set them: the type forbids
 * the common ones, and all of them are dropped if passed. That includes the
 * child-logger fields, so an event can't claim another organisation's ID.
 */
const RESERVED = new Set([
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
  'invalidEvent',
  'suppressedEvent',
  'suppressedCount',
  'suppressedFrom',
  'suppressedTo',
  'lineCut',
  'fieldsUnreadable',
]);

/** An event's fields. Put an error under `err`; errors under other names are logged the same safe way. */
export type LogFields = Readonly<Record<string, unknown>> & {
  readonly time?: never;
  readonly level?: never;
  readonly service?: never;
  readonly env?: never;
  readonly release?: never;
  readonly event?: never;
  readonly correlationId?: never;
  readonly orgId?: never;
  readonly actor?: never;
  readonly module?: never;
};

/** What a child logger adds to each of its lines, e.g. per request. */
export interface LogBindings {
  readonly correlationId?: string;
  readonly orgId?: string;
  /** The user or agent ID acting. */
  readonly actor?: string;
  readonly module?: string;
}
const BINDING_NAMES = ['correlationId', 'orgId', 'actor', 'module'] as const;

export type LogMethod = (event: EventName, fields?: LogFields) => void;

export interface Logger {
  readonly error: LogMethod;
  readonly warn: LogMethod;
  readonly info: LogMethod;
  readonly debug: LogMethod;
  child(bindings: LogBindings): Logger;
  /**
   * Writes any held-back counts now. Call it before the process exits, on a
   * normal exit and on a fatal error, or the last minute's counts are lost.
   */
  flush(): void;
}

export interface LoggerOptions {
  /** Which runtime is logging, e.g. `api` or `worker`. */
  readonly service: string;
  readonly config: Pick<Config, 'environment' | 'release' | 'log'>;
  /**
   * Where lines go. By default, stdout, written synchronously so a crash can't
   * lose the last lines. Tests pass a capture.
   */
  readonly destination?: pino.DestinationStream;
  /** Milliseconds since 1970, for the time field and the volume guard's minutes. */
  readonly now?: () => number;
}

const NO_EVENT = '(no event)';

/** Our level for one of pino's level numbers (error is 50, warn 40, info 30). */
function levelName(level: number): LogLevel {
  if (level >= 50) return 'error';
  if (level >= 40) return 'warn';
  return level >= 30 ? 'info' : 'debug';
}

/**
 * The line's event: the first text argument of the log call. For our own calls
 * that's the event name; a call with no text (possible once a framework logs
 * through pino directly) is counted as one event.
 */
export function eventOf(args: readonly unknown[]): string {
  const text = args.find((arg) => typeof arg === 'string');
  return typeof text === 'string' ? text.slice(0, 200) : NO_EVENT;
}

/** The fields as plain, redacted data, without the logger's own names. It never throws. */
function prepared(fields: LogFields): Record<string, unknown> {
  const plain = toLoggable(fields);
  if (typeof plain !== 'object' || plain === null || Array.isArray(plain)) return { fieldsUnreadable: true };
  const kept = Object.entries(plain).filter(([name]) => !RESERVED.has(name));
  return redactJson(Object.fromEntries(kept)) as Record<string, unknown>;
}

/** The known binding names, with text values only. They're redacted with each finished line. */
function bindingsOf(bindings: LogBindings): Record<string, string> {
  return Object.fromEntries(
    BINDING_NAMES.flatMap((name) => {
      const value: unknown = bindings[name];
      return typeof value === 'string' ? [[name, value]] : [];
    }),
  );
}

function wrap(instance: pino.Logger, writeSuppressed: (includeCurrentMinute?: boolean) => void): Logger {
  const at =
    (level: LogLevel): LogMethod =>
    (event, fields = {}) => {
      const valid = EVENT_NAME.test(event) && !event.startsWith(LOGGER_EVENTS);
      const invalid = valid ? {} : { invalidEvent: redactJson(event) };
      instance[level]({ ...prepared(fields), ...invalid }, valid ? event : INVALID_EVENT);
    };
  return {
    error: at('error'),
    warn: at('warn'),
    info: at('info'),
    debug: at('debug'),
    child: (bindings) => wrap(instance.child(bindingsOf(bindings)), writeSuppressed),
    flush: () => {
      writeSuppressed(true);
      instance.flush();
    },
  };
}

export function createLogger(options: LoggerOptions): Logger {
  const now = options.now ?? Date.now;
  const guard = createVolumeGuard(options.config.log.eventCapPerMinute, now);
  const destination = options.destination ?? pino.destination({ dest: 1, sync: true });
  const iso = (ms: number): string => new Date(ms).toISOString();

  // Held-back counts go out through the root logger, so they don't carry
  // whichever request's bindings happened to log next. They're marked with a
  // private flag, not recognised by name, so a caller can't forge one past the cap.
  let writingSummary = false;
  const writeSuppressed = (includeCurrentMinute = false): void => {
    for (const { event, count, level, minuteStart } of guard.takeSuppressed(includeCurrentMinute)) {
      writingSummary = true;
      try {
        root[levelName(level)](
          {
            // Always one of our own validated event names, or the logger's.
            suppressedEvent: event,
            suppressedCount: count,
            suppressedFrom: iso(minuteStart),
            suppressedTo: iso(minuteStart + MINUTE_MS),
          },
          SUPPRESSED_EVENT,
        );
      } finally {
        writingSummary = false;
      }
    }
  };

  const root = pino(
    {
      level: options.config.log.level,
      base: { service: options.service, env: options.config.environment, release: options.config.release },
      // The message argument is the event name, so it's written as `event`.
      messageKey: 'event',
      timestamp: () => `,"time":"${iso(now())}"`,
      formatters: { level: (label) => ({ level: label }) },
      // Fields reach pino already converted and redacted. pino's own error
      // serializer, used when none is given, would re-read `err` and copy
      // fields back, so it's replaced with one that changes nothing.
      serializers: { err: (value: unknown) => value },
      hooks: {
        logMethod(args, method, level) {
          if (!writingSummary) {
            writeSuppressed();
            if (!guard.admit(eventOf(args), level)) return;
          }
          method.apply(this, args);
        },
        streamWrite: (line) => redactLine(line, now),
      },
    },
    destination,
  );
  return wrap(root, writeSuppressed);
}
