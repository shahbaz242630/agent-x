// The value shapes settings are checked against. Each message says what a
// value must look like, never what it was.
import { z } from 'zod';

export const text = z
  .string({ error: 'is required' })
  .min(1, { error: 'is empty: give it a value, or remove it to use the default', abort: true });

export function wholeNumber(limits: { min: number; max: number; unit?: string; minimumReason?: string }) {
  const unit = limits.unit === undefined ? '' : ` ${limits.unit}`;
  const reason = limits.minimumReason === undefined ? '' : ` (${limits.minimumReason})`;
  return text
    .regex(/^[0-9]+$/, { error: 'must be a whole number, written in digits only' })
    .transform(Number)
    .pipe(
      // A digits-only value that isn't a finite number overflowed, so it is too big.
      z
        .number({ error: `must be at most ${limits.max}${unit}` })
        .min(limits.min, { error: `must be at least ${limits.min}${unit}${reason}` })
        .max(limits.max, { error: `must be at most ${limits.max}${unit}` }),
    );
}

/** A DNS name in lower case: labels of letters, digits and inner dashes, joined by dots. */
const HOST_NAME = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;

/** Where the database is: a service name (`db`), a DNS name, or an IP address. */
export const databaseHost = text.pipe(
  z.union([z.string().regex(HOST_NAME), z.ipv4(), z.ipv6()], {
    error: 'must be a host name in lower case (letters, digits, dots and dashes) or an IP address',
  }),
);

/** A Postgres name that needs no quoting: a database or a role. */
export const identifier = text.regex(/^[a-z_][a-z0-9_]{0,62}$/, {
  error:
    'must be a plain Postgres name: lower-case letters, digits and underscores, up to 63, not starting with a digit',
});

/** How the database connection is protected: verify-full everywhere real; disable only for a local stack (ADR-002). */
const DATABASE_TLS_MODES = ['verify-full', 'disable'] as const;
export type DatabaseTlsMode = (typeof DATABASE_TLS_MODES)[number];

export const tlsMode = text.pipe(
  z.enum(DATABASE_TLS_MODES, { error: `must be one of: ${DATABASE_TLS_MODES.join(', ')}` }),
);
