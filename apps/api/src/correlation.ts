// Logging standard §2: every request has a correlation ID. It's on each of the
// request's log lines and returned in the response, so a caller can quote it.
// A caller's own ID is kept only if it's a UUID, because it goes into the log
// and back out in a header; anything else is replaced with a new one. A caller
// can still reuse an ID; from Phase 1, when requests are signed in, the log
// lines also carry the organisation.
import type { IdGenerator } from '@agentx/core/shared-kernel';
import { z } from 'zod';

export const CORRELATION_HEADER = 'x-correlation-id';

const uuid = z.uuid();

/** The nil and max UUIDs are valid, but every caller that sends one would share it. */
const SHARED_IDS: ReadonlySet<string> = new Set([
  '00000000-0000-0000-0000-000000000000',
  'ffffffff-ffff-ffff-ffff-ffffffffffff',
]);

/** The request's correlation ID: the caller's UUID in lower case, or a new UUIDv7. */
export function correlationIdFrom(header: string | string[] | undefined, ids: IdGenerator): string {
  const caller = uuid.safeParse(header);
  const id = caller.success ? caller.data.toLowerCase() : undefined;
  return id === undefined || SHARED_IDS.has(id) ? ids.next() : id;
}
