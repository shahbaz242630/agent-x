// SA3e: Zitadel's machine IDs, handed out in turn. `GET /internal/zitadel-machine-id`.
//
// Zitadel (v4.17.3, internal/id/sonyflake.go) mints each ID from the time, a counter and
// a 16-bit machine ID of its process. Two copies holding the same machine ID can mint the
// same ID in the same 10 ms, which may merge two of its records. Its hostname mode hashes
// each copy's hostname into 16 bits, so two copies can collide by chance; production runs
// 2 to 4 (SA3a). Its webhook mode instead asks a URL at start (a plain GET, no timeout,
// any 400-599 an error), hashes the answer's body bytes with FNV-1 32 (Go's
// hash/fnv New32), and keeps the low 16 bits. With nothing else to try it panics,
// so the container restarts and asks again.
//
// So this answers each ask with the next number of a database sequence (0090), written as
// a body whose FNV-1 32 hash has exactly that number in its low 16 bits: the name in it,
// `agentx-<id>-<k>`, has the first k that makes it so (one in 65,536 does, so about 65,000
// tries, a few milliseconds). Two live copies share a machine ID only after 65,536 starts.
// The body is the JSON the contract writes, byte for byte, and Zitadel is given no JSONPath:
// with one, it would hash its re-serialised match (`["..."]`) instead of the body.
//
// Internal only. Zitadel calls the API's internal address inside the environment; the
// public app door sends every path on the app host to the API (apps.bicep), so the path
// alone could be asked from the internet. Each answer is refused, as the same 404 as an
// address that doesn't exist, unless the request's Host is the API's internal host, which
// AGENTX_MACHINE_IDS_HOST names: a door carries its own host name (the app or auth host),
// and Container Apps refuses requests from outside the environment to an app's internal
// name. The raw Host header is read, never X-Forwarded-Host, which a client writes. Off
// (404 to all) where the setting is unset: development, test and the compose stack, whose
// Zitadel keeps its own default. A neighbour inside the environment could still draw
// numbers and move the turn on; no secret header guards against that, as the only
// neighbours are our own apps and a vault-held secret in Zitadel's environment would add
// a secret where SECRETS_IN_ENVIRONMENT keeps the fewest.
import type { Logger, ProblemEvent } from '@agentx/platform/observability';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { sendErrorBody } from './errors.ts';

export const MACHINE_ID_PATH = '/internal/zitadel-machine-id';
const MACHINE_ID_HANDED_OUT = 'machine_ids.handed_out';
const MACHINE_ID_FAILED: ProblemEvent = 'machine_ids.failed';

/** FNV-1 32's starting value and prime (FNV spec; Go's hash/fnv New32). */
const FNV_OFFSET_BASIS = 0x81_1c_9d_c5;
const FNV_PRIME = 0x01_00_01_93;

/** The top of a 16-bit machine ID. */
const MOST_ID = 0xff_ff;

/**
 * How many names are tried for one ID before giving up. One in 65,536 fits, so 2^22
 * tries miss only about once in e^64 asks; the cap only keeps a bug from spinning forever.
 */
export const MOST_TRIES = 2 ** 22;

/**
 * FNV-1 32 (multiply, then XOR each byte) of ASCII text, from `from` (the offset basis,
 * or the hash of the text before it). Only ever given ASCII: one code unit, one byte.
 */
export function fnv1Of(text: string, from: number = FNV_OFFSET_BASIS): number {
  let hash = from;
  for (let index = 0; index < text.length; index += 1) {
    hash = (Math.imul(hash, FNV_PRIME) ^ text.charCodeAt(index)) >>> 0;
  }
  return hash;
}

/** The answer's body for a name, exactly as the contract writes it (and as JSON.stringify does). */
export const bodyOf = (machine: string): string => JSON.stringify({ machine });

/**
 * The name whose answer's body hashes, in Zitadel's way, to the machine ID `id`; none
 * within `mostTries`. The body's fixed start is hashed once, each try only its tail.
 */
export function machineNameFor(id: number, mostTries: number = MOST_TRIES): string | undefined {
  const name = (tries: number): string => `agentx-${String(id)}-${String(tries)}`;
  // `{"machine":"agentx-<id>-`: the body up to the try's number.
  const start = fnv1Of(bodyOf(name(0)).slice(0, -'0"}'.length));
  for (let tries = 0; tries < mostTries; tries += 1) {
    if ((fnv1Of(`${String(tries)}"}`, start) & MOST_ID) === id) return name(tries);
  }
  return undefined;
}

/** Where machine IDs come from, and the one host they are handed out on. */
export interface MachineIds {
  /** The API's internal host name (AGENTX_MACHINE_IDS_HOST), lowercase, no port. */
  readonly host: string;
  /** The next machine ID from the database's sequence (nextMachineId). */
  readonly next: () => Promise<number | undefined>;
}

/** The request's own Host, lowercase, without a port. */
const hostOf = (header: string | undefined): string => (header ?? '').toLowerCase().replace(/:\d+$/, '');

const RESPONSE = z
  .object({
    machine: z.string().describe("A name whose body hashes, in Zitadel's webhook way, to this process's machine ID."),
  })
  .describe('One Zitadel machine ID, as its webhook reads it.');

const SCHEMA = {
  summary: "A Zitadel process's machine ID",
  description:
    "Asked by Zitadel's processes at start, inside the environment only: anywhere else, and wherever it is off, the answer is 404.",
  response: { 200: RESPONSE },
};

export function registerMachineIds(app: FastifyInstance, machineIds: MachineIds | undefined, logger: Logger): void {
  app
    .withTypeProvider<ZodTypeProvider>()
    .get(MACHINE_ID_PATH, { schema: SCHEMA, config: { access: ['public'] } }, async (request, reply) => {
      if (hostOf(request.headers.host) !== machineIds?.host) {
        return sendErrorBody(reply, 404, 'NOT_FOUND', request.id);
      }
      const log = logger.child({ correlationId: request.id });
      const id = await machineIds.next();
      const machine =
        id !== undefined && Number.isInteger(id) && id >= 0 && id <= MOST_ID ? machineNameFor(id) : undefined;
      if (machine === undefined) {
        // Zitadel's process panics on this answer and its container starts again, asking again.
        log.error(MACHINE_ID_FAILED, { id });
        return sendErrorBody(reply, 500, 'INTERNAL_ERROR', request.id);
      }
      log.info(MACHINE_ID_HANDED_OUT, { id });
      return reply.code(200).send({ machine });
    });
}
