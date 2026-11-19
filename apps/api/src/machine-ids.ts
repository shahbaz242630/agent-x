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
// Zitadel keeps its own default.
//
// AG10: and it must carry the header Zitadel's config file names (MACHINE_ID_HEADER), so the
// guard is ours and not the platform's alone: a neighbour inside the environment, or a door
// that one day forwards the internal Host, draws nothing without it. Zitadel's webhook signs
// nothing (its settings are a URL, a JSONPath and static headers, in the pinned image's
// defaults), so a shared value is the most it can show. That value reaches Zitadel as a file
// (`--config`, a vault secret mounted beside its master key), never its environment, and the
// API mounts the same secret (AGENTX_MACHINE_IDS_CONFIG_FILE), so the two can't drift.
// Compared in constant time, as SHA-256 digests so the length gives nothing away either.
import { createHash, timingSafeEqual } from 'node:crypto';

import { MACHINE_ID_HEADER } from '@agentx/platform/config';
import type { Logger, ProblemEvent } from '@agentx/platform/observability';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { sendErrorBody } from './errors.ts';

export const MACHINE_ID_PATH = '/internal/zitadel-machine-id';
const MACHINE_ID_HANDED_OUT = 'machine_ids.handed_out';
const MACHINE_ID_FAILED: ProblemEvent = 'machine_ids.failed';
const MACHINE_ID_REFUSED: ProblemEvent = 'machine_ids.refused';

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
 * within `mostTries`, and none at once for anything but a 16-bit whole number, which no
 * hash's low 16 bits could equal (the search would only spin to its cap). The body's
 * fixed start is hashed once, each try only its tail.
 */
export function machineNameFor(id: number, mostTries: number = MOST_TRIES): string | undefined {
  if (!Number.isInteger(id) || id < 0 || id > MOST_ID) return undefined;
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
  /** The value of the header Zitadel's config file names (AGENTX_MACHINE_IDS_CONFIG). */
  readonly key: string;
  /** The next machine ID from the database's sequence (nextMachineId). */
  readonly next: () => Promise<number | undefined>;
}

const digestOf = (value: string): Buffer => createHash('sha256').update(value).digest();

/** Whether the request carries the header once, with exactly `key`; in constant time. */
function presents(header: string | string[] | undefined, key: string): boolean {
  return typeof header === 'string' && timingSafeEqual(digestOf(header), digestOf(key));
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
    "Asked by Zitadel's processes at start, inside the environment only and with the header their config file names: without it, anywhere else, and wherever it is off, the answer is 404.",
  response: { 200: RESPONSE },
};

export function registerMachineIds(app: FastifyInstance, machineIds: MachineIds | undefined, logger: Logger): void {
  app
    .withTypeProvider<ZodTypeProvider>()
    .get(MACHINE_ID_PATH, { schema: SCHEMA, config: { access: ['public'] } }, async (request, reply) => {
      // Zitadel asks with GET alone: the HEAD Fastify adds would draw a number no one keeps.
      if (request.method !== 'GET' || hostOf(request.headers.host) !== machineIds?.host) {
        return sendErrorBody(reply, 404, 'NOT_FOUND', request.id);
      }
      const log = logger.child({ correlationId: request.id });
      if (!presents(request.headers[MACHINE_ID_HEADER.toLowerCase()], machineIds.key)) {
        // Inside the environment, but not Zitadel as its config file has it: never what was presented.
        log.warn(MACHINE_ID_REFUSED, {});
        return sendErrorBody(reply, 404, 'NOT_FOUND', request.id);
      }
      let id: number | undefined;
      let err: unknown;
      try {
        id = await machineIds.next();
      } catch (error) {
        err = error;
      }
      const machine = id === undefined ? undefined : machineNameFor(id);
      if (machine === undefined) {
        // Zitadel's process panics on this answer and its container starts again, asking again.
        log.error(MACHINE_ID_FAILED, err === undefined ? { id } : { err });
        return sendErrorBody(reply, 500, 'INTERNAL_ERROR', request.id);
      }
      log.info(MACHINE_ID_HANDED_OUT, { id });
      return reply.code(200).send({ machine });
    });
}
