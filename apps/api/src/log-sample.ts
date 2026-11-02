// Which requests' lines of success are kept when sampling is on (4D2e Stage F:
// AGENTX_LOG_SUCCESS_SAMPLE_ONE_IN, default 1, off). A request is in or out by
// its correlation ID, so its request line and its decision's timers go together.
//
// A client can send its own correlation ID, so the hash is salted with a random
// value made once a process and never written anywhere: no ID can be picked to
// be left out. One client repeating one ID does get one answer from one process;
// the activity row, never sampled, still holds each of its requests.
//
// This says only which lines may go. What is never sampled (a failure, an abort,
// a sign-in, `spend_request.decided`, and every other event: `handoff.*`, payment
// moves, `audit.*`, `security.*`, `access_log.*`) simply never asks it.
import { createHmac, randomBytes } from 'node:crypto';

export interface LogSample {
  /** Keeps 1 request in this many; 1 keeps them all. */
  readonly oneIn: number;
  keeps(correlationId: string): boolean;
}

/** Sampling off: the lines as they always were. */
export const EVERY_LINE: LogSample = Object.freeze({ oneIn: 1, keeps: () => true });

/** `salt`: a random one for each process; only a test names its own. */
export function createLogSample(oneIn: number, salt: Buffer = randomBytes(32)): LogSample {
  if (oneIn === 1) return EVERY_LINE;
  return Object.freeze({
    oneIn,
    keeps: (correlationId: string) =>
      createHmac('sha256', salt).update(correlationId).digest().readUInt32BE(0) % oneIn === 0,
  });
}

/** A decision this slow keeps its timers whatever the sample says: the slow ones are those a reader looks for. */
export const SLOW_DECISION_MS = 150;

/**
 * What a decision's line says of where its time went: all of `timers` when it was
 * slow or its request is in the sample; nothing otherwise. `sampleOf` marks those
 * kept only by the sample, each standing for that many (a slow one stands for itself).
 */
export function timersKept<Timers extends object>(
  sample: LogSample,
  correlationId: string,
  durationMs: number,
  timers: () => Timers,
): Timers | (Timers & { readonly sampleOf: number }) | Record<string, never> {
  if (durationMs >= SLOW_DECISION_MS) return timers();
  if (!sample.keeps(correlationId)) return {};
  return sample.oneIn === 1 ? timers() : { ...timers(), sampleOf: sample.oneIn };
}
