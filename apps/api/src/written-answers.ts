// SEC-WEB-06: an answer leaves only as the contract wrote it, either an object
// through the schema its route declares for its status (contract.ts), or the
// one error body (errors.ts). Each marks its reply here, and the check as the
// answer leaves refuses any other, so a string, bytes or a stream a route sent
// itself never goes out.
import type { FastifyReply } from 'fastify';

const written = new WeakSet<FastifyReply>();

/** Marks the reply's answer as one the contract wrote. */
export function markWritten(reply: FastifyReply): void {
  written.add(reply);
}

/** Whether the contract wrote the reply's answer. */
export function isWritten(reply: FastifyReply): boolean {
  return written.has(reply);
}
