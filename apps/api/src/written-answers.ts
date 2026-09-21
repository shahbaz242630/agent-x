// SEC-WEB-06: an answer leaves only as the contract wrote it, byte for byte:
// the text the zod serializer wrote for an object its route declares
// (contract.ts), or the one error body's text (errors.ts). Each is recorded
// against its reply here, and the check as the answer leaves lets out only that
// text: a string, bytes or a stream a route sent itself, anything a hook put in
// its place, or a second send on the same reply, never goes out.
import type { FastifyReply } from 'fastify';

const written = new WeakMap<FastifyReply, string>();

/**
 * The reply whose object the contract has just let through to the serializer.
 * Fastify serializes straight after the last preSerialization hook, with no
 * wait between, so the serializer's next text is this reply's.
 */
let writing: FastifyReply | undefined;

/** Records text the contract wrote for the reply itself: the one error body. */
export function markWritten(reply: FastifyReply, text: string): void {
  written.set(reply, text);
}

/** Names the reply whose object the serializer writes next (contract.ts, its last preSerialization hook). */
export function aboutToWrite(reply: FastifyReply): void {
  writing = reply;
}

/** A serializer that records what it writes against the reply `aboutToWrite` named. */
export function recordingWrites(serialize: (data: unknown) => string): (data: unknown) => string {
  return (data) => {
    const reply = writing;
    // Cleared first, so a serializer that throws can't leave its reply named for another's text.
    writing = undefined;
    const text = serialize(data);
    if (reply !== undefined) written.set(reply, text);
    return text;
  };
}

/** Whether the contract wrote anything for the reply (Fastify's own HEAD hook may since have emptied it). */
export function hasWritten(reply: FastifyReply): boolean {
  return written.has(reply);
}

/** Whether the payload is, exactly, what the contract wrote for the reply. */
export function isWritten(reply: FastifyReply, payload: unknown): boolean {
  return typeof payload === 'string' && written.get(reply) === payload;
}
