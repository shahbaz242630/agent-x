// SEC-WEB-06: an answer leaves only as the contract wrote it, byte for byte:
// the text the zod serializer wrote for an object its route declares
// (contract.ts), or the one error body's text (errors.ts). Each is recorded
// against its reply here, and the check as the answer leaves lets out only that
// text: a string, bytes or a stream a route sent itself, anything a hook put in
// its place, or a second send on the same reply, never goes out.
import type { FastifyReply } from 'fastify';

const written = new WeakMap<FastifyReply, string>();

/**
 * The reply whose object the contract has just let through to the serializer,
 * and that object. Fastify serializes straight after a route's last
 * preSerialization hook, with no wait between, so the serializer's next text is
 * this reply's, when it writes this very object: text any other call writes
 * (a hook's own serializeInput, say) is never taken for it.
 */
let writing: { readonly reply: FastifyReply; readonly data: unknown } | undefined;

/** Records text the contract wrote for the reply itself: the one error body. */
export function markWritten(reply: FastifyReply, text: string): void {
  written.set(reply, text);
}

/** Names the reply, and the object, the serializer writes next (contract.ts, a route's last preSerialization hook). */
export function aboutToWrite(reply: FastifyReply, data: unknown): void {
  writing = { reply, data };
}

/** A serializer that records what it writes against the reply `aboutToWrite` named. */
export function recordingWrites(serialize: (data: unknown) => string): (data: unknown) => string {
  return (data) => {
    const named = writing;
    // Cleared first, so a serializer that throws can't leave its reply named, holding it.
    writing = undefined;
    const text = serialize(data);
    if (named !== undefined && named.data === data) written.set(named.reply, text);
    return text;
  };
}

/** The text the contract wrote for the reply, if any. */
export function writtenText(reply: FastifyReply): string | undefined {
  return written.get(reply);
}
