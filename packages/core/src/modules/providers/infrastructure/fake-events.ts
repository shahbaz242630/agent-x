// The fake partner's messages (Phase 4 E1b; rail map §1.8; ADR-007 §12;
// SEC-PTR-01, -03, -06): shaped on the rail's status alerts, signed with the
// fake's own key (0063, made the first time it is asked for, so none sits in
// the code), so tests and staging can send real-looking messages through the
// same front door the real partner's will use.
//
// - A message's body is the rail's shape: `Meta` (its `EventType`, its
//   `EventDateTime`, its `ConsentId`) and, only sometimes, `Data` naming the
//   payment, here by our instruction ID (the fake echoes our idempotency key).
//   No event ID: the rail's carry none, so the inbox keys it by its body's SHA-256.
// - The signature is HMAC-SHA-256 over the time it was sent and the raw body,
//   `t=<ISO time>,v1=<hex>` in `x-fake-signature`. It is checked before the
//   body is read; a time more than 5 minutes from now either way is stale.
// The real partner's signature (a signed JWT in an encrypted JWE, rail map §5)
// replaces this in Phase 5, in its own adapter; the flow behind it stays.
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

import { UUID } from '../../../shared-kernel/index.ts';
import type { EventCheck, EventHeaders, EventReference } from '../domain/events.ts';

/** The header the fake signs its messages in. */
export const FAKE_SIGNATURE_HEADER = 'x-fake-signature';

/** How far a signed time may be from now, either way (SEC-PTR-03). */
export const FAKE_EVENT_WINDOW_MS = 5 * 60_000;

/** A message the fake partner sends: what happened, the consent, and the payment when it names one. */
export interface FakeMessage {
  readonly eventType: string;
  readonly consentId: string;
  /** Our instruction ID: left out, the message names the consent alone (rail map §1.8). */
  readonly instructionId?: string;
}

/** A message as it goes over the wire: its body's bytes and the headers that come with it. */
export interface SignedMessage {
  readonly body: Buffer;
  readonly headers: Readonly<Record<string, string>>;
}

const SIGNATURE = /^t=([^,]{1,64}),v1=([0-9a-f]{64})$/;

const macOf = (key: Buffer, sentAt: string, body: Uint8Array): Buffer =>
  createHmac('sha256', key).update(`${sentAt}.`).update(body).digest();

/** Any body, signed by the fake partner at `now`: a test's own shapes, malformed ones among them. */
export function signFakeBody(key: Buffer, body: Buffer, now: Date): SignedMessage {
  const sentAt = now.toISOString();
  return {
    body,
    headers: {
      'content-type': 'application/json',
      [FAKE_SIGNATURE_HEADER]: `t=${sentAt},v1=${macOf(key, sentAt, body).toString('hex')}`,
    },
  };
}

/** The message, as the fake partner signs and sends it at `now`. */
export function signFakeMessage(key: Buffer, message: FakeMessage, now: Date): SignedMessage {
  const body = JSON.stringify({
    Meta: { EventType: message.eventType, EventDateTime: now.toISOString(), ConsentId: message.consentId },
    ...(message.instructionId !== undefined && { Data: { InstructionId: message.instructionId } }),
  });
  return signFakeBody(key, Buffer.from(body, 'utf8'), now);
}

const isText = (value: unknown, most: number): value is string =>
  typeof value === 'string' && value.length >= 1 && value.length <= most;

/** What a signed body names, or undefined where it isn't a message the fake sends. */
function readMessage(body: Uint8Array): { eventType: string; reference: EventReference } | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(body).toString('utf8'));
  } catch {
    return undefined;
  }
  if (typeof parsed !== 'object' || parsed === null) return undefined;
  const { Meta: meta, Data: data } = parsed as { Meta?: unknown; Data?: unknown };
  if (typeof meta !== 'object' || meta === null) return undefined;
  const { EventType: eventType, ConsentId: consentId } = meta as { EventType?: unknown; ConsentId?: unknown };
  if (!isText(eventType, 100) || !isText(consentId, 200)) return undefined;
  if (data === undefined) return { eventType, reference: { kind: 'consent', consentId } };
  const instructionId =
    typeof data === 'object' && data !== null ? (data as { InstructionId?: unknown }).InstructionId : undefined;
  if (typeof instructionId !== 'string' || !UUID.test(instructionId)) return undefined;
  return { eventType, reference: { kind: 'instruction', instructionId: instructionId.toLowerCase() } };
}

/**
 * The message checked as the fake partner signed it: its signature over the
 * raw body first, then its signed time, then its body; verified and
 * normalised, or refused and why.
 */
export function verifyFakeMessage(key: Buffer, body: Uint8Array, headers: EventHeaders, now: Date): EventCheck {
  const header = headers[FAKE_SIGNATURE_HEADER];
  const signed = typeof header === 'string' ? SIGNATURE.exec(header) : null;
  if (signed === null) return { kind: 'refused', reason: 'signature' };
  const [, sentAt = '', given = ''] = signed;
  const expected = macOf(key, sentAt, body);
  if (!timingSafeEqual(Buffer.from(given, 'hex'), expected)) return { kind: 'refused', reason: 'signature' };
  const at = new Date(sentAt).getTime();
  if (Number.isNaN(at) || Math.abs(now.getTime() - at) > FAKE_EVENT_WINDOW_MS)
    return { kind: 'refused', reason: 'stale' };
  const message = readMessage(body);
  if (message === undefined) return { kind: 'refused', reason: 'malformed' };
  return {
    kind: 'verified',
    event: {
      partner: 'fake',
      dedupeKey: createHash('sha256').update(body).digest('hex'),
      eventType: message.eventType,
      reference: message.reference,
    },
  };
}
