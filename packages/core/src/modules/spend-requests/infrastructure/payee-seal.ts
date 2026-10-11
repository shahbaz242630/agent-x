// The payee seal (Phase 2 E1b; ADR-012 §2; SEC-DB-09): a keyed hash of the
// payee key a decision's claim and reservation were made on, sealed in its
// `spend_request.decided` event, so the holdings check can tell a key nulled
// or swapped past the app. The key itself never goes into the log: it is our
// keyed fingerprint of a bank account or the partner's own identity for the
// payee (ADR-014 §3). Keyed with `decision-hash`, apart from `payee-index`,
// whose versions are kept for good as a decision's evidence is: the message
// is labelled as a payee seal, so it can never be read as a decision's hash.
import type { KeyProvider, Message } from '@agentx/platform/keys';

import type { HeldSealed, PayeeSeal } from '../domain/holdings.ts';

/** The request whose payee key is sealed, and the key: null where its supplier has none. */
export interface SealedFor {
  readonly orgId: string;
  readonly requestId: string;
  readonly payeeKey: string | null;
}

/**
 * What is sealed. No key and a key are told apart by shape, not by a value a
 * key could take: a reservation's `payee_key` has no check against '' (0040,
 * review), so '' must never pass as none.
 */
const payeeSealMessage = ({ orgId, requestId, payeeKey }: SealedFor): Message => [
  'spend-request-payee',
  orgId.toLowerCase(),
  requestId.toLowerCase(),
  ...(payeeKey === null ? ['none'] : ['key', payeeKey]),
];

/** The seal of the request's payee key, with the current `decision-hash` key. */
export function sealPayee(keys: KeyProvider, sealedFor: SealedFor): PayeeSeal {
  const { mac, keyVersion } = keys.mac('decision-hash', payeeSealMessage(sealedFor));
  return { mac: Buffer.from(mac).toString('hex'), keyVersion };
}

/**
 * Whether a claim's or reservation's payee key is the one its request's
 * decision sealed: true where none was sealed (decided before E1b), false
 * where the seal can't be read.
 */
export function payeeAsSealed(keys: KeyProvider, seal: HeldSealed['payee'], sealedFor: SealedFor): boolean {
  if (seal === 'none') return true;
  if (seal === 'unreadable') return false;
  return keys.verifyMac('decision-hash', seal.keyVersion, payeeSealMessage(sealedFor), Buffer.from(seal.mac, 'hex'));
}
