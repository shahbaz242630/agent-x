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

/** What is sealed: the request's payee key, or none (a part of its own, as 0039's keys are never empty). */
const sealed = (orgId: string, requestId: string, payeeKey: string | null): Message => [
  'spend-request-payee',
  orgId.toLowerCase(),
  requestId.toLowerCase(),
  payeeKey ?? '',
];

/** The seal of the request's payee key, with the current `decision-hash` key. */
export function sealPayee(keys: KeyProvider, orgId: string, requestId: string, payeeKey: string | null): PayeeSeal {
  const { mac, keyVersion } = keys.mac('decision-hash', sealed(orgId, requestId, payeeKey));
  return { mac: Buffer.from(mac).toString('hex'), keyVersion };
}

/**
 * Whether a claim's or reservation's payee key is the one its request's
 * decision sealed: true where none was sealed (decided before E1b), false
 * where the seal can't be read.
 */
export function payeeAsSealed(
  keys: KeyProvider,
  seal: HeldSealed['payee'],
  {
    orgId,
    requestId,
    payeeKey,
  }: { readonly orgId: string; readonly requestId: string; readonly payeeKey: string | null },
): boolean {
  if (seal === 'none') return true;
  if (seal === 'unreadable') return false;
  return keys.verifyMac(
    'decision-hash',
    seal.keyVersion,
    sealed(orgId, requestId, payeeKey),
    Buffer.from(seal.mac, 'hex'),
  );
}
