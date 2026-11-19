// A flow's decision sealed (Phase 6 6F1 gate, tamper pass S205; SEC-OAUTH-13;
// 0100): oauth.flows holds no signed state, and its owner can write any row,
// so an allowed flow is believed only with a MAC the app made as the person
// decided it, with a key the database never holds.
//
// The key is the agent-key pepper, the OAuth credential family's own (it MACs
// every agent key and connection token), under a label of its own, so no MAC
// of one can stand for another's. The message is every field that says what
// the flow grants and to whom: its ID and kind; the organisation and
// connection key it was allowed with; the client; the redirect address, PKCE
// challenge and code hash a code is exchanged with, or the device code hash a
// device polls with; the scopes asked and the resource; when it ends, when it
// was decided and when its code ends. A row changed in any of them, or planted
// whole, no longer matches; a MAC copied to another flow names the first.
import type { KeyProvider, Message } from '@agentx/platform/keys';

import { pepperHeld, scopesText } from '../../agents/index.ts';
import type { AnyFlowRead } from './flows.ts';
import { PKCE_METHOD } from './pkce.ts';

/** The decision's own label, versioned: a change to the message is a new label. */
const DECISION_LABEL = 'oauth-flow-decision-v1';

/** The pepper whose MAC a decision keeps, the version beside it for rotation. */
const PEPPER = 'agent-key-pepper';

/** A decision's MAC, as hex, and the pepper's version it was made with. */
export interface DecisionSeal {
  readonly mac: string;
  readonly keyVersion: number;
}

/** What an allowed decision adds to its flow, all of it bound by the seal. */
export interface AllowedFields {
  readonly orgId: string;
  readonly keyId: string;
  /** A code flow's code's SHA-256; none for a device's, whose device code is its own. */
  readonly codeHash: string | null;
  readonly decidedAt: Date;
  readonly codeEndsAt: Date | null;
}

/** An absent field, where the other kind of flow has one: never a value, as every kept one has at least a character. */
const NONE = '';

function decisionMessage(flow: AnyFlowRead, allowed: AllowedFields): Message {
  const code = flow.kind === 'code' ? flow : undefined;
  return [
    DECISION_LABEL,
    flow.id.toLowerCase(),
    flow.kind,
    allowed.orgId.toLowerCase(),
    allowed.keyId.toLowerCase(),
    flow.clientId,
    code?.redirectUri ?? NONE,
    code === undefined ? NONE : `${PKCE_METHOD}:${code.codeChallenge}`,
    allowed.codeHash ?? NONE,
    flow.kind === 'device' ? flow.deviceHash : NONE,
    scopesText(flow.scopesAsked),
    flow.resource,
    flow.endsAt.toISOString(),
    allowed.decidedAt.toISOString(),
    allowed.codeEndsAt?.toISOString() ?? NONE,
  ];
}

/** The seal of the flow, as read, allowed with these fields: made with the pepper's current version. */
export function decisionSealed(keys: KeyProvider, flow: AnyFlowRead, allowed: AllowedFields): DecisionSeal {
  const { mac, keyVersion } = keys.mac(PEPPER, decisionMessage(flow, allowed));
  return { mac: mac.toString('hex'), keyVersion };
}

/**
 * Whether an allowed flow, as read, is the one the app decided: `sound`; `unsealed`, decided before seals were kept
 * (0100) or its seal taken out; `key_not_held`, sealed with a pepper version this process no longer holds; or
 * `tampered`, its seal not its own. Only `sound` may be exchanged.
 */
export type DecisionJudged = 'sound' | 'unsealed' | 'key_not_held' | 'tampered';

export function decisionJudged(keys: KeyProvider, flow: AnyFlowRead): DecisionJudged {
  const { seal, orgId, keyId, decidedAt } = flow;
  if (flow.decided !== 'allowed' || orgId === null || keyId === null || decidedAt === null) return 'tampered';
  if (seal === null) return 'unsealed';
  if (!pepperHeld(keys, seal.keyVersion)) return 'key_not_held';
  const allowed: AllowedFields =
    flow.kind === 'code'
      ? { orgId, keyId, codeHash: flow.codeHash, decidedAt, codeEndsAt: flow.codeEndsAt }
      : { orgId, keyId, codeHash: null, decidedAt, codeEndsAt: null };
  return keys.verifyMac(PEPPER, seal.keyVersion, decisionMessage(flow, allowed), Buffer.from(seal.mac, 'hex'))
    ? 'sound'
    : 'tampered';
}
