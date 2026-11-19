// A flow sealed as it opens and as it is decided (Phase 6 6F1 gate, tamper
// pass S205; SEC-OAUTH-13; 0101): oauth.flows holds no signed state, and its
// owner can write any row, so a flow is believed only with the MACs the app
// made of it, with a key the database never holds.
//
// - Opened (`oauth-flow-open-v2`): what the client asked for, as it asked: the
//   flow's ID and kind, the client, its redirect address, `state` and PKCE challenge,
//   or the device code hash its device polls with and the user code hash its
//   person types, the scopes asked, the
//   resource and when it ends. Checked wherever a pending flow is read for a
//   person's consent (the request shown, the device's claim, the ask, the
//   confirm), so what a person allows is what the client sent.
// - Decided (`oauth-flow-decision-v2`): the same, and the organisation and
//   connection key it was allowed with, its code's hash, when it was decided
//   and when its code ends. Checked before any token is issued.
//
// The key is the agent-key pepper, the OAuth credential family's own (it MACs
// every agent key and connection token), under labels of their own, so no MAC
// of one can stand for another's. A row changed in any field, or planted
// whole, no longer matches; a MAC copied to another flow names the first.
//
// v2 (S206, R-15) added the client's `state`, which goes back to it with its
// code: v1 left the owner free to rewrite it. A v1 seal is never believed, or
// that rewrite would stay open; one that checks is a flow opened by the release
// before this one, refused without the alarm (flows live minutes).
import type { KeyProvider, Message } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { pepperHeld, type Scope, scopesText } from '../../agents/index.ts';
import type { AnyFlowRead, DecisionSeal } from './flow-reads.ts';
import { PKCE_METHOD } from './pkce.ts';

/** The labels, versioned: a change to a message is a new label. */
const OPEN_LABEL = 'oauth-flow-open-v2';
const DECISION_LABEL = 'oauth-flow-decision-v2';
/** The labels before `state` was sealed: checked only to tell a flow the release before opened from a forged one. */
const OPEN_LABEL_V1 = 'oauth-flow-open-v1';
const DECISION_LABEL_V1 = 'oauth-flow-decision-v1';

/** The pepper whose MAC a seal is, the version beside it for rotation. */
const PEPPER = 'agent-key-pepper';

export type { DecisionSeal } from './flow-reads.ts';

/** What a flow is as opened, all of it bound by its open seal. */
export interface OpenedFields {
  readonly id: string;
  readonly kind: 'code' | 'device';
  readonly clientId: string;
  /** A code flow's; none for a device's. */
  readonly redirectUri: string | null;
  /** A code flow's client's `state`, sent back with its code; none for a device's, or a code flow's without one. */
  readonly state: string | null;
  readonly codeChallenge: string | null;
  /** A device flow's device code's SHA-256; none for a code flow's. */
  readonly deviceHash: string | null;
  /** A device flow's user code's SHA-256, which its person types to claim it; none for a code flow's. */
  readonly userCodeHash: string | null;
  readonly scopesAsked: readonly Scope[];
  readonly resource: string;
  readonly endsAt: Date;
}

/** What an allowed decision adds to its flow, all of it bound by the decision's seal. */
export interface AllowedFields {
  readonly orgId: string;
  readonly keyId: string;
  /** A code flow's code's SHA-256; none for a device's, whose device code is its own. */
  readonly codeHash: string | null;
  readonly decidedAt: Date;
  readonly codeEndsAt: Date | null;
}

/** An absent field, where the other kind of flow has one: never a value, as every kept one has at least a character (0093 holds `state` to 1-512). */
const NONE = '';

/** A flow as read, as the fields it was opened with. */
export const openedFieldsOf = (flow: AnyFlowRead): OpenedFields => ({
  id: flow.id,
  kind: flow.kind,
  clientId: flow.clientId,
  redirectUri: flow.kind === 'code' ? flow.redirectUri : null,
  state: flow.kind === 'code' ? flow.state : null,
  codeChallenge: flow.kind === 'code' ? flow.codeChallenge : null,
  deviceHash: flow.kind === 'device' ? flow.deviceHash : null,
  userCodeHash: flow.kind === 'device' ? flow.userCodeHash : null,
  scopesAsked: flow.scopesAsked,
  resource: flow.resource,
  endsAt: flow.endsAt,
});

/** The parts both v1 seals took of what the flow was opened with, after the label: all but `state`. */
const openedPartsV1 = (opened: OpenedFields): string[] => [
  opened.id.toLowerCase(),
  opened.kind,
  opened.clientId,
  opened.redirectUri ?? NONE,
  opened.codeChallenge === null ? NONE : `${PKCE_METHOD}:${opened.codeChallenge}`,
  opened.deviceHash ?? NONE,
  opened.userCodeHash ?? NONE,
  scopesText(opened.scopesAsked),
  opened.resource,
  opened.endsAt.toISOString(),
];

/** The parts both seals take of what the flow was opened with, after the label. */
const openedParts = (opened: OpenedFields): string[] => [...openedPartsV1(opened), opened.state ?? NONE];

/** A seal's message two ways: as sealed now, and as the release before sealed it. */
interface Versions {
  readonly now: () => Message;
  readonly before: () => Message;
}

const decisionMessage = (label: string, opened: readonly string[], allowed: AllowedFields): Message => {
  return [
    label,
    ...opened,
    allowed.orgId.toLowerCase(),
    allowed.keyId.toLowerCase(),
    allowed.codeHash ?? NONE,
    allowed.decidedAt.toISOString(),
    allowed.codeEndsAt?.toISOString() ?? NONE,
  ];
};

const sealOf = (keys: KeyProvider, message: Message): DecisionSeal => {
  const { mac, keyVersion } = keys.mac(PEPPER, message);
  return { mac: mac.toString('hex'), keyVersion };
};

/** The seal of a flow as it opens: made with the pepper's current version. */
export const openSealed = (keys: KeyProvider, opened: OpenedFields): DecisionSeal =>
  sealOf(keys, [OPEN_LABEL, ...openedParts(opened)]);

/** The seal of the flow, as read, allowed with these fields: made with the pepper's current version. */
export const decisionSealed = (keys: KeyProvider, flow: AnyFlowRead, allowed: AllowedFields): DecisionSeal =>
  sealOf(keys, decisionMessage(DECISION_LABEL, openedParts(openedFieldsOf(flow)), allowed));

/**
 * Whether a flow, as read, is as the app sealed it: `sound`; `unsealed`, sealed before seals were kept (0101), by the
 * release before while this one rolls out, or its seal taken out; `superseded`, sealed v1 by the release before this
 * one (S206), whose seal doesn't bind its `state`; `key_not_held`, sealed with a pepper version this process no longer
 * holds; or `tampered`, its seal not its own. Only `sound` is believed.
 */
export type DecisionJudged = 'sound' | 'unsealed' | 'superseded' | 'key_not_held' | 'tampered';

function judged(keys: KeyProvider, seal: DecisionSeal | null, messages: Versions): DecisionJudged {
  if (seal === null) return 'unsealed';
  if (!pepperHeld(keys, seal.keyVersion)) return 'key_not_held';
  const mac = Buffer.from(seal.mac, 'hex');
  if (keys.verifyMac(PEPPER, seal.keyVersion, messages.now(), mac)) return 'sound';
  return keys.verifyMac(PEPPER, seal.keyVersion, messages.before(), mac) ? 'superseded' : 'tampered';
}

/** Whether the flow, as read, is the one its client opened. */
export function openJudged(keys: KeyProvider, flow: AnyFlowRead): DecisionJudged {
  const opened = openedFieldsOf(flow);
  return judged(keys, flow.openSeal, {
    now: () => [OPEN_LABEL, ...openedParts(opened)],
    before: () => [OPEN_LABEL_V1, ...openedPartsV1(opened)],
  });
}

/** Whether an allowed flow, as read, is the one the app decided. */
export function decisionJudged(keys: KeyProvider, flow: AnyFlowRead): DecisionJudged {
  const { orgId, keyId, decidedAt } = flow;
  if (flow.decided !== 'allowed' || orgId === null || keyId === null || decidedAt === null) return 'tampered';
  const allowed: AllowedFields =
    flow.kind === 'code'
      ? { orgId, keyId, codeHash: flow.codeHash, decidedAt, codeEndsAt: flow.codeEndsAt }
      : { orgId, keyId, codeHash: null, decidedAt, codeEndsAt: null };
  const opened = openedFieldsOf(flow);
  return judged(keys, flow.seal, {
    now: () => decisionMessage(DECISION_LABEL, openedParts(opened), allowed),
    before: () => decisionMessage(DECISION_LABEL_V1, openedPartsV1(opened), allowed),
  });
}

/**
 * Whether a pending flow may be shown, claimed or decided (S205): only one its client opened, as sealed. Anything else
 * is answered as no flow at all, and logged: one not its own is the integrity alarm (a flow comes before any
 * organisation, so no organisation is held for it: none is decided); a pepper version no longer held, ours to fix; one
 * with no seal, or sealed v1 (S206), opened by the release before while this one rolls out, a warning.
 */
export function pendingFlowSound(keys: KeyProvider, logger: Logger, flow: AnyFlowRead): boolean {
  const open = openJudged(keys, flow);
  if (open === 'tampered') {
    logger.error('audit.integrity_failed', {
      chain: 'oauth',
      check: 'oauth_flow',
      reason: 'open_seal',
      objectId: flow.id,
    });
  } else if (open === 'unsealed') logger.warn('oauth.flow_unsealed', { flowId: flow.id });
  else if (open === 'superseded') logger.warn('oauth.flow_seal_superseded', { flowId: flow.id });
  else if (open === 'key_not_held') {
    logger.error('oauth.seal_key_not_held', { flowId: flow.id, keyVersion: flow.openSeal?.keyVersion });
  }
  return open === 'sound';
}
