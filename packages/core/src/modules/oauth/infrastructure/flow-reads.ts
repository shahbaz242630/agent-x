// A flow as opened and as read (0093, 0095, 0099, 0101): apart from flows.ts, which reads and writes the rows, and
// flow-seals.ts, which seals them, so neither imports the other.
import type { Scope } from '../../agents/index.ts';

/** A seal (flow-seals.ts): its MAC, as hex, and the agent-key pepper's version it was made with. */
export interface DecisionSeal {
  readonly mac: string;
  readonly keyVersion: number;
}

/** A browser's flow, as opened. */
export interface CodeFlow {
  readonly id: string;
  readonly clientId: string;
  readonly redirectUri: string;
  /** The client's own `state`, sent back unchanged; null for none. */
  readonly state: string | null;
  readonly codeChallenge: string;
  readonly scopesAsked: readonly Scope[];
  readonly resource: string;
  readonly browserHash: string;
  readonly createdAt: Date;
  readonly endsAt: Date;
}

/**
 * Whether a flow was decided, and how: when, the organisation and connection key an allowed one made, its decision's
 * seal (0101, flow-seals.ts), and its use.
 */
export interface FlowOutcome {
  readonly decided: 'allowed' | 'denied' | null;
  readonly decidedAt: Date | null;
  readonly orgId: string | null;
  readonly keyId: string | null;
  readonly seal: DecisionSeal | null;
  /** The seal it was opened with (0101, flow-seals.ts). */
  readonly openSeal: DecisionSeal | null;
  readonly usedAt: Date | null;
}

/** A browser's flow as read: opened, and whether it was decided and its code used. */
export interface FlowRead extends CodeFlow, FlowOutcome {
  readonly kind: 'code';
  /** Its code's SHA-256, once allowed. */
  readonly codeHash: string | null;
  readonly codeEndsAt: Date | null;
}

/** A device's flow as read (6E3c): the browser that claimed it, if one did, and when the device last polled. */
export interface DeviceFlowRead extends FlowOutcome {
  readonly kind: 'device';
  readonly id: string;
  readonly clientId: string;
  readonly scopesAsked: readonly Scope[];
  readonly resource: string;
  /** Its device code's SHA-256. */
  readonly deviceHash: string;
  /** Its user code's SHA-256. */
  readonly userCodeHash: string;
  readonly browserHash: string | null;
  /** The SHA-256 of the person who claimed it with that browser (AG8), if one did. */
  readonly personHash: string | null;
  readonly intervalSeconds: number;
  readonly polledAt: Date | null;
  readonly createdAt: Date;
  readonly endsAt: Date;
}

/** Either kind of flow, as the consent reads one by its ID. */
export type AnyFlowRead = FlowRead | DeviceFlowRead;
