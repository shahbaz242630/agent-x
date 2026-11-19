// The MACs on people, console sessions and step-up challenges (S205 tamper pass;
// ADR-012 §2, Threat-Model row 13: operators can stop money, not grant
// authority). Both tables are global, so no row wall stands between them and
// the database's owner, who holds none of the app's keys: without a MAC, a
// session row it planted signed anyone in as anyone, a challenge it moved to
// verified, with a passkey, let the app sign an admin's change itself, and a
// person's subject moved to the owner's own login account signed the owner in
// as that person, through the login service itself.
//
// Each row carries a MAC with `session-mac` over a fixed, versioned, labelled
// message of every column that says who it is, what it proved or what it is
// for, and the key version it was made with. A row is believed only if its MAC
// holds with that version; one that doesn't is no session or no challenge, and
// raises the integrity alarm (`audit.integrity_failed`), as an audit chain's
// break does. A session's last use is left out: it moves on every request, and
// moving it only keeps alive a session whose cookie the mover still lacks.
import { KeyError, type KeyProvider, type Message } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

/** What a session or challenge MAC is made and checked with. */
export interface RowMacs {
  readonly keys: KeyProvider;
  readonly logger: Logger;
}

/** A row's MAC, as its columns keep it. */
export interface RowMac {
  readonly mac: Buffer;
  readonly mac_key_version: number;
}

/** What a person's MAC covers: who they are at the login service, for good. */
export interface UserFacts {
  readonly id: string;
  readonly issuer: string;
  readonly subject: string;
  readonly createdAt: Date;
}

/** What a session's MAC covers. */
export interface SessionFacts {
  readonly id: string;
  readonly userId: string;
  readonly cookieHash: Buffer;
  readonly idpSessionId: string | null;
  readonly authTime: Date;
  readonly amr: readonly string[];
  readonly createdAt: Date;
  readonly endsAt: Date;
}

/** A step-up's evidence, as a verified challenge's MAC covers it. */
export interface VerifiedFacts {
  readonly verifiedAt: Date;
  readonly authTime: Date;
  readonly amr: readonly string[];
  readonly idpSessionId: string | null;
  readonly idTokenHash: Buffer;
}

/** What a challenge's MAC covers: what it is for, and, once verified, what the fresh sign-in proved. */
export interface ChallengeFacts {
  readonly id: string;
  readonly sessionId: string;
  readonly userId: string;
  readonly action: string;
  readonly changeHash: Buffer;
  readonly nonce: string;
  readonly createdAt: Date;
  readonly endsAt: Date;
  readonly verified: VerifiedFacts | undefined;
}

/** Each message's label: a session's MAC can never stand for a challenge's, nor either for another key's work. */
const USER_LABEL = 'agentx/identity.user/v1';
const SESSION_LABEL = 'agentx/identity.session/v1';
const CHALLENGE_LABEL = 'agentx/identity.step-up-challenge/v1';

const time = (at: Date): string => String(at.getTime());
/** A list as its count, then each item: the parts are length-prefixed, so no two lists read alike. */
const list = (items: readonly string[]): string[] => [String(items.length), ...items];
/** An absent value apart from any present one, however the column's own check is set. */
const maybe = (value: string | null): string[] => (value === null ? ['none'] : ['some', value]);

export const userMessage = (facts: UserFacts): Message => [
  USER_LABEL,
  facts.id,
  facts.issuer,
  facts.subject,
  time(facts.createdAt),
];

export const sessionMessage = (facts: SessionFacts): Message => [
  SESSION_LABEL,
  facts.id,
  facts.userId,
  facts.cookieHash,
  ...maybe(facts.idpSessionId),
  time(facts.authTime),
  ...list(facts.amr),
  time(facts.createdAt),
  time(facts.endsAt),
];

export function challengeMessage(facts: ChallengeFacts): Message {
  const opened: Message = [
    CHALLENGE_LABEL,
    facts.id,
    facts.sessionId,
    facts.userId,
    facts.action,
    facts.changeHash,
    facts.nonce,
    time(facts.createdAt),
    time(facts.endsAt),
  ];
  const { verified } = facts;
  if (verified === undefined) return [...opened, 'opened'];
  return [
    ...opened,
    'verified',
    time(verified.verifiedAt),
    time(verified.authTime),
    ...list(verified.amr),
    ...maybe(verified.idpSessionId),
    verified.idTokenHash,
  ];
}

/** The row's MAC with the current `session-mac` key, as its columns keep it. */
export function macOf(keys: KeyProvider, message: Message): RowMac {
  const { mac, keyVersion } = keys.mac('session-mac', message);
  return { mac, mac_key_version: keyVersion };
}

/**
 * Whether the row's MAC holds for the message, with the version it names. A
 * MAC or version the owner took out or made up (no such key version) holds
 * for nothing, the same as a wrong one.
 */
export function macHolds(
  keys: KeyProvider,
  message: Message,
  row: { readonly mac: unknown; readonly mac_key_version: unknown },
): boolean {
  const { mac, mac_key_version: version } = row;
  if (!Buffer.isBuffer(mac) || typeof version !== 'number' || !Number.isSafeInteger(version)) return false;
  try {
    return keys.verifyMac('session-mac', version, message, mac);
  } catch (error) {
    if (error instanceof KeyError) return false;
    throw error;
  }
}

/**
 * The integrity alarm for a person, session or challenge whose MAC doesn't
 * hold: a row written by something without the app's key (`mac`), or a
 * challenge whose MAC holds but whose use the audit trail already records,
 * put back after its change deleted it (`already_used`), or one whose use
 * can't be told because the audit chain since it opened fails its check
 * (`chain_unverified`). Names the row and
 * its person, never the cookie, so the incident can find who was being
 * impersonated.
 */
export function rowForged(
  logger: Logger,
  check: 'user' | 'session' | 'step_up_challenge',
  row: { readonly id: string; readonly user_id: string },
  reason: 'mac' | 'already_used' | 'chain_unverified' = 'mac',
): void {
  logger.error('audit.integrity_failed', { check, reason, rowId: row.id, userId: row.user_id });
}
