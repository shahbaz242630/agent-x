// Linking the business's own bank account through the payment partner (PRD
// §2.3, ADR-014 §4, BR-01, BR-02, SEC-PTR-08; Phase 1 D2-3b). Composed here, in
// the API, as ADR-004 §7 has it: the partner is the providers module's
// adapter, the links and sources the funding-sources module's, the member
// identity's.
//
// 1. `start` (`funding-sources.link.start`), an admin: our link ID made, the
//    partner asked for a session under it (the partner's idempotency key), and
//    then, in one transaction, the key claimed, the member read again, the
//    organisation's lock for starting links, the day's budget
//    (LINK_STARTS_SPENT), and the link added. The partner is never called
//    inside the transaction: a network call must not hold its locks, and the
//    fake partner's own records are another transaction. A retry of the same
//    write answers the link the first one added; the session the retry asked
//    for goes unused and runs out at the partner, as an unapproved link does.
// 2. The business approves at its bank, through the partner's page. Nothing
//    that comes back through the browser is believed.
// 3. `confirm` (`funding-sources.link.confirm`), an admin: the link must be
//    the organisation's; the partner is asked, server to server, how the link
//    it started for this organisation ended; then, in one transaction, the key
//    claimed, the member read again, the link locked, and: still waiting, left
//    open (202); linked, the source added from the partner's answer and the
//    link settled with it; turned down, run out or unknown to the partner,
//    the link settled so. A link settled already answers as it stands.
//
// A source already gone at the partner by the time it is confirmed is never
// added: the link is settled `rejected`, and linking again makes a new one.
//
// Lock order (ADR-006 §6): the idempotency key, the link-start lock, the
// member's membership (2a), the link and its source (5), the chain head last.
import {
  addLink,
  addSource,
  type FundingSourcesTables,
  linkOf,
  type LinkRecord,
  linksStartedSince,
  MOST_LINKS_STARTED_A_DAY,
  oneLinkStartAtATime,
  settleLink,
  sourceOf,
  type SourceRecord,
} from '@agentx/core/modules/funding-sources';
import { type AuditTables, type SignedStates, withSignedStates } from '@agentx/core/modules/audit';
import type { DirectoryTables } from '@agentx/core/modules/directory';
import { type IdentityTables, membershipOf, type Role } from '@agentx/core/modules/identity';
import { type FinancialRailAdapter, type LinkOutcome, RailUnavailable } from '@agentx/core/modules/providers';
import type { Clock, IdGenerator, ReasonCode } from '@agentx/core/shared-kernel';
import {
  createIdempotentWrites,
  type Database,
  type DatabaseTransaction,
  type IdempotentRequest,
  limitStatements,
} from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

/** Starting a link. */
export const LINK_START_OPERATION = 'funding-sources.link.start';
/** Confirming it with the partner, once the business has been at its bank. */
export const LINK_CONFIRM_OPERATION = 'funding-sources.link.confirm';

/** The roles that may link the organisation's bank account: its admins, who hold its authority (PRD §7.3). */
export const LINKING_ROLES = ['admin'] as const;

/** The tables linking works on. */
export type LinkingTables = IdentityTables & FundingSourcesTables & DirectoryTables & AuditTables;
type LinkingTx = DatabaseTransaction<LinkingTables>;

/** Who is linking: a signed-in member, in the organisation the access hook verified. */
export interface LinkingMember {
  readonly orgId: string;
  readonly userId: string;
}

/** A refusal, as the use case answers it. */
interface Refused {
  readonly outcome: 'refused';
  readonly status: number;
  readonly code: ReasonCode;
}

/** A link, and the source it made once linked. */
interface LinkWithSource {
  readonly link: LinkRecord;
  readonly source: SourceRecord | null;
}

export type LinkStartWrite =
  | { readonly outcome: 'started'; readonly link: LinkRecord; readonly authoriseUrl: string }
  | { readonly outcome: 'conflict' }
  | { readonly outcome: 'busy' }
  | Refused;

export type LinkConfirmWrite =
  | ({ readonly outcome: 'confirmed' } & LinkWithSource)
  | { readonly outcome: 'conflict' }
  | { readonly outcome: 'busy' }
  | Refused;

export interface FundingSourceLinks {
  start(member: LinkingMember, idempotent: IdempotentRequest, correlationId: string): Promise<LinkStartWrite>;
  confirm(
    member: LinkingMember,
    idempotent: IdempotentRequest,
    linkId: string,
    correlationId: string,
  ): Promise<LinkConfirmWrite>;
}

const DAY_MS = 86_400_000;

/** A refusal thrown inside a write, so everything it did rolls back. */
class LinkRefused extends Error {
  readonly status: number;
  readonly code: ReasonCode;

  constructor(status: number, code: ReasonCode) {
    super(`linking refused: ${code}`);
    this.name = 'LinkRefused';
    this.status = status;
    this.code = code;
  }
}

const refused = (status: number, code: ReasonCode): Refused => ({ outcome: 'refused', status, code });
const PARTNER_UNAVAILABLE = refused(503, 'PARTNER_UNAVAILABLE');

/** The partner's answer, or `unavailable` when it didn't give one. */
async function asked<T>(call: () => Promise<T>): Promise<T | 'unavailable'> {
  try {
    return await call();
  } catch (error) {
    if (error instanceof RailUnavailable) return 'unavailable';
    throw error;
  }
}

export function createFundingSourceLinks({
  database,
  keys,
  ids,
  clock,
  rail,
  partner,
  logger,
}: {
  readonly database: Database<LinkingTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  /** The partner, or undefined where none is set up (config.partner): then every call answers PARTNER_UNAVAILABLE. */
  readonly rail: FinancialRailAdapter | undefined;
  /** The partner's name, as a link and a source keep it. */
  readonly partner: string;
  readonly logger: Logger;
}): FundingSourceLinks {
  const inOrganisation = <T>(
    orgId: string,
    correlationId: string,
    work: (tx: LinkingTx, states: SignedStates) => Promise<T>,
  ): Promise<T> =>
    withSignedStates(database, orgId, { keys, ids, logger: logger.child({ correlationId }) }, async (tx, states) => {
      await limitStatements(tx);
      return work(tx, states);
    });

  /** The write with its key claimed first; a refusal is answered, with everything it did rolled back. */
  const write = async (
    member: LinkingMember,
    idempotent: IdempotentRequest,
    correlationId: string,
    work: (tx: LinkingTx, states: SignedStates) => Promise<{ status: number; resourceId: string }>,
  ) => {
    const idempotency = createIdempotentWrites({ keys, logger: logger.child({ correlationId }) });
    try {
      return await inOrganisation(member.orgId, correlationId, (tx, states) =>
        idempotency.run(tx, idempotent, () => work(tx, states)),
      );
    } catch (error) {
      if (error instanceof LinkRefused) return refused(error.status, error.code);
      throw error;
    }
  };

  /** The member's membership, read again for this decision: an active admin, or FORBIDDEN (INTEGRITY_FAILED if tampered with). */
  const adminIn = async (tx: LinkingTx, states: SignedStates, member: LinkingMember, roles: readonly Role[]) => {
    const membership = await membershipOf(tx, states, member.orgId, member.userId);
    if (membership.outcome === 'tampered') throw new LinkRefused(503, 'INTEGRITY_FAILED');
    if (membership.outcome !== 'active' || !roles.includes(membership.role)) throw new LinkRefused(403, 'FORBIDDEN');
    return membership;
  };

  /** The link and the source it made, read (`share`): NOT_FOUND, or INTEGRITY_FAILED for a source that can't be believed. */
  const withSource = async (tx: LinkingTx, states: SignedStates, orgId: string, linkId: string) => {
    const link = await linkOf(tx, { orgId, id: linkId }, 'share');
    if (link === undefined) throw new LinkRefused(404, 'NOT_FOUND');
    if (link.sourceId === null) return { link, source: null };
    const read = await sourceOf(tx, states, { orgId, id: link.sourceId }, 'share');
    if (read.outcome === 'tampered') throw new LinkRefused(503, 'INTEGRITY_FAILED');
    if (read.outcome === 'missing') throw new Error(`a settled link names a source that isn't there: ${linkId}`);
    return { link, source: read.source };
  };

  /** A read in the organisation's transaction, a refusal inside it answered. */
  const answered = async <T extends object>(
    orgId: string,
    correlationId: string,
    work: (tx: LinkingTx, states: SignedStates) => Promise<T>,
  ): Promise<T | Refused> => {
    try {
      return await inOrganisation(orgId, correlationId, work);
    } catch (error) {
      if (error instanceof LinkRefused) return refused(error.status, error.code);
      throw error;
    }
  };

  /** Settles the open link from the partner's answer, adding its source when linked: the write's status. */
  const settle = async (
    tx: LinkingTx,
    states: SignedStates,
    member: LinkingMember,
    link: LinkRecord,
    outcome: LinkOutcome,
  ): Promise<number> => {
    const key = { orgId: member.orgId, id: link.id };
    const now = clock.now();
    if (outcome.kind === 'waiting') return 202;
    if (outcome.kind === 'refused') {
      await settleLink(tx, key, { outcome: outcome.reason }, now);
      return 200;
    }
    // Gone at the partner before Agent X confirmed it: never added, and linking again makes a new one.
    if (outcome.source.availability === 'UNAVAILABLE') {
      await settleLink(tx, key, { outcome: 'rejected' }, now);
      return 200;
    }
    const sourceId = ids.next();
    await addSource(tx, states, {
      orgId: member.orgId,
      id: sourceId,
      linkId: link.id,
      partner,
      state: outcome.source,
      createdAt: now,
      actor: { type: 'user', id: member.userId },
    });
    await settleLink(tx, key, { outcome: 'linked', sourceId }, now);
    return 201;
  };

  return {
    async start(member, idempotent, correlationId) {
      if (rail === undefined) return PARTNER_UNAVAILABLE;
      const linkId = ids.next();
      const session = await asked(() => rail.startSourceLink({ organizationId: member.orgId, linkId }));
      if (session === 'unavailable') return PARTNER_UNAVAILABLE;
      const done = await write(member, idempotent, correlationId, async (tx, states) => {
        await oneLinkStartAtATime(tx, member.orgId);
        const { id: startedBy } = await adminIn(tx, states, member, LINKING_ROLES);
        const now = clock.now();
        if ((await linksStartedSince(tx, member.orgId, new Date(now.getTime() - DAY_MS))) >= MOST_LINKS_STARTED_A_DAY) {
          throw new LinkRefused(409, 'LINK_STARTS_SPENT');
        }
        await addLink(tx, {
          orgId: member.orgId,
          id: linkId,
          startedBy,
          partner,
          sessionRef: session.sessionRef,
          expiresAt: session.expiresAt,
          createdAt: now,
        });
        return { status: 201, resourceId: linkId };
      });
      if (done.outcome === 'refused' || done.outcome === 'conflict' || done.outcome === 'busy') return done;
      const { resourceId } = done.result;
      // A retry answers the first write's link: the partner gives its session again, by the same ID.
      const answer =
        resourceId === linkId
          ? session
          : await asked(() => rail.startSourceLink({ organizationId: member.orgId, linkId: resourceId }));
      if (answer === 'unavailable') return PARTNER_UNAVAILABLE;
      const link = await inOrganisation(member.orgId, correlationId, (tx) =>
        linkOf(tx, { orgId: member.orgId, id: resourceId }, 'share'),
      );
      if (link === undefined) throw new Error(`a link just added isn't there: ${resourceId}`);
      return { outcome: 'started', link, authoriseUrl: answer.authoriseUrl };
    },

    async confirm(member, idempotent, linkId, correlationId) {
      if (rail === undefined) return PARTNER_UNAVAILABLE;
      // Only a link the organisation started is asked about, never an ID from anywhere else.
      const known = await answered(member.orgId, correlationId, async (tx) => {
        const link = await linkOf(tx, { orgId: member.orgId, id: linkId }, 'share');
        if (link === undefined) throw new LinkRefused(404, 'NOT_FOUND');
        return link;
      });
      if (known.outcome === 'refused') return known;
      const outcome =
        known.outcome === 'open'
          ? await asked(() => rail.confirmSourceLink({ organizationId: member.orgId, linkId }))
          : undefined;
      if (outcome === 'unavailable') return PARTNER_UNAVAILABLE;
      const done = await write(member, idempotent, correlationId, async (tx, states) => {
        await adminIn(tx, states, member, LINKING_ROLES);
        const link = await linkOf(tx, { orgId: member.orgId, id: linkId }, 'change');
        if (link === undefined) throw new LinkRefused(404, 'NOT_FOUND');
        // Settled already, by this write's retry or another confirm (the lock waits for one at once, then reads what it
        // left): answered as it stands.
        if (link.outcome !== 'open' || outcome === undefined) return { status: 200, resourceId: linkId };
        return { status: await settle(tx, states, member, link, outcome), resourceId: linkId };
      });
      if (done.outcome === 'refused' || done.outcome === 'conflict' || done.outcome === 'busy') return done;
      const read = await answered(member.orgId, correlationId, (tx, states) =>
        withSource(tx, states, member.orgId, linkId),
      );
      if ('outcome' in read) return read;
      return { outcome: 'confirmed', ...read };
    },
  };
}
