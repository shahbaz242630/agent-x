// Linking the business's own bank account through the payment partner (PRD
// §2.3, ADR-014 §4, BR-01, BR-02, SEC-PTR-08; Phase 1 D2-3b). Composed here, in
// the API, as ADR-004 §7 has it: the partner is the providers module's
// adapter, the links and sources the funding-sources module's, the member
// identity's.
//
// 1. `start` (`funding-sources.link.start`), an admin: the member and the
//    day's budget checked first, so no session is asked of the partner for a
//    start that would be refused; our link ID, made from the write's own
//    idempotency key (the S68 audit: a retry, or a request sent again, asks
//    the partner for the same session, never another; requests with fresh
//    keys sent at once can each still open one before the budget's count
//    in the transaction refuses all but the day's last, bounded by the
//    per-person rate limit, Carry-Forward); the partner asked for
//    a session under it (the partner's idempotency key), and its page held to
//    the partner's own origin over HTTPS (`isPartnerPage`); then, in one
//    transaction, the key claimed, the organisation's lock for starting links,
//    the member read again, the day's budget again (LINK_STARTS_SPENT, the
//    check that counts), and the link added. The partner is never called
//    inside the transaction: a network call must not hold its locks, and the
//    fake partner's own records are another transaction. A retry of the same
//    write answers the link the first one added; the session the retry asked
//    is the same one, and a retry while the partner is down answers
//    PARTNER_UNAVAILABLE. The same key used again after its 30 days, once
//    swept, finds its link taken: 409 IDEMPOTENCY_KEY_REUSED.
// 2. The business approves at its bank, through the partner's page. Nothing
//    that comes back through the browser is believed.
// 3. `confirm` (`funding-sources.link.confirm`), an admin: the link must be
//    the organisation's; the partner is asked, server to server, how the link
//    it started for this organisation ended; then, in one transaction, the key
//    claimed, the member read again, the link locked, and: still waiting, left
//    open (202), and the key's claim rolled back, so asking again with the
//    same key asks the partner again; linked, the source added from the
//    partner's answer and the link settled with it; turned down, run out or
//    unknown to the partner, the link settled so. A link settled already
//    answers as it stands.
//
// A source already gone at the partner by the time it is confirmed is never
// added: the link is settled `rejected`, and linking again makes a new one.
//
// Lock order (ADR-006 §6): the idempotency key, the link-start lock, the
// member's membership (2a), the link and its source (5), the chain head last.
import {
  addLink,
  addSource,
  linkOf,
  type LinkRecord,
  linksStartedSince,
  MOST_LINKS_STARTED_A_DAY,
  oneLinkStartAtATime,
  settleLink,
  sourceOf,
  type SourceRecord,
} from '@agentx/core/modules/funding-sources';
import type { SignedStates } from '@agentx/core/modules/audit';
import {
  createDatabaseRecords,
  createFakeRail,
  type FakePartnerTables,
  isPartnerPage,
  type FakeRail,
  type FinancialRailAdapter,
  limitsInAccountCurrency,
  type LinkOutcome,
} from '@agentx/core/modules/providers';
import { createHash } from 'node:crypto';

import { type Clock, DAY_MS, type IdGenerator } from '@agentx/core/shared-kernel';
import { type Database, type IdempotentRequest, isUnwritten } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import {
  asked,
  createFundingSourceWork,
  type FundingSourceMember,
  FundingSourceRefused,
  type FundingSourceTables,
  type FundingSourceTx,
  PARTNER_UNAVAILABLE,
  orStillWaiting,
  StillWaiting,
} from './funding-source-work.ts';
import type { Refused } from './refused.ts';

/** Starting a link. */
export const LINK_START_OPERATION = 'funding-sources.link.start';
/** Confirming it with the partner, once the business has been at its bank. */
export const LINK_CONFIRM_OPERATION = 'funding-sources.link.confirm';

/** The roles that may link the organisation's bank account: its admins, who hold its authority (PRD §7.3). */
export const LINKING_ROLES = ['admin'] as const;

/** The tables linking works on. */
export type LinkingTables = FundingSourceTables;

/** Who is linking: a signed-in member, in the organisation the access hook verified. */
export type LinkingMember = FundingSourceMember;

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

/**
 * The link's ID, made from the write's idempotency key and whose it is (the
 * S68 audit): the same request sent again names the same link, so the
 * partner, asked under it, answers the same session. A UUID (version 8, RFC
 * 9562) of the key's SHA-256; the key is the client's, so the ID is no
 * secret, and it is only ever looked up within its organisation.
 */
export function linkIdFor(request: IdempotentRequest): string {
  const hash = createHash('sha256')
    .update(
      JSON.stringify([
        request.orgId.toLowerCase(),
        request.client.kind,
        request.client.id,
        request.operation,
        request.key,
      ]),
    )
    .digest();
  hash[6] = ((hash[6] ?? 0) & 0x0f) | 0x80;
  hash[8] = ((hash[8] ?? 0) & 0x3f) | 0x80;
  const hex = hash.subarray(0, 16).toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** Whether a link's insert found its ID taken: the same key, used again once its record was swept. */
const isLinkTaken = (error: unknown): boolean =>
  typeof error === 'object' &&
  error !== null &&
  (error as { code?: unknown }).code === '23505' &&
  (error as { constraint?: unknown }).constraint === 'links_pkey';

/**
 * The partner the config names (ADR-014 §4): the fake, over its own records in
 * the app's database, its bank for the staging demo's steps (fake-bank.ts), or
 * none, when every link answers PARTNER_UNAVAILABLE.
 */
export function railFor(
  partner: { readonly mode: 'fake' } | undefined,
  {
    database,
    clock,
    ids,
  }: { readonly database: Database<FakePartnerTables>; readonly clock: Clock; readonly ids: IdGenerator },
): FakeRail | undefined {
  return partner === undefined ? undefined : createFakeRail({ clock, ids, records: createDatabaseRecords(database) });
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
  const work = createFundingSourceWork({ database, keys, ids, logger });
  const { inOrganisation, answered } = work;

  /** The write with its key claimed first; still waiting at the bank, answered with nothing of it kept. */
  const write = (
    member: LinkingMember,
    idempotent: IdempotentRequest,
    correlationId: string,
    change: (tx: FundingSourceTx, states: SignedStates) => Promise<{ status: number; resourceId: string }>,
  ) => orStillWaiting(() => work.write(member, idempotent, correlationId, change));

  const adminIn = work.memberIn;

  /** The link and the source it made, read (`share`): NOT_FOUND, or INTEGRITY_FAILED for a source that can't be believed. */
  const withSource = async (tx: FundingSourceTx, states: SignedStates, orgId: string, linkId: string) => {
    const link = await linkOf(tx, { orgId, id: linkId }, 'share');
    if (link === undefined) throw new FundingSourceRefused(404, 'NOT_FOUND');
    if (link.sourceId === null) return { link, source: null };
    const read = await sourceOf(tx, states, { orgId, id: link.sourceId }, 'share');
    if (read.outcome === 'tampered') throw new FundingSourceRefused(503, 'INTEGRITY_FAILED');
    if (read.outcome === 'missing') throw new Error(`a settled link names a source that isn't there: ${linkId}`);
    return { link, source: read.source };
  };

  /** Refused past the day's budget of link starts (LINK_STARTS_SPENT). */
  const withinBudget = async (tx: FundingSourceTx, orgId: string): Promise<void> => {
    const since = new Date(clock.now().getTime() - DAY_MS);
    if ((await linksStartedSince(tx, orgId, since)) >= MOST_LINKS_STARTED_A_DAY) {
      throw new FundingSourceRefused(409, 'LINK_STARTS_SPENT');
    }
  };

  /** Settles the open link from the partner's answer, adding its source when linked: the write's status. */
  const settle = async (
    tx: FundingSourceTx,
    states: SignedStates,
    member: LinkingMember,
    link: LinkRecord,
    outcome: LinkOutcome,
  ): Promise<number> => {
    const key = { orgId: member.orgId, id: link.id };
    const now = clock.now();
    if (outcome.kind === 'waiting') throw new StillWaiting();
    if (outcome.kind === 'refused') {
      await settleLink(tx, key, { outcome: outcome.reason }, now);
      return 200;
    }
    // Limits in another currency than the account's (the S68 audit): kept, they'd show agents the wrong one.
    if (!limitsInAccountCurrency(outcome.source)) {
      logger.child({ orgId: member.orgId }).error('funding_sources.currency_mismatch', { linkId: link.id });
      await settleLink(tx, key, { outcome: 'rejected' }, now);
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
    return 200;
  };

  return {
    async start(member, idempotent, correlationId) {
      if (rail === undefined) return PARTNER_UNAVAILABLE;
      // Checked before the partner is asked, so a start that would be refused opens no session there.
      const early = await answered(member.orgId, correlationId, async (tx, states) => {
        await adminIn(tx, states, member, LINKING_ROLES);
        await withinBudget(tx, member.orgId);
        return {};
      });
      if ('outcome' in early) return early;
      const linkId = linkIdFor(idempotent);
      const session = await asked(() => rail.startSourceLink({ organizationId: member.orgId, linkId }));
      if (session === 'unavailable') return PARTNER_UNAVAILABLE;
      // A page a person is sent to: the partner's own, over HTTPS, or none at all.
      if (!isPartnerPage(session.authoriseUrl, rail.authoriseOrigin)) {
        logger.child({ correlationId }).error('funding_sources.partner_page_refused', { partner });
        return PARTNER_UNAVAILABLE;
      }
      const done = await write(member, idempotent, correlationId, async (tx, states) => {
        await oneLinkStartAtATime(tx, member.orgId);
        const { id: startedBy } = await adminIn(tx, states, member, LINKING_ROLES);
        await withinBudget(tx, member.orgId);
        try {
          await addLink(tx, {
            orgId: member.orgId,
            id: linkId,
            startedBy,
            partner,
            sessionRef: session.sessionRef,
            expiresAt: session.expiresAt,
            createdAt: clock.now(),
          });
        } catch (error) {
          if (isLinkTaken(error)) throw new FundingSourceRefused(409, 'IDEMPOTENCY_KEY_REUSED');
          throw error;
        }
        return { status: 201, resourceId: linkId };
      });
      if (isUnwritten(done)) return done;
      // Only a confirm can find its link still waiting.
      if (done.outcome === 'waiting') throw new Error('a link start answered as still waiting');
      const { resourceId } = done.result;
      // Named by the key, a retry's link is this one: the partner gave its session again, by the same ID.
      if (resourceId !== linkId)
        throw new Error(`a link start answered another link than its key names: ${resourceId}`);
      const link = await inOrganisation(member.orgId, correlationId, (tx) =>
        linkOf(tx, { orgId: member.orgId, id: resourceId }, 'share'),
      );
      if (link === undefined) throw new Error(`a link just added isn't there: ${resourceId}`);
      return { outcome: 'started', link, authoriseUrl: session.authoriseUrl };
    },

    async confirm(member, idempotent, linkId, correlationId) {
      if (rail === undefined) return PARTNER_UNAVAILABLE;
      // Only a link the organisation started is asked about, never an ID from anywhere else.
      const known = await answered(member.orgId, correlationId, async (tx) => {
        const link = await linkOf(tx, { orgId: member.orgId, id: linkId }, 'share');
        if (link === undefined) throw new FundingSourceRefused(404, 'NOT_FOUND');
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
        if (link === undefined) throw new FundingSourceRefused(404, 'NOT_FOUND');
        // Settled already, by this write's retry or another confirm (the lock waits for one at once, then reads what it
        // left): answered as it stands.
        if (link.outcome !== 'open' || outcome === undefined) return { status: 200, resourceId: linkId };
        return { status: await settle(tx, states, member, link, outcome), resourceId: linkId };
      });
      // Still waiting leaves nothing written: answered with the link as it stands, open.
      if (isUnwritten(done)) return done;
      const read = await answered(member.orgId, correlationId, (tx, states) =>
        withSource(tx, states, member.orgId, linkId),
      );
      if ('outcome' in read) return read;
      return { outcome: 'confirmed', ...read };
    },
  };
}
