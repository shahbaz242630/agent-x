// Copying the login service's admin events into our audit trail (ADR-003 §4,
// SEC-OPS-02; B6-2b): the API's job, on a timer of its own, reading Zitadel's
// event feed (idp-feed.ts) from where it got to and recording each event we
// copy, so a change made to a person's login behind Agent X's back (a second
// factor removed, a password reset, a login locked, someone given rights in
// the login service itself) is on the record and told.
//
// For each event, once for each organisation the person belongs to, in one
// transaction, withTenant's for that organisation:
// - the organisation's own chain records `person.sign_in_changed` about the
//   person (subject `person`, their Agent X user ID), with Zitadel's event,
//   its type, when, and whether the person did it themselves;
// - a sign-in change is told to the person and to the organisation's admins
//   (0024), written to the outbox in the same transaction;
// - the platform chain records `idp.event_copied` with the event, the
//   organisation and its time, last (ADR-006 §6: the platform head is the
//   last lock of all).
// An event about no one who has signed in to Agent X, about someone who has
// but belongs to no organisation, or about the login service's own
// organisations or instance, is recorded on the platform chain alone,
// organisation `none`, naming the person when there is one (B6-2b review: a
// deliberate rule, not a gap). There is no organisation to tell, and none to
// tell later: B6-3's cooling-off after a reset reads the platform chain by
// person, so a factor removed before someone joins still limits them.
//
// Where it got to is the latest time the platform chain holds for a copied
// event: each run reads from a millisecond before it to a minute before now
// (an event written late, by an older clock, is still read), at most
// MOST_PAGES pages a run, each page from a millisecond before the last one's
// last event. Zitadel's span leaves out its own start (review: its search
// reads events after `since`), so reading from a millisecond before reads
// again the event a run stopped part-way at (it stops at the first that
// fails, which is then the latest copied), and any at the same time as the
// last one read, which a page's end or a run's may cut through; those copied
// already are skipped, as below. Each page so moves on by the events it
// holds, never reading a burst again from its start (reviews). A full page
// all within one millisecond can't be moved past without leaving out any more
// at that time, so it is logged as an error (`idp_events.tied_page`) and
// passed.
// An event, with an organisation, already on the platform chain is skipped,
// so a run that stops part-way, or reads the same time again, copies nothing
// twice. The first run starts a day back.
//
// Impersonation (which the stack never turns on) is logged as an error;
// rights given in the login service, and tokens issued, as warnings. A run
// never throws: a feed that can't be read, or a record that can't be written,
// is logged and the run ends; the next picks up where this one got to.
import { withTenant } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import type { Kysely } from 'kysely';

import type { Clock, IdGenerator } from '../../../shared-kernel/index.ts';
import { type AuditTables, createAuditTrail } from '../../audit/index.ts';
import { type DirectoryTables, organizationsOf } from '../../directory/index.ts';
import type { Notice, NotificationsTables, Outbox } from '../../notifications/index.ts';
import {
  createPlatformChain,
  latestPlatformTime,
  platformEventWith,
  type PlatformControlsTables,
} from '../../platform-controls/index.ts';
import { isToldToThePerson } from '../domain/idp-event.ts';
import type { IdpEvent, IdpEventFeed } from './idp-feed.ts';
import type { IdentityTables } from './tables.ts';
import { userOfSubject } from './users.ts';

/** The platform chain's record of each event copied, and the action the cursor is read from. */
export const IDP_EVENT_COPIED = 'idp.event_copied';

/** The organisation chain's record of a person's sign-in changed. */
export const SIGN_IN_CHANGED = 'person.sign_in_changed';

/** How far back the first run reads. */
const FIRST_RUN_BACK_MS = 24 * 3_600_000;

/** How long an event may be written after its time and still be read: runs read up to this long ago. */
const SETTLE_MS = 60_000;

/** How far before where it got to, or the last page's last event, each read starts: Zitadel's span leaves out its start. */
const OVERLAP_MS = 1;

/** The most pages of events one run reads. */
const MOST_PAGES = 10;

/** The events a page asks for. */
const PAGE = 100;

/** Who records: the API's own job. */
const ACTOR = { type: 'system', id: 'api' } as const;

type Tables = IdentityTables & DirectoryTables & AuditTables & NotificationsTables & PlatformControlsTables;

export interface IdpEventCopier {
  /** Copies the events since the last run, until none is left or the signal is aborted. Never throws. */
  run(signal?: AbortSignal): Promise<void>;
}

/** An event's name: its aggregate and its place among the aggregate's events. */
const keyOf = (event: IdpEvent): string => `${event.aggregateType}:${event.aggregateId}:${event.sequence}`;

/** Who made the change: the person themselves, someone else, or the login service itself. */
const byWhom = (event: IdpEvent): 'self' | 'other' | 'system' =>
  event.editorUserId === null ? 'system' : event.editorUserId === event.aggregateId ? 'self' : 'other';

export function createIdpEventCopier({
  database,
  feed,
  keys,
  ids,
  clock,
  issuer,
  outbox,
  logger,
}: {
  readonly database: Kysely<Tables>;
  readonly feed: IdpEventFeed;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  /** The login service the feed is read from: its subjects are its user IDs. */
  readonly issuer: string;
  readonly outbox: Outbox;
  readonly logger: Logger;
}): IdpEventCopier {
  const trail = createAuditTrail({ keys, ids });
  const platform = createPlatformChain({ keys, ids });

  /** Records the event for one organisation, or for none, in one transaction; false if it was already. */
  const copyOnce = async (event: IdpEvent, person: string | undefined, orgId: string | null): Promise<boolean> => {
    const key = keyOf(event);
    const org = orgId ?? 'none';
    if (await platformEventWith(database, IDP_EVENT_COPIED, { event: key, org })) return false;
    const platformEvent = {
      actor: ACTOR,
      action: IDP_EVENT_COPIED,
      details: {
        event: key,
        org,
        type: event.type,
        at: event.createdAt.toISOString(),
        by: byWhom(event),
        person: person ?? null,
      },
    };
    if (orgId === null || person === undefined) {
      await database.transaction().execute((tx) => platform.record(tx, platformEvent));
      return true;
    }
    await withTenant(database, orgId, async (tx) => {
      await trail.record(tx, orgId, {
        actor: ACTOR,
        action: SIGN_IN_CHANGED,
        subject: { type: 'person', id: person, version: 1 },
        details: { event: key, type: event.type, at: event.createdAt.toISOString(), by: byWhom(event) },
      });
      if (isToldToThePerson(event.eventClass)) {
        const about = { orgId, kind: event.eventClass, membershipId: null, role: null, aboutId: person } as const;
        const notices: Notice[] = [
          { ...about, recipientUserId: person },
          { ...about, recipientUserId: null },
        ];
        await outbox.add(tx, notices);
      }
      await platform.record(tx, platformEvent);
    });
    return true;
  };

  /** Copies one event to every organisation its person belongs to; how many records it wrote. */
  const copy = async (event: IdpEvent): Promise<number> => {
    const person =
      event.aggregateType === 'user'
        ? await userOfSubject(database, { issuer, subject: event.aggregateId })
        : undefined;
    const orgs = person === undefined ? [] : await organizationsOf(database, person);
    let written = 0;
    for (const orgId of orgs.length === 0 ? [null] : orgs) {
      if (await copyOnce(event, person, orgId)) written += 1;
    }
    if (written > 0) {
      const facts = { eventType: event.type, by: byWhom(event), organisations: orgs.length };
      if (event.eventClass === 'impersonated') logger.error('idp.impersonated', facts);
      else if (event.eventClass === 'rights_changed') logger.warn('idp.rights_changed', facts);
      else if (event.eventClass === 'token_issued') logger.warn('idp.token_issued', facts);
    }
    return written;
  };

  /** Reads and copies pages until none is left, MOST_PAGES are read, or the signal is aborted. */
  const copyAll = async (signal: AbortSignal | undefined): Promise<{ events: number; written: number }> => {
    let events = 0;
    let written = 0;
    const until = new Date(clock.now().getTime() - SETTLE_MS);
    const latest = await latestPlatformTime(database, IDP_EVENT_COPIED, 'at');
    let since =
      latest === undefined
        ? new Date(clock.now().getTime() - FIRST_RUN_BACK_MS)
        : new Date(latest.getTime() - OVERLAP_MS);
    for (let page = 0; page < MOST_PAGES; page += 1) {
      if (since.getTime() >= until.getTime()) break;
      const found = await feed.eventsBetween(since, until, PAGE);
      for (const event of found) {
        if (signal?.aborted === true) return { events, written };
        written += await copy(event);
        events += 1;
      }
      // A page not full is the last.
      const last = found.at(-1);
      if (found.length < PAGE || last === undefined) break;
      const next = new Date(last.createdAt.getTime() - OVERLAP_MS);
      if (next.getTime() <= since.getTime()) {
        // The whole page within a millisecond: moving on leaves out any more at that time.
        logger.error('idp_events.tied_page', { at: last.createdAt.toISOString(), events: found.length });
        since = last.createdAt;
      } else {
        since = next;
      }
    }
    return { events, written };
  };

  return {
    async run(signal) {
      try {
        const { events, written } = await copyAll(signal);
        if (written > 0) logger.info('idp_events.copied', { events, records: written });
      } catch (error) {
        logger.warn('idp_events.run_failed', { err: error });
      }
    },
  };
}
