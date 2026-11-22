// Copying the login service's admin events into our audit trail (ADR-003 §4,
// SEC-OPS-02; B6-2b): the API's job, on a timer of its own, reading Zitadel's
// event feed (idp-feed.ts) from where it got to and recording each event we
// copy, so a change made to a person's login behind Agent X's back (a second
// factor removed, a password reset, a login locked, someone given rights in
// the login service itself) is on the record and told.
//
// One copy at a time, by the jobs' lease (4D2e D). A stale holder (a process
// frozen while leading, running on as it wakes) or a second copy is safe too
// (SA2): each record's transaction first takes a lock named for the event, that
// only copiers take, and judges again under it whether the event was copied for
// that organisation, and whether for any (so a change that ends sessions ends
// them once). A second copier of the same event waits, then finds it copied.
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
// person, so a factor removed before someone joins still limits them; and by
// the login (`subject`, recorded with every event about one, SA2), so one
// removed before they first sign in does too.
//
// The feed is read as two (S210 final): the password resets asked for, in a
// search of their own, and every other event, the changes, each from a read
// position of its own and within pages of its own, the changes first; so a
// flood of resets, which anyone can send, never holds a real change back. The
// changes' feed left more than two runs behind is an error
// (`idp_events.changes_late`): real changes, and their alarms, are late. A
// position is read only from copies at or below the platform chain's head and
// dated no more than two minutes ahead (a row the database's owner planted
// decides nothing); one still past a minute ago reads nothing that run, said
// (`idp_events.position_ahead`).
// Where each got to is the latest time the platform chain holds for a copied
// event of its types (0119's index): each run reads from a millisecond before
// it to a minute before now (an event written late, by an older clock, is
// still read), at most MOST_PAGES pages a run of each feed (the resets' fewer:
// under a flood they fall behind, which is accepted, as they change no
// credential), each page from a millisecond before the last one's
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
// twice. Each feed's first run starts a day back.
//
// The S68 audit added two rules, decided once per event, on its first copy:
// - A change that ends sessions (idp-event.ts `endsSessions`: a second factor
//   added or removed, the password or the login's email changed, the login
//   blocked) ends every Agent X session of the person, in the first copy's
//   transaction, before anything else is locked (ADR-006 §6 level 0b) but the
//   event's own lock, which nothing else takes: the sessions, then their
//   challenges, then the organisation's chain, the outbox and the platform
//   chain's head last (forced in idp-copier.db.test.ts).
// - A security key or passkey added counts toward B6-3d's restriction, 7
//   days without an admin's or approver's powers (`counts: 'yes'` on the
//   platform chain's record), unless it is the person's first second factor
//   of all: so a phished session can't enrol its own key and pass the
//   passkey rule at once, whether the person held a key or an app code
//   alone (F1's first-passkey review). It counts when the person now holds
//   another factor of any kind or a second key, or holds no key at all (the
//   login service's lists trail the event: fails closed), or had a factor
//   of any kind removed in the 7 days before (removing the person's first,
//   then adding one's own). When the factors can't be read (no reset token
//   set, or an answer that can't be judged), it counts: fails closed.
// - A second factor of any kind removed, even by the person, counts too when
//   a key was added in the 7 days before (the S68 review; F1's for an app
//   code): adding one's own key and then removing the person's factor,
//   within one run, leaves the new key alone when the addition is judged, so
//   the removal is what shows the swap.
//
// A password reset asked for (S210 R2-2) changes no credential and anyone who
// knows a login's name can ask for one, so it ends no session and is told to
// the person alone, never the admins, at most once an hour (`told: 'yes'` on
// the platform chain's record of the copy that told them). A flood of them is
// copied once a person a page, the page's latest, the others counted on it
// (`alsoAsked`); read on a feed of its own, it can't hold the copies of real
// changes back.
//
// Impersonation (which the stack never turns on) is logged as an error;
// rights given in the login service, and tokens issued, as warnings. Each of
// these, and a tied page, is told at once by an alert of its own
// (LOGIN_SERVICE_ALERT_EVENTS, SA2), whatever its level; but a token or a grant
// that is exactly one of our own routine changes (idp-event.ts
// isOurRoutineChange: one of our actors, to one of our service users, only
// their roles) is an info line, `idp.token_issued_by_us` or
// `idp.rights_changed_by_us`, which no alert counts and which, as every line
// here, names no account (SA2b). A run
// never throws: a feed that can't be read, or a record that can't be written,
// is logged and the run ends; the next picks up where this one got to.
import { holdTransactionLock, withTenant } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import type { Kysely, Transaction } from 'kysely';

import { type Clock, DAY_MS, HOUR_MS, type IdGenerator } from '../../../shared-kernel/index.ts';
import { type AuditTables, createAuditTrail, nowChainsOf, waitWitnessed } from '../../audit/index.ts';
import { type DirectoryTables, organizationsOf } from '../../directory/index.ts';
import type { NotificationsTables, Outbox } from '../../notifications/index.ts';
import {
  createPlatformChain,
  latestPlatformTime,
  latestPlatformTimeOf,
  platformEventWith,
  type PlatformControlsTables,
} from '../../platform-controls/index.ts';
import {
  endsSessions,
  FEED_TYPES,
  type IdpFeedPart,
  isOurRoutineChange,
  type OurLoginChanges,
  isToldOnlyToThePerson,
  isToldToThePerson,
  PASSKEY_ADDED_EVENTS,
  SECOND_FACTOR_REMOVED_EVENTS,
} from '../domain/idp-event.ts';
import { restrictedUntil } from '../domain/removal-restriction.ts';
import { toldOfReset, toldThePersonAlone } from './grant-notices.ts';
import type { SecondFactorsHeld } from './idp-factors.ts';
import type { IdpEvent, IdpEventFeed } from './idp-feed.ts';
import { endSessionsOf, lockSessionsOf, sessionsEndedEvent } from './sessions.ts';
import { lockChallengesOf } from './step-up-challenges.ts';
import type { IdentityTables } from './tables.ts';
import { userOfSubject } from './users.ts';

/** The platform chain's record of each event copied, and the action each feed's read position is read from. */
export const IDP_EVENT_COPIED = 'idp.event_copied';

/** The organisation chain's record of a person's sign-in changed. */
export const SIGN_IN_CHANGED = 'person.sign_in_changed';

/** How far back the first run reads. */
const FIRST_RUN_BACK_MS = DAY_MS;

/** How long an event may be written after its time and still be read: runs read up to this long ago. */
const SETTLE_MS = 60_000;

/** How far before where it got to, or the last page's last event, each read starts: Zitadel's span leaves out its start. */
const OVERLAP_MS = 1;

/**
 * The most pages of events one run reads of each feed (S210 final): the resets asked for have pages of their own, so a
 * flood of them, which anyone can send, never spends the changes' pages.
 */
const MOST_PAGES: Readonly<Record<IdpFeedPart, number>> = { changes: 10, resets: 5 };

/**
 * How far ahead of the app's clock a copy's time may be and still count toward a read position (AT13h's two minutes):
 * the clocks of two copiers may differ by that much; a row past it, which only the database's owner can plant, never.
 */
const POSITION_AHEAD_MS = 2 * 60_000;

/** How far behind a minute ago the changes' feed may be left by a run before it is an error: two of the API's 5-minute runs. */
const LATE_AFTER_MS = 2 * 5 * 60_000;

/** The events a page asks for. */
const PAGE = 100;

/** Who records: the API's own job. */
const ACTOR = { type: 'system', id: 'api' } as const;

/** No actor's change is ours: what a deployment that names none gets. */
const NONE_OURS: OurLoginChanges = { actors: new Set(), serviceUsers: new Set() };

/** The lock each record's transaction takes first, named for the event: only copiers take it (SA2). */
export const COPY_LOCK = 'idp-event-copy';

type Tables = IdentityTables & DirectoryTables & AuditTables & NotificationsTables & PlatformControlsTables;

export interface IdpEventCopier {
  /** Copies the events since the last run, until none is left or the signal is aborted. Never throws: says if it failed. */
  run(signal?: AbortSignal): Promise<'ran' | 'skipped'>;
}

/** An event's name: its aggregate and its place among the aggregate's events. */
const keyOf = (event: IdpEvent): string => `${event.aggregateType}:${event.aggregateId}:${event.sequence}`;

/** An event read, and how many more of its kind about its login the page held before it, left uncopied (R2-2). */
interface Kept {
  readonly event: IdpEvent;
  readonly alsoAsked: number;
}

/**
 * The page's events to copy (S210 R2-2): every one, but of the events told to the person alone only the latest of each
 * type about each login, counting the others on it. The latest, so the page's last event is always copied and where the
 * copy got to moves on past the flood.
 */
function coalesced(page: readonly IdpEvent[]): Kept[] {
  const kindOf = (event: IdpEvent) => `${event.aggregateType}:${event.aggregateId}:${event.type}`;
  const latest = new Map<string, number>();
  const seen = new Map<string, number>();
  page.forEach((event, index) => {
    if (!isToldOnlyToThePerson(event.eventClass)) return;
    latest.set(kindOf(event), index);
    seen.set(kindOf(event), (seen.get(kindOf(event)) ?? 0) + 1);
  });
  return page.flatMap((event, index): Kept[] => {
    if (!isToldOnlyToThePerson(event.eventClass)) return [{ event, alsoAsked: 0 }];
    return latest.get(kindOf(event)) === index ? [{ event, alsoAsked: (seen.get(kindOf(event)) ?? 1) - 1 }] : [];
  });
}

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
  factors,
  ours = NONE_OURS,
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
  /** Which second factors a person holds, keys apart from others (the reset token's reader); undefined: every key added counts. */
  readonly factors?: SecondFactorsHeld | undefined;
  /** Who makes our own routine changes in the login service (SA2); undefined: none is ours, every one alerts. */
  readonly ours?: OurLoginChanges | undefined;
  readonly logger: Logger;
}): IdpEventCopier {
  const trail = createAuditTrail({ keys, ids });
  const platform = createPlatformChain({ keys, ids });

  /** Whether an event of one of `types` was copied for the person in the 7 days before `event`. */
  const copiedWithinWeek = async (event: IdpEvent, person: string, types: readonly string[]): Promise<boolean> => {
    const at = await latestPlatformTimeOf(database, 'at', [
      { action: IDP_EVENT_COPIED, facts: { person }, oneOf: { type: types } },
    ]);
    return at !== undefined && restrictedUntil(at).getTime() >= event.createdAt.getTime();
  };

  /**
   * Whether a key added counts toward the restriction: unless the person
   * holds it alone, as above; and when that can't be read, it counts.
   */
  const keyAddedCounts = async (event: IdpEvent, person: string): Promise<boolean> => {
    if (await copiedWithinWeek(event, person, SECOND_FACTOR_REMOVED_EVENTS)) return true;
    if (factors === undefined) return true;
    try {
      const held = await factors.secondFactorsHeld(event.aggregateId);
      // No key listed: the lists trail the event that added one, so what else is held isn't known.
      return held.others > 0 || held.keys !== 1;
    } catch (error) {
      logger.warn('idp_events.keys_unread', { err: error });
      return true;
    }
  };

  /**
   * Whether a second factor removed counts toward the restriction, whoever
   * removed it: a key was added in the 7 days before (a swap of the person's
   * factor for another's key). The addition is copied first, as the feed
   * gives events in time order.
   */
  const removalCounts = (event: IdpEvent, person: string): Promise<boolean> =>
    copiedWithinWeek(event, person, PASSKEY_ADDED_EVENTS);

  /** Whether the event counts toward the restriction: a key added or a factor removed, as above; nothing else. */
  const counted = (event: IdpEvent, person: string): Promise<boolean> | boolean => {
    if (PASSKEY_ADDED_EVENTS.includes(event.type)) return keyAddedCounts(event, person);
    if (SECOND_FACTOR_REMOVED_EVENTS.includes(event.type)) return removalCounts(event, person);
    return false;
  };

  /**
   * Whether the person is told of this event, one told to them alone (R2-2): unless a copy told them within the hour
   * before it, so a flood of resets asked for reaches their inbox once an hour at most.
   */
  const tellsAlone = async (event: IdpEvent, person: string): Promise<boolean> => {
    const at = await latestPlatformTimeOf(database, 'at', [
      { action: IDP_EVENT_COPIED, facts: { person, told: 'yes' }, oneOf: { type: [event.type] } },
    ]);
    return at === undefined || at.getTime() + HOUR_MS <= event.createdAt.getTime();
  };

  /**
   * Ends every session of the person, locking them and then their challenges
   * first (level 0b, in order of ID, as a demotion does), so the challenges
   * the sessions' end deletes are never locked out of order; how many ended.
   */
  const endSessions = async (tx: Parameters<typeof endSessionsOf>[0], person: string, at: Date): Promise<number> => {
    await lockSessionsOf(tx, [person]);
    await lockChallengesOf(tx, [person]);
    return endSessionsOf(tx, person, at);
  };

  /**
   * Records the event for one organisation, or for none, in one transaction;
   * false if it was already. The event's lock first, then judged again under
   * it: copied for this organisation already, nothing; copied for none yet,
   * this is the first copy, which ends the person's sessions when the change
   * does, unless this run ended them already (`endedThisRun`). `counts` is
   * decided once, before the first copy; so is `tells`, which only the first
   * organisation's copy of an event told to the person alone carries (R2-2).
   */
  const copyOnce = async (
    event: IdpEvent,
    person: string | undefined,
    orgId: string | null,
    {
      counts,
      tells,
      alsoAsked,
      endedThisRun,
    }: {
      readonly counts: boolean;
      readonly tells: boolean;
      readonly alsoAsked: number;
      readonly endedThisRun: Set<string>;
    },
  ): Promise<boolean> => {
    const key = keyOf(event);
    const org = orgId ?? 'none';
    // Read first outside, so a run reading the same time again opens no transaction for what it copied.
    if (await platformEventWith(database, IDP_EVENT_COPIED, { event: key, org })) return false;
    const details = {
      event: key,
      org,
      type: event.type,
      at: event.createdAt.toISOString(),
      by: byWhom(event),
      person: person ?? null,
      ...(event.aggregateType === 'user' && { subject: event.aggregateId }),
      ...(counts && { counts: 'yes' }),
      ...(tells && { told: 'yes' }),
      ...(alsoAsked > 0 && { alsoAsked }),
    };
    const platformEvent = (signInsEnded: number | undefined) => ({
      actor: ACTOR,
      action: IDP_EVENT_COPIED,
      details: signInsEnded === undefined ? details : { ...details, signInsEnded },
    });
    /** The person's sessions ended, when the copy ends them: how many, and the signed record of the end (R-15). */
    const ended = async (tx: Transaction<Tables>, ending: string | undefined) => {
      if (ending === undefined) return { count: undefined, signed: [] };
      const at = clock.now();
      return { count: await endSessions(tx, ending, at), signed: [sessionsEndedEvent(ending, at)] };
    };
    /** The platform chain's records, last of all (ADR-006 §6): the copy, then the end if there was one. */
    const recordOnPlatform = async (tx: Transaction<Tables>, end: Awaited<ReturnType<typeof ended>>) => {
      for (const event of [platformEvent(end.count), ...end.signed]) await platform.record(tx, event);
    };
    /** The event's lock, then whether to copy it and whose sessions to end: undefined to copy nothing. */
    const judged = async (tx: Transaction<Tables>): Promise<{ ending: string | undefined } | undefined> => {
      await holdTransactionLock(tx, COPY_LOCK, key);
      if (await platformEventWith(tx, IDP_EVENT_COPIED, { event: key, org })) return undefined;
      const ends = person !== undefined && endsSessions(event.eventClass) && !endedThisRun.has(person);
      const first = ends && !(await platformEventWith(tx, IDP_EVENT_COPIED, { event: key }));
      return { ending: first ? person : undefined };
    };
    /** Whose sessions the copy ended, kept once its transaction commits. */
    let ending: string | undefined;
    const opened: { tx?: object } = {};
    const copied = await (orgId === null || person === undefined
      ? database.transaction().execute(async (tx) => {
          opened.tx = tx;
          const copying = await judged(tx);
          if (copying === undefined) return false;
          ending = copying.ending;
          await recordOnPlatform(tx, await ended(tx, copying.ending));
          return true;
        })
      : withTenant(database, orgId, async (tx) => {
          opened.tx = tx;
          const copying = await judged(tx);
          if (copying === undefined) return false;
          ending = copying.ending;
          const end = await ended(tx, copying.ending);
          await trail.record(tx, orgId, {
            actor: ACTOR,
            action: SIGN_IN_CHANGED,
            subject: { type: 'person', id: person, version: 1 },
            details: { event: key, type: event.type, at: event.createdAt.toISOString(), by: byWhom(event) },
          });
          if (isToldToThePerson(event.eventClass)) {
            await outbox.add(tx, toldOfReset(orgId, event.eventClass, person, false));
          } else if (tells) {
            // The notice of a password changed, whose words name a reset asked for too: to the person alone.
            await outbox.add(tx, toldThePersonAlone(orgId, 'password_changed', person));
          }
          await recordOnPlatform(tx, end);
          return true;
        }));
    if (ending !== undefined) endedThisRun.add(ending);
    // Its heads outside the database before the copy is taken as done (TR-1): WitnessUnconfirmed past the wait, the
    // copy kept (a later run finds it copied), its heads still queued.
    if (opened.tx !== undefined) await waitWitnessed(nowChainsOf(opened.tx));
    return copied;
  };

  /** Copies one event to every organisation its person belongs to; how many records it wrote. */
  const copy = async ({ event, alsoAsked }: Kept, endedThisRun: Set<string>): Promise<number> => {
    const person =
      event.aggregateType === 'user'
        ? await userOfSubject(database, { issuer, subject: event.aggregateId }, { keys, logger })
        : undefined;
    const orgs = person === undefined ? [] : await organizationsOf(database, person);
    // Decided once, on the event's first copy: a run that stopped part-way decides nothing again.
    const copiedBefore = await platformEventWith(database, IDP_EVENT_COPIED, { event: keyOf(event) });
    const counts = !copiedBefore && person !== undefined ? await counted(event, person) : false;
    let tells =
      !copiedBefore && person !== undefined && orgs.length > 0 && isToldOnlyToThePerson(event.eventClass)
        ? await tellsAlone(event, person)
        : false;
    let written = 0;
    for (const orgId of orgs.length === 0 ? [null] : orgs) {
      if (await copyOnce(event, person, orgId, { counts, tells, alsoAsked, endedThisRun })) written += 1;
      // Told once, by the first organisation's copy: the person is one person whatever organisations they are in.
      tells = false;
    }
    if (written > 0) told(event, orgs.length);
    return written;
  };

  /** The line a copied event's class asks for: an alarm, a warning the alert counts, or our own routine change. */
  const told = (event: IdpEvent, organisations: number): void => {
    const facts = { eventType: event.type, by: byWhom(event), organisations };
    if (event.eventClass === 'impersonated') {
      logger.error('idp.impersonated', facts);
      return;
    }
    if (event.eventClass !== 'rights_changed' && event.eventClass !== 'token_issued') return;
    if (isOurRoutineChange(event, ours)) {
      // SA2b: no editor or target, as no other line has: they would name our own accounts, which the deployment keeps
      // in the vault so nobody learns which to aim at. The platform record keeps the event's key, to look up there.
      const mine = { eventType: event.type, organisations };
      if (event.eventClass === 'rights_changed') logger.info('idp.rights_changed_by_us', mine);
      else logger.info('idp.token_issued_by_us', mine);
    } else if (event.eventClass === 'rights_changed') {
      logger.warn('idp.rights_changed', facts);
    } else {
      logger.warn('idp.token_issued', facts);
    }
  };

  /** What a run, or one feed's part of it, copied. */
  interface Copied {
    events: number;
    written: number;
    alsoAsked: number;
  }

  /** Where one feed's run reads from: just before where it got to, or a day back; undefined, said, when that is ahead. */
  const startOf = async (part: IdpFeedPart, until: Date): Promise<Date | undefined> => {
    const notAfter = new Date(clock.now().getTime() + POSITION_AHEAD_MS);
    const latest = await latestPlatformTime(database, IDP_EVENT_COPIED, 'at', FEED_TYPES[part], notAfter);
    if (latest === undefined) return new Date(clock.now().getTime() - FIRST_RUN_BACK_MS);
    const since = new Date(latest.getTime() - OVERLAP_MS);
    if (since.getTime() < until.getTime()) return since;
    // Where it got to is past a minute ago: a copy by a copier whose clock runs ahead, or a row planted ahead by the
    // database's owner (one past POSITION_AHEAD_MS decides nothing). Nothing is read until the time passes it, which
    // takes minutes at most; said, as nothing is copied meanwhile.
    logger.error('idp_events.position_ahead', { feed: part, position: latest.toISOString() });
    return undefined;
  };

  /**
   * A full page all within one millisecond, passed: moving on leaves out any more at that time. On the resets' feed
   * only resets asked for can be missed, which change no credential: words of their own, outside the SEV-1 alert.
   */
  const tiedPage = (part: IdpFeedPart, last: IdpEvent, events: number): void => {
    const facts = { at: last.createdAt.toISOString(), events };
    if (part === 'resets') logger.error('idp_events.tied_page_resets', facts);
    else logger.error('idp_events.tied_page', facts);
  };

  /**
   * Reads and copies one feed's pages, from its own read position, until none is left, its MOST_PAGES are read, or the
   * signal is aborted; where the next run will read it from when its pages ran out first, else undefined.
   */
  const copyPart = async (
    part: IdpFeedPart,
    until: Date,
    endedThisRun: Set<string>,
    copied: Copied,
    signal: AbortSignal | undefined,
  ): Promise<Date | undefined> => {
    let since = await startOf(part, until);
    if (since === undefined) return undefined;
    for (let page = 0; page < MOST_PAGES[part]; page += 1) {
      if (since.getTime() >= until.getTime()) return undefined;
      const found = await feed.eventsBetween(since, until, PAGE, part);
      for (const kept of coalesced(found)) {
        if (signal?.aborted === true) return undefined;
        copied.written += await copy(kept, endedThisRun);
        copied.events += 1 + kept.alsoAsked;
        copied.alsoAsked += kept.alsoAsked;
      }
      // A page not full is the last.
      const last = found.at(-1);
      if (found.length < PAGE || last === undefined) return undefined;
      const next = new Date(last.createdAt.getTime() - OVERLAP_MS);
      if (next.getTime() <= since.getTime()) {
        tiedPage(part, last, found.length);
        since = last.createdAt;
      } else {
        since = next;
      }
    }
    return since;
  };

  /**
   * Copies the changes, then the resets asked for, each feed within its own pages. The changes' feed left more than
   * LATE_AFTER_MS behind a minute ago is an error, once a run: real changes, and their alarms, are late.
   */
  const copyAll = async (signal: AbortSignal | undefined): Promise<Copied> => {
    const copied: Copied = { events: 0, written: 0, alsoAsked: 0 };
    const until = new Date(clock.now().getTime() - SETTLE_MS);
    // Each person's sessions ended once a run, at their first event that ends them (R-15, S206): every event the run
    // copies was made before `until`, so before that end, which covers them all; and one person's changes in a burst
    // put one record of an end on the platform chain a run, not one each.
    const endedThisRun = new Set<string>();
    const behind = await copyPart('changes', until, endedThisRun, copied, signal);
    if (behind !== undefined && until.getTime() - behind.getTime() > LATE_AFTER_MS) {
      logger.error('idp_events.changes_late', {
        since: behind.toISOString(),
        behindMinutes: Math.floor((until.getTime() - behind.getTime()) / 60_000),
      });
    }
    // The resets may fall behind under a flood, run after run, and that is accepted: they change no credential, and
    // their own pages and read position keep them from ever holding back the changes above.
    if (signal?.aborted !== true) await copyPart('resets', until, endedThisRun, copied, signal);
    return copied;
  };

  return {
    async run(signal) {
      try {
        const { events, written, alsoAsked } = await copyAll(signal);
        if (written > 0) logger.info('idp_events.copied', { events, records: written, alsoAsked });
        return 'ran';
      } catch (error) {
        logger.warn('idp_events.run_failed', { err: error });
        return 'skipped';
      }
    },
  };
}
