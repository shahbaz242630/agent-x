// The login service's event feed (ADR-003 §4, SEC-OPS-02; B6-2b): the events
// we copy (WATCHED_IDP_EVENTS) created within a span of time, oldest first,
// from Zitadel's event search (`POST /admin/v1/events/_search`), which only a
// service user holding its instance's read-only role (IAM Owner Viewer) may
// ask. The token is the API's directory token (B5-3), that user's.
//
// - The token goes only to the issuer's origin, through the same route as
//   sign-in (`routedToIssuer`), and the outbound fetch's allowlist.
// - Each event is read strictly: its type one we copy, its IDs Zitadel's
//   shape, its sequence digits, its time a time. Anything else throws, as
//   does an answer larger than MOST_ANSWER_BYTES: the feed is then tried
//   again later, never read in part. An event's payload, which may hold an
//   email address, is never read.
// - A login service that can't be reached, refuses the token, or answers
//   otherwise than 200 throws IdpFeedUnavailable, naming the step, never the
//   answer.
import type { OutboundFetch } from '@agentx/platform/outbound';

import { classOfIdpEvent, type IdpEventClass, MOST_WATCHED_TYPES, WATCHED_IDP_EVENTS } from '../domain/idp-event.ts';
import { boundedText } from './zitadel-answer.ts';
import { routedToIssuer } from './zitadel-route.ts';

/** How long one call to the login service may take. */
const CALL_TIMEOUT_MS = 20_000;

/** The most an answer may hold: a page of events, each with a payload we don't read. */
const MOST_ANSWER_BYTES = 2 * 1024 * 1024;

/** The most events one search takes. */
export const MOST_EVENTS_A_PAGE = 100;

/** A token: visible ASCII, bounded. */
const TOKEN = /^[!-~]{1,4096}$/;

/** An ID as Zitadel makes them: digits, or letters for its own system actors. */
const ZITADEL_ID = /^[0-9A-Za-z_-]{1,200}$/;

/** A sequence: a whole number, as Zitadel writes a uint64 in JSON. */
const SEQUENCE = /^[0-9]{1,20}$/;

/** One event, as we copy it. */
export interface IdpEvent {
  /** Zitadel's own type, one we copy. */
  readonly type: string;
  readonly eventClass: IdpEventClass;
  /** What it is about: a user, an organisation or the instance, by Zitadel's ID. */
  readonly aggregateType: 'user' | 'org' | 'instance';
  readonly aggregateId: string;
  /** Its place among its aggregate's events: with the aggregate, it names the event. */
  readonly sequence: string;
  readonly createdAt: Date;
  /** Who made it, by Zitadel's user ID; null when Zitadel names no one. */
  readonly editorUserId: string | null;
}

export class IdpFeedUnavailable extends Error {
  override readonly name = 'IdpFeedUnavailable';
  constructor(step: string) {
    super(`the login service's event feed couldn't be read: ${step}`);
  }
}

export interface IdpEventFeed {
  /** The events we copy created from `since` to `until`, at most `most`, oldest first. Throws IdpFeedUnavailable. */
  eventsBetween(since: Date, until: Date, most: number): Promise<readonly IdpEvent[]>;
}

const AGGREGATES: ReadonlySet<string> = new Set(['user', 'org', 'instance']);

type Answer = Readonly<Record<string, unknown>>;

const field = (value: unknown, name: string): unknown =>
  typeof value === 'object' && value !== null ? (value as Answer)[name] : undefined;

/** The event, read strictly; undefined for one that isn't as Zitadel writes it. */
function eventOf(raw: unknown): IdpEvent | undefined {
  const type = field(field(raw, 'type'), 'type');
  const aggregate = field(raw, 'aggregate');
  const aggregateType = field(field(aggregate, 'type'), 'type');
  const aggregateId = field(aggregate, 'id');
  const sequence = field(raw, 'sequence');
  const creationDate = field(raw, 'creationDate');
  const editor = field(field(raw, 'editor'), 'userId');
  if (typeof type !== 'string') return undefined;
  const eventClass = classOfIdpEvent(type);
  if (eventClass === undefined) return undefined;
  if (typeof aggregateType !== 'string' || !AGGREGATES.has(aggregateType)) return undefined;
  if (typeof aggregateId !== 'string' || !ZITADEL_ID.test(aggregateId)) return undefined;
  const sequenceText = typeof sequence === 'number' && Number.isSafeInteger(sequence) ? String(sequence) : sequence;
  if (typeof sequenceText !== 'string' || !SEQUENCE.test(sequenceText)) return undefined;
  if (typeof creationDate !== 'string') return undefined;
  const createdAt = new Date(creationDate);
  if (Number.isNaN(createdAt.getTime())) return undefined;
  if (editor !== undefined && editor !== '' && (typeof editor !== 'string' || !ZITADEL_ID.test(editor)))
    return undefined;
  return {
    type,
    eventClass,
    aggregateType: aggregateType as IdpEvent['aggregateType'],
    aggregateId,
    sequence: sequenceText,
    createdAt,
    editorUserId: typeof editor === 'string' && editor !== '' ? editor : null,
  };
}

export function createIdpEventFeed({
  issuer,
  internalOrigin,
  token,
  fetch,
}: {
  /** The login service, exactly as its tokens name it. */
  readonly issuer: string;
  /** Where to reach it inside the platform (B2-6); undefined to call the issuer itself. */
  readonly internalOrigin: string | undefined;
  readonly token: string;
  readonly fetch: OutboundFetch;
}): IdpEventFeed {
  if (!URL.canParse(issuer) || new URL(issuer).origin !== issuer) throw new RangeError('the issuer must be an origin');
  if (!TOKEN.test(token)) throw new RangeError('the token must be 1 to 4096 visible ASCII characters');
  const eventTypes = Object.keys(WATCHED_IDP_EVENTS);
  if (eventTypes.length > MOST_WATCHED_TYPES) throw new RangeError('more event types than one search takes');

  return {
    async eventsBetween(since, until, most) {
      if (!Number.isSafeInteger(most) || most < 1 || most > MOST_EVENTS_A_PAGE) {
        throw new RangeError(`a search takes 1 to ${String(MOST_EVENTS_A_PAGE)} events`);
      }
      const [url, init] = routedToIssuer(issuer, internalOrigin, `${issuer}/admin/v1/events/_search`, {
        method: 'POST',
        headers: { authorization: `Bearer ${token}`, accept: 'application/json', 'content-type': 'application/json' },
        body: JSON.stringify({
          asc: true,
          limit: most,
          event_types: eventTypes,
          range: { since: since.toISOString(), until: until.toISOString() },
        }),
      });
      let response: Response;
      try {
        response = await fetch(url, { ...init, signal: AbortSignal.timeout(CALL_TIMEOUT_MS) });
      } catch {
        throw new IdpFeedUnavailable('the call failed');
      }
      if (response.status !== 200) {
        await response.body?.cancel();
        throw new IdpFeedUnavailable(`it answered ${String(response.status)}`);
      }
      let answer: unknown;
      try {
        answer = JSON.parse(
          await boundedText(
            response,
            MOST_ANSWER_BYTES,
            () => new IdpFeedUnavailable(`the answer was larger than ${String(MOST_ANSWER_BYTES)} bytes`),
          ),
        );
      } catch (error) {
        if (error instanceof IdpFeedUnavailable) throw error;
        throw new IdpFeedUnavailable('the answer is not JSON');
      }
      const raw = field(answer, 'events') ?? [];
      if (!Array.isArray(raw) || raw.length > most) throw new IdpFeedUnavailable('the answer holds no list of events');
      return raw.map((each) => {
        const event = eventOf(each);
        if (event === undefined) throw new IdpFeedUnavailable('an event is not as the login service writes them');
        return event;
      });
    },
  };
}
