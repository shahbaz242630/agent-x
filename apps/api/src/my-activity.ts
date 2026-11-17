// One person's own activity log (Phase 6 6E1a, CO8, PL-48; decision 26's L8:
// "everything logged, per person, one click for them"). Routes about a
// person's own account (`person`): no organisation header, no role, and the
// person is always the session's, never a parameter, so no request can name
// another's rows.
//
// - `GET /v1/auth/activity?from&to[&before][&limit]`: the requests the person
//   made naming no organisation they are verified in (`access.person_requests`:
//   their profile, their session, an invitation, an organisation they turned
//   out not to be in, kept only as their claim), newest first, a page at most
//   MOST_A_PAGE, each marked sealed or not by `sealedThrough`, the newest day
//   the person log's seal on the platform chain names. Their requests in an
//   organisation are that organisation's log, read by its admins (D1). Beside
//   them, Agent X's own exports of this person's log for a case, newest first
//   (D2): a person is told when we read theirs out.
// - `POST /v1/auth/activity/exports {from, to, format}`: their own log as CSV
//   or NDJSON, up to 12 months and MOST_EXPORTED_REQUESTS requests
//   (ACTIVITY_EXPORT_TOO_LARGE, nothing recorded), recorded first on the
//   platform chain as `access_log.person_exported` (naming the person, the
//   range, the format, the count and the last row written then), five an hour a
//   person counted from those records under the person's own lock
//   (ACTIVITY_EXPORTS_SPENT); one built at a time on a server
//   (ACTIVITY_EXPORTS_BUSY). With an Idempotency-Key, kept under
//   PERSON_KEYS_TENANT (the store is walled by organisation; a person's own
//   writes belong to none), so a retry answers the same rows again.
// - A seal or a record on the platform chain that can't be believed raises the
//   alarm (`audit.integrity_failed`, check `person_log`) and is 503
//   INTEGRITY_FAILED; nothing is held (D3).
// Reading the page is itself a row of the person log (the activity recorder).
import { type ActivityCursor, type PersonActivityRow, personInRange, personPage } from '@agentx/core/modules/activity';
import {
  EXPORT_BATCH,
  MOST_EXPORT_DAYS,
  MOST_EXPORTED_REQUESTS,
  newestPersonSeal,
  operatorExportsOf,
  personActivityShown,
  PERSON_LOG_EXPORTED,
  personExportsSince,
  type PersonLogEvent,
  personLogEventOf,
  personNdjsonLine,
} from '@agentx/core/modules/evidence';
import { createPlatformChain } from '@agentx/core/modules/platform-controls';
import { type Clock, DAY_MS, HOUR_MS, type IdGenerator } from '@agentx/core/shared-kernel';
import {
  createIdempotentWrites,
  type Database,
  type DatabaseTransaction,
  holdTransactionLock,
  type IdempotentRequest,
  isUnwritten,
  limitedTransaction,
  withTenant,
} from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { need } from './access.ts';
import { CLIENT_CLUES, cursorOf, cursorText } from './activity-log.ts';
import { API_SCHEMAS } from './api-schemas.ts';
import { BUSY_RETRY_SECONDS } from './errors.ts';
import {
  CONTENT_TYPES,
  csvRow,
  EXPORT_BODY_LIMIT,
  EXPORT_FORMATS,
  exportFile,
  type ExportFormat,
} from './audit-log-exports.ts';
import { answerRefusal, idempotentRequest } from './idempotent-writes.ts';
import { personLogAlarm, type PersonSealTables } from './person-seal.ts';
import { type Refused, refused } from './refused.ts';
import { UseCaseRefused } from './use-case-work.ts';

/**
 * Where a person's own writes keep their idempotency keys: the store is walled by organisation (0006), and these
 * belong to none. No organisation has this ID; each key is the person's own by its client (the store's key holds it).
 */
export const PERSON_KEYS_TENANT = '00000000-0000-0000-0000-000000000000';

export const MY_ACTIVITY_EXPORT_OPERATION = 'my-activity.export';

/** The advisory lock a person's own downloads count their hourly budget under (ADR-006 §6). */
export const MY_ACTIVITY_EXPORTS_LOCK = 'my-activity-exports';

/** The most rows a page holds. */
const MOST_A_PAGE = 100;

/** The most of a person's own downloads in an hour, as an admin's of theirs. */
const MOST_EXPORTS_AN_HOUR = 5;

/** How many of Agent X's exports of the person's log the page lists, newest first. */
const EXPORTS_LISTED = 20;

/**
 * How many people's downloads one server builds at once, apart from the organisations' (activity-log-exports.ts):
 * each holds its whole file in memory.
 */
const MOST_BUILDING = 2;

const ACTOR = { type: 'system', id: 'api' } as const;

type MyActivityTx = DatabaseTransaction<PersonSealTables>;

/** A page of the person's log asked for: the range, where it starts before, how many. */
export interface MyActivityAsked {
  readonly from: Date;
  readonly to: Date;
  readonly before: ActivityCursor | undefined;
  readonly limit: number;
}

export type MyActivityPage =
  | {
      readonly outcome: 'page';
      readonly rows: readonly PersonActivityRow[];
      readonly next: ActivityCursor | null;
      readonly sealedDay: string | null;
      readonly exports: readonly PersonLogEvent[];
    }
  | Refused;

/** A download as asked for: its range and format. */
export interface MyExportAsked {
  readonly from: Date;
  readonly to: Date;
  readonly format: ExportFormat;
}

/** A download made: its record's ID, its file's name, type and text, and how many requests. */
interface MyExportFile {
  readonly id: string;
  readonly fileName: string;
  readonly contentType: (typeof CONTENT_TYPES)[ExportFormat];
  readonly content: string;
  readonly requests: number;
}

export type MyExportWrite =
  | { readonly outcome: 'exported'; readonly file: MyExportFile }
  | { readonly outcome: 'conflict' }
  | { readonly outcome: 'busy' }
  | Refused;

export interface MyActivity {
  /** A page of the person's own log; `userId` always the session's. */
  page(userId: string, asked: MyActivityAsked, correlationId: string): Promise<MyActivityPage>;
  /** The person's own log downloaded, recorded first; `userId` always the session's. */
  export(
    userId: string,
    idempotent: IdempotentRequest,
    asked: MyExportAsked,
    correlationId: string,
  ): Promise<MyExportWrite>;
}

/** Thrown inside the write, so everything it did rolls back, and answered as the refusal. */
class MyActivityRefused extends UseCaseRefused {}

/**
 * Who may build a download of their own log now (review round 1: no person can hold the others up): every person's
 * build on this server shares MOST_BUILDING slots, kept apart from the organisations' downloads (their own module's
 * one); a person holds one at a time; and a retry answered from its key (no budget spent, so the file built again)
 * is held to MOST_EXPORTS_AN_HOUR an hour a person, in this process's memory.
 */
export function createBuildGate(
  clock: Clock,
  slots = MOST_BUILDING,
  mostReplays = MOST_EXPORTS_AN_HOUR,
  /** How many people's retries are kept before the stale are swept: then twice as many as remain, or this. */
  sweepFrom = 1_024,
) {
  const building = new Set<string>();
  // Each person's retries in the last hour, newest last; a person with none is no entry (review round 2: bounded by
  // the people active in the hour, however many there are).
  const replays = new Map<string, number[]>();
  let sweepAt = sweepFrom;
  /** Every person's retries older than the hour forgotten, and anyone left with none. */
  const sweep = (since: number) => {
    for (const [userId, times] of replays) {
      const recent = times.filter((at) => at > since);
      if (recent.length === 0) replays.delete(userId);
      else replays.set(userId, recent);
    }
    sweepAt = Math.max(sweepFrom, replays.size * 2);
  };
  return {
    /** Takes a slot for the person: undefined once taken, or the refusal (BUSY: the person's own, or no slot free). */
    enter(userId: string): Refused | undefined {
      if (building.has(userId) || building.size >= slots) return refused(503, 'ACTIVITY_EXPORTS_BUSY');
      building.add(userId);
      return undefined;
    },
    leave(userId: string): void {
      building.delete(userId);
    },
    /** Counts a retry answered from its key: SPENT past the person's hourly replays, else undefined. */
    replayed(userId: string): Refused | undefined {
      const now = clock.now().getTime();
      const since = now - HOUR_MS;
      if (replays.size >= sweepAt) sweep(since);
      const recent = (replays.get(userId) ?? []).filter((at) => at > since);
      if (recent.length >= mostReplays) return refused(409, 'ACTIVITY_EXPORTS_SPENT');
      replays.set(userId, [...recent, now]);
      return undefined;
    },
    /** How many people's retries are kept now: for the tests. */
    kept: (): number => replays.size,
  };
}

/** A CSV download's header: one column a field of a request as shown. */
export const MY_ACTIVITY_CSV_HEADER = [
  'id',
  'recordedAt',
  'localTime',
  'claimedOrganizationId',
  'method',
  'route',
  'pathIds',
  'status',
  'reason',
  'correlationId',
  'durationMs',
  'sealed',
  'ip',
  'approximateCountry',
  'approximateCity',
  'placeBy',
  'timeZone',
  'timeZoneFrom',
];

/** One request as a download's file holds it: one NDJSON line, or one CSV row (every cell made safe, SEC-EVD-04). */
export const myActivityLineOf = (format: ExportFormat, row: PersonActivityRow, sealedDay: string | null): string => {
  if (format === 'ndjson') return personNdjsonLine(row, sealedDay);
  const shown = personActivityShown(row, sealedDay);
  const { place, timeZone } = shown.client;
  return csvRow(
    [shown.id, shown.recordedAt, shown.localTime ?? '', shown.claimedOrganizationId ?? '', shown.method, shown.route]
      .concat([shown.pathIds.join(' '), String(shown.status), shown.reason ?? '', shown.correlationId])
      .concat([String(shown.durationMs), String(shown.sealed), shown.client.ip ?? ''])
      .concat([place?.country ?? '', place?.city ?? '', place === null ? '' : `${place.by} (${place.link})`])
      .concat([timeZone?.name ?? '', timeZone?.from ?? '']),
  );
};

export function createMyActivity({
  database,
  keys,
  ids,
  clock,
  logger,
  mostRequests = MOST_EXPORTED_REQUESTS,
}: {
  readonly database: Database<PersonSealTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly logger: Logger;
  /** The cap, MOST_EXPORTED_REQUESTS unless a test sets it lower. */
  readonly mostRequests?: number;
}): MyActivity {
  const platform = createPlatformChain({ keys, ids });
  const gate = createBuildGate(clock);

  /** A read in one limited transaction; a record that can't be believed raises the alarm and is INTEGRITY_FAILED. */
  const read = async <T>(correlationId: string, work: (tx: MyActivityTx) => Promise<T | 'unsealed'>) => {
    const found = await limitedTransaction(database, work);
    if (found !== 'unsealed') return found;
    personLogAlarm(logger.child({ correlationId }), 'unsealed', null);
    return refused(503, 'INTEGRITY_FAILED');
  };

  /** The newest day sealed, believed. */
  const sealedDayOf = async (tx: MyActivityTx) => {
    const sealed = await newestPersonSeal(tx, keys);
    return sealed === 'unsealed' ? sealed : sealed.day;
  };

  /** The download's file: the person's rows written up to `writtenUpTo`, newest first, a batch to a transaction. */
  const fileOf = async (
    userId: string,
    id: string,
    asked: MyExportAsked,
    writtenUpTo: string | null,
    correlationId: string,
  ): Promise<MyExportWrite> => {
    const lines: string[] = [];
    // Every row marked against one seal, read once: one landing mid-file would show a day half sealed.
    const sealedDay = await read(correlationId, sealedDayOf);
    if (typeof sealedDay === 'object' && sealedDay !== null) return sealedDay;
    // undefined: the first batch, from the newest; null: none left.
    let before: ActivityCursor | null | undefined = writtenUpTo === null ? null : undefined;
    while (before !== null && writtenUpTo !== null) {
      const start: ActivityCursor | undefined = before;
      const page: Awaited<ReturnType<typeof personPage>> = await limitedTransaction(database, (tx) =>
        personPage(tx, userId, { ...asked, before: start, writtenUpTo, limit: EXPORT_BATCH }),
      );
      for (const row of page.rows) lines.push(myActivityLineOf(asked.format, row, sealedDay));
      before = page.next;
    }
    // Counted before exportFile puts a CSV's header in front of the lines.
    const requests = lines.length;
    const file = { id, ...exportFile('my-activity', asked, MY_ACTIVITY_CSV_HEADER, lines), requests };
    return { outcome: 'exported', file };
  };

  /** The download recorded on the platform chain, before any row is read: the key's outcome, or the refusal. */
  const recorded = async (
    userId: string,
    idempotent: IdempotentRequest,
    asked: MyExportAsked,
    correlationId: string,
  ) => {
    const idempotency = createIdempotentWrites({ keys, logger: logger.child({ correlationId }) });
    try {
      return await withTenant(database, PERSON_KEYS_TENANT, (tx) =>
        idempotency.run(tx, idempotent, async () => {
          // The person's other download in flight commits or rolls back before this one counts (ADR-006 §6).
          await holdTransactionLock(tx, MY_ACTIVITY_EXPORTS_LOCK, userId);
          const since = new Date(clock.now().getTime() - HOUR_MS);
          if ((await personExportsSince(tx, userId, since)) >= MOST_EXPORTS_AN_HOUR) {
            throw new MyActivityRefused(409, 'ACTIVITY_EXPORTS_SPENT');
          }
          const range = await personInRange(tx, userId, asked);
          if (range.rows > mostRequests) throw new MyActivityRefused(409, 'ACTIVITY_EXPORT_TOO_LARGE');
          const event = await platform.record(tx, {
            actor: ACTOR,
            action: PERSON_LOG_EXPORTED,
            details: {
              person: userId,
              from: asked.from.toISOString(),
              to: asked.to.toISOString(),
              format: asked.format,
              requests: range.rows,
              writtenUpTo: range.writtenUpTo,
            },
          });
          return { status: 201, resourceId: event.id };
        }),
      );
    } catch (error) {
      if (error instanceof MyActivityRefused) return refused(error.status, error.code);
      throw error;
    }
  };

  /** The download, recorded first, then its file, built in the person's slot. */
  const exported = async (
    userId: string,
    idempotent: IdempotentRequest,
    asked: MyExportAsked,
    correlationId: string,
  ): Promise<MyExportWrite> => {
    const done = await recorded(userId, idempotent, asked, correlationId);
    if (isUnwritten(done)) return done;
    // A retry spends no budget, yet its file is built again: held to its own hourly count.
    const spent = done.outcome === 'replayed' ? gate.replayed(userId) : undefined;
    if (spent !== undefined) return spent;
    // A retry reads its own record for the last row it was made to, so it answers the same requests.
    const id = done.result.resourceId;
    const made = await read(correlationId, (tx) => personLogEventOf(tx, keys, id));
    if (made !== undefined && 'outcome' in made) return made;
    if (made?.action !== PERSON_LOG_EXPORTED || made.details.person !== userId) {
      // Our own record, just written or found by the person's own key: gone, another kind, or another's, is past the app.
      personLogAlarm(logger.child({ correlationId }), 'unsealed', null);
      return refused(503, 'INTEGRITY_FAILED');
    }
    const { writtenUpTo } = made.details;
    return fileOf(userId, id, asked, typeof writtenUpTo === 'string' ? writtenUpTo : null, correlationId);
  };

  return {
    page: (userId, asked, correlationId) =>
      read(correlationId, async (tx) => {
        const page = await personPage(tx, userId, asked);
        const sealedDay = await sealedDayOf(tx);
        const exports = await operatorExportsOf(tx, keys, userId, EXPORTS_LISTED);
        if (sealedDay === 'unsealed' || exports === 'unsealed') return 'unsealed' as const;
        return { outcome: 'page' as const, ...page, sealedDay, exports };
      }),

    async export(userId, idempotent, asked, correlationId) {
      const busy = gate.enter(userId);
      if (busy !== undefined) return busy;
      try {
        return await exported(userId, idempotent, asked, correlationId);
      } finally {
        gate.leave(userId);
      }
    },
  };
}

/** The session's person: the access hook lets no one else through, so a route that runs without one is a bug. */
const personOf = (request: FastifyRequest): string => {
  if (request.person === null) throw new Error("a person's own route ran without a person");
  return request.person.userId;
};

const MY_ACTIVITY_ROW = z
  .object({
    id: z.uuid().describe('The row, by its ID.'),
    recordedAt: z.iso.datetime().describe('When the request arrived, in UTC: exact.'),
    localTime: z
      .string()
      .nullable()
      .describe('The same moment as the clock read in `client.timeZone`, with its offset; null with no time zone.'),
    claimedOrganizationId: z
      .uuid()
      .nullable()
      .describe(
        'The organisation your request named, when you were not a verified member of it: your own claim, never shown to that organisation; null for none.',
      ),
    method: z.string().describe('The request’s method, such as `GET`.'),
    route: z.string().describe('The route’s pattern, such as `/v1/auth/session`: never the address as sent.'),
    pathIds: z.array(z.uuid()).describe('The IDs its path named, in order.'),
    status: z.int().describe('The answer’s HTTP status.'),
    reason: z.string().nullable().describe('The reason code of a refusal or failure; null for neither.'),
    correlationId: z.uuid().describe('The request’s correlation ID.'),
    durationMs: z.int().min(0).describe('How long it took to answer, in milliseconds.'),
    sealed: z
      .boolean()
      .describe('Whether its day is sealed on the platform audit chain: written on or before `sealedThrough`.'),
    client: CLIENT_CLUES,
  })
  .register(API_SCHEMAS, { id: 'MyActivityRow', description: 'One request in your own activity log.' });

const MY_ACTIVITY_EXPORT = z
  .object({
    id: z.uuid().describe('The export’s record on the platform audit chain.'),
    at: z.iso.datetime().describe('When Agent X exported it.'),
    from: z.string().nullable().describe('The range it covered: from this time.'),
    to: z.string().nullable().describe('To this time.'),
    requests: z.int().nullable().describe('How many of your requests it held.'),
    caseRef: z
      .string()
      .nullable()
      .describe('The case it was for: a dispute’s, an incident’s or a regulator’s reference.'),
  })
  .register(API_SCHEMAS, {
    id: 'MyActivityExportByAgentX',
    description: 'An export of your activity log Agent X made for a case: you are always told.',
  });

const PAGE_SCHEMA = {
  summary: 'Your own activity log: every request you made outside an organisation, newest first',
  querystring: z
    .strictObject({
      from: z.iso.datetime().describe('Requests made at or after it.'),
      to: z.iso.datetime().describe('Requests made before it.'),
      before: z.string().max(80).optional().describe('The page starts before this row: the page before’s `next`.'),
      limit: z.coerce
        .number()
        .int()
        .min(1)
        .max(MOST_A_PAGE)
        .optional()
        .describe(
          `How many at most, 1 to ${String(MOST_A_PAGE)}; all ${String(MOST_A_PAGE)} unless fewer are asked for.`,
        ),
    })
    .superRefine((query, context) => {
      if (new Date(query.from).getTime() >= new Date(query.to).getTime()) {
        context.addIssue({ code: 'custom', message: 'the range starts before it ends' });
      }
      if (query.before !== undefined && cursorOf(query.before) === undefined) {
        context.addIssue({ code: 'custom', message: 'before is a page’s `next`' });
      }
    }),
  response: {
    200: z
      .object({
        rows: z.array(MY_ACTIVITY_ROW).describe('Your requests, newest first.'),
        next: z.string().nullable().describe('Where the next page starts before (`before`); null at the end.'),
        sealedThrough: z.iso
          .date()
          .nullable()
          .describe('The newest day sealed, UTC: every request written on or before it is sealed. Null while none is.'),
        exportsByAgentX: z
          .array(MY_ACTIVITY_EXPORT)
          .describe('Agent X’s exports of your activity log for a case, newest first: the latest 20.'),
      })
      .describe('A page of your own activity log.'),
  },
};

const EXPORT_SCHEMA = {
  summary: 'Download your own activity log, as CSV or NDJSON: the download is itself recorded',
  body: z
    .strictObject({
      from: z.iso.datetime().describe('Requests made at or after it.'),
      to: z.iso.datetime().describe('Requests made before it.'),
      format: z.enum(EXPORT_FORMATS).describe('`csv`, for a spreadsheet; `ndjson`, one request a line.'),
    })
    .superRefine((body, context) => {
      const span = new Date(body.to).getTime() - new Date(body.from).getTime();
      if (span <= 0 || span > MOST_EXPORT_DAYS * DAY_MS) {
        context.addIssue({
          code: 'custom',
          message: `the range starts before it ends, ${String(MOST_EXPORT_DAYS)} days at most`,
        });
      }
    })
    .describe('The range to download and the format.'),
  response: {
    201: z
      .object({
        export: z
          .object({
            id: z.uuid().describe('The download’s own record on the platform audit chain.'),
            fileName: z.string().describe('A name to save it as.'),
            contentType: z.enum(Object.values(CONTENT_TYPES)).describe('The file’s type.'),
            content: z.string().describe('The file, whole: its requests newest first.'),
            requests: z.int().min(0).describe('How many requests it holds.'),
          })
          .register(API_SCHEMAS, { id: 'MyActivityExport', description: 'A download of your own activity log.' }),
      })
      .describe('The download, recorded first.'),
  },
};

/** A fact of an export's record as text, or null. */
const textOf = (value: unknown): string | null => (typeof value === 'string' ? value : null);

/** The person's own routes. Without `activity` (a test of other routes) they are still documented, and fail. */
export function registerMyActivity(app: FastifyInstance, { activity }: { activity: MyActivity | undefined }): void {
  const routes = app.withTypeProvider<ZodTypeProvider>();

  routes.get('/v1/auth/activity', { schema: PAGE_SCHEMA, config: { access: ['person'] } }, async (request, reply) => {
    const userId = personOf(request);
    const { from, to, before, limit } = request.query;
    const page = await need(activity).page(
      userId,
      {
        from: new Date(from),
        to: new Date(to),
        before: before === undefined ? undefined : cursorOf(before),
        limit: limit ?? MOST_A_PAGE,
      },
      request.id,
    );
    if (page.outcome === 'refused') return answerRefusal(page, request, reply);
    return {
      rows: page.rows.map((row) => personActivityShown(row, page.sealedDay)),
      next: page.next === null ? null : cursorText(page.next),
      sealedThrough: page.sealedDay,
      exportsByAgentX: page.exports.map(({ id, recordedAt, details }) => ({
        id,
        at: recordedAt.toISOString(),
        from: textOf(details.from),
        to: textOf(details.to),
        requests: typeof details.requests === 'number' ? details.requests : null,
        caseRef: textOf(details.caseRef),
      })),
    };
  });

  routes.post(
    '/v1/auth/activity/exports',
    {
      schema: EXPORT_SCHEMA,
      bodyLimit: EXPORT_BODY_LIMIT,
      config: { access: ['person'], operation: MY_ACTIVITY_EXPORT_OPERATION },
    },
    async (request, reply) => {
      const userId = personOf(request);
      const { body } = request;
      const written = await need(activity).export(
        userId,
        idempotentRequest(request, PERSON_KEYS_TENANT),
        { from: new Date(body.from), to: new Date(body.to), format: body.format },
        request.id,
      );
      if (written.outcome === 'exported') return reply.code(201).send({ export: written.file });
      // Every slot in use, or the person's own build under way: worth sending again shortly.
      if (written.outcome === 'refused' && written.code === 'ACTIVITY_EXPORTS_BUSY') {
        reply.header('retry-after', String(BUSY_RETRY_SECONDS));
      }
      return answerRefusal(written, request, reply);
    },
  );
}
