// Downloading the organisation's audit log (Phase 3 E10b; partner rule S119;
// decision 24: admins only, CSV and NDJSON, each download itself logged, up
// to 12 months a download; at most MOST_EXPORTED_EVENTS events, partner S121).
//
// - `POST /v1/audit-log/exports {from, to, actions?, format}`: the range is
//   counted first, refused past MOST_EXPORTED_EVENTS (AUDIT_EXPORT_TOO_LARGE)
//   with nothing written; an admin's sixth in an hour is AUDIT_EXPORTS_SPENT.
//   Then the download is recorded, `audit_log.exported` about the log, naming
//   the range, the actions, the format, how many events and the newest one's
//   seq, before a byte of it is read: so reading the log out is on the log.
// - Its answer carries the file whole, in the contract's own JSON (the
//   contract writes every answer; it sends no stream of a route's own): the
//   events up to that seq, newest first, read in batches of EXPORT_BATCH,
//   each believed only whole as a page's are (logPageOf). One that can't be is
//   503 INTEGRITY_FAILED, the alarm raised, never a file with it left out. A
//   retry with its key answers the same file, read again to the same seq.
// - NDJSON: one event a line, its facts as an object and its chain hashes, so
//   the links can be checked outside Agent X. CSV: one row an event, its facts
//   as JSON text; every cell a spreadsheet would read as a formula starts
//   with `'` (SEC-EVD-04). The platform's own seals are left out of both, as
//   from a page (factsShown).
// - Each actor is named beside their ID, as on a page (decision 25,
//   actor-names.ts), as at the download: a retry's file holds the same
//   events, its names as the login service has them then.
import {
  actorEventsSince,
  type AuditActor,
  createAuditTrail,
  eventsInRange,
  type LogEvent,
} from '@agentx/core/modules/audit';
import type { DirectoryNames } from '@agentx/core/modules/identity';
import { actionProblems, type Clock, DAY_MS, HOUR_MS, type IdGenerator } from '@agentx/core/shared-kernel';
import { type Database, holdTransactionLock, type IdempotentRequest, isUnwritten } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { memberInSessionOf, need } from './access.ts';
import { API_SCHEMAS } from './api-schemas.ts';
import { type ActorName, createActorNamer } from './actor-names.ts';
import {
  type AuditLogTables,
  AuditLogRefused,
  eventShown,
  factsShown,
  heldLogPage,
  MOST_ACTIONS_FILTERED,
  SEQ,
} from './audit-log.ts';
import { answerRefusal, idempotentRequest } from './idempotent-writes.ts';
import { type Refused, refused } from './refused.ts';
import { createUseCaseWork, type Member } from './use-case-work.ts';

export const EXPORT_OPERATION = 'audit-log.export';

/** The action a download records about the log. */
export const AUDIT_LOG_EXPORTED = 'audit_log.exported';

/** The most events one download holds (partner, S121): a longer range is downloaded in parts. */
const MOST_EXPORTED_EVENTS = 10_000;

/** The longest range one download covers (decision 24: 12 months, a leap year's included). */
const MOST_EXPORT_DAYS = 366;

/** The most downloads one admin makes in an hour. */
const MOST_EXPORTS_AN_HOUR = 5;

/** The advisory lock an admin's downloads count their hourly budget under (ADR-006 §6, 2b). */
export const EXPORTS_LOCK = 'audit-log-exports';

/** How many events one read of the download takes. */
const EXPORT_BATCH = 500;

const EXPORT_FORMATS = ['csv', 'ndjson'] as const;
type ExportFormat = (typeof EXPORT_FORMATS)[number];

const CONTENT_TYPES = { csv: 'text/csv', ndjson: 'application/x-ndjson' } as const satisfies Record<
  ExportFormat,
  string
>;

/** Who may download the log (decision 24). */
const EXPORTING_ROLES = ['admin'] as const;

/** A download as asked for: its range, its actions (all when none), its format. */
export interface ExportAsked {
  readonly from: Date;
  readonly to: Date;
  readonly actions: readonly string[] | undefined;
  readonly format: ExportFormat;
}

/** A download made: its record's ID, its file's name, type and text, how many events, and the newest's seq. */
interface ExportFile {
  readonly id: string;
  readonly fileName: string;
  readonly contentType: (typeof CONTENT_TYPES)[ExportFormat];
  readonly content: string;
  readonly events: number;
  readonly upToSeq: bigint | null;
}

export type ExportWrite =
  | { readonly outcome: 'exported'; readonly file: ExportFile }
  | { readonly outcome: 'conflict' }
  | { readonly outcome: 'busy' }
  | Refused;

export interface AuditLogExports {
  export(
    member: Member,
    idempotent: IdempotentRequest,
    asked: ExportAsked,
    correlationId: string,
  ): Promise<ExportWrite>;
}

/** A CSV cell: quoted, its quotes doubled, and one a spreadsheet would read as a formula made text (SEC-EVD-04). */
export const csvCell = (value: string): string => {
  const text = /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
  return `"${text.replaceAll('"', '""')}"`;
};

const CSV_HEADER = [
  'seq',
  'recordedAt',
  'actorType',
  'actorId',
  'actorName',
  'actorEmail',
  'actorNameFrom',
  'action',
  'subjectType',
  'subjectId',
  'subjectVersion',
  'details',
  'hash',
  'prevHash',
];

/** One event as the file holds it, its actor named. */
const lineOf = (format: ExportFormat, logged: LogEvent, names: ReadonlyMap<string, ActorName>): string => {
  const shown = eventShown(logged, names);
  const facts = Object.fromEntries(factsShown(logged.event.details));
  if (format === 'ndjson') return JSON.stringify({ ...shown, details: facts });
  const { actor, subject } = shown;
  return [shown.seq, shown.recordedAt, actor.type, actor.id, actor.name ?? '', actor.email ?? '', actor.shownFrom ?? '']
    .concat([shown.action, subject.type, subject.id])
    .concat([String(subject.version), JSON.stringify(facts), shown.hash, shown.prevHash])
    .map(csvCell)
    .join(',');
};

/** A day of a range, as the file's name holds it. */
const dayOf = (at: Date): string => at.toISOString().slice(0, 10);

export function createAuditLogExports({
  database,
  keys,
  ids,
  clock,
  logger,
  directory,
  mostEvents = MOST_EXPORTED_EVENTS,
}: {
  readonly database: Database<AuditLogTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly logger: Logger;
  /** The login service's names; undefined when none is set up, and people are named from the kept copy. */
  readonly directory: DirectoryNames | undefined;
  /** The cap, MOST_EXPORTED_EVENTS unless a test sets it lower: ten thousand events are too many to record in one. */
  readonly mostEvents?: number;
}): AuditLogExports {
  const work = createUseCaseWork({ database, keys, ids, logger, Refusal: AuditLogRefused });
  const trail = createAuditTrail({ keys, ids });

  /** The download's file: its events up to `upToSeq`, newest first, a batch to a transaction. */
  const fileOf = async (
    orgId: string,
    id: string,
    asked: ExportAsked,
    upToSeq: bigint | null,
    correlationId: string,
  ) => {
    const lines: string[] = [];
    // One namer for the whole download: once the login service fails, no later batch waits on it.
    const namer = createActorNamer({ directory, logger: logger.child({ correlationId }) });
    let beforeSeq = upToSeq === null ? null : upToSeq + 1n;
    while (beforeSeq !== null) {
      const before = beforeSeq;
      const read = await work.inOrganisation(orgId, correlationId, (tx, states) =>
        heldLogPage(tx, states, keys, orgId, { ...asked, beforeSeq: before, limit: EXPORT_BATCH }),
      );
      const names = await namer.namesOf(read.events, read.held);
      lines.push(...read.events.map((event) => lineOf(asked.format, event, names)));
      beforeSeq = read.next;
    }
    const header = asked.format === 'csv' ? [CSV_HEADER.map(csvCell).join(',')] : [];
    return {
      id,
      fileName: `audit-log-${dayOf(asked.from)}-to-${dayOf(asked.to)}.${asked.format}`,
      contentType: CONTENT_TYPES[asked.format],
      content: `${[...header, ...lines].join('\n')}\n`,
      events: lines.length,
      upToSeq,
    };
  };

  return {
    async export(member, idempotent, asked, correlationId) {
      const actor: AuditActor = { type: 'user', id: member.userId };
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        await work.memberIn(tx, states, member, EXPORTING_ROLES);
        // Under the admin's own download lock (ADR-006 §6, 2b), so their other download in flight commits or rolls back before this counts.
        await holdTransactionLock(tx, EXPORTS_LOCK, member.orgId, member.userId);
        const since = new Date(clock.now().getTime() - HOUR_MS);
        if ((await actorEventsSince(tx, member.orgId, actor, AUDIT_LOG_EXPORTED, since)) >= MOST_EXPORTS_AN_HOUR) {
          throw new AuditLogRefused(409, 'AUDIT_EXPORTS_SPENT');
        }
        const range = await eventsInRange(tx, member.orgId, asked);
        if (range.events > mostEvents) throw new AuditLogRefused(409, 'AUDIT_EXPORT_TOO_LARGE');
        const recorded = await trail.record(tx, member.orgId, {
          actor,
          action: AUDIT_LOG_EXPORTED,
          subject: { type: 'audit_log', id: member.orgId, version: 1 },
          details: {
            from: asked.from.toISOString(),
            to: asked.to.toISOString(),
            actions: asked.actions?.join(',') ?? null,
            format: asked.format,
            events: range.events,
            upToSeq: range.upToSeq?.toString() ?? null,
          },
        });
        return { status: 201, resourceId: recorded.id };
      });
      if (isUnwritten(done)) return done;
      // A retry reads its own record for the seq it was made to, so it answers the same file.
      const id = done.result.resourceId;
      const made = await work.answered(member.orgId, correlationId, async (tx) => {
        const found = await trail.recordedEvent(tx, member.orgId, { eventId: id });
        if (found.kind !== 'recorded') throw new AuditLogRefused(503, 'INTEGRITY_FAILED');
        const upTo = found.event.details.upToSeq;
        return { upToSeq: typeof upTo === 'string' ? BigInt(upTo) : null };
      });
      if ('outcome' in made) return made;
      try {
        return { outcome: 'exported', file: await fileOf(member.orgId, id, asked, made.upToSeq, correlationId) };
      } catch (error) {
        if (error instanceof AuditLogRefused) return refused(error.status, error.code);
        throw error;
      }
    },
  };
}

const EXPORT_SCHEMA = {
  summary: 'Download your organisation’s audit log, as CSV or NDJSON: the download is itself logged',
  body: z
    .strictObject({
      from: z.iso.datetime().describe('Events recorded at or after it.'),
      to: z.iso.datetime().describe('Events recorded before it.'),
      actions: z
        .array(z.string())
        .min(1)
        .max(MOST_ACTIONS_FILTERED)
        .optional()
        .describe(`Only these actions, at most ${String(MOST_ACTIONS_FILTERED)}; every one when left out.`),
      format: z
        .enum(EXPORT_FORMATS)
        .describe(
          '`csv`, for a spreadsheet; `ndjson`, one event a line with its chain hashes, to check outside Agent X.',
        ),
    })
    .superRefine((body, context) => {
      const span = new Date(body.to).getTime() - new Date(body.from).getTime();
      if (span <= 0 || span > MOST_EXPORT_DAYS * DAY_MS) {
        context.addIssue({
          code: 'custom',
          message: `the range starts before it ends, ${String(MOST_EXPORT_DAYS)} days at most`,
        });
      }
      if (!(body.actions ?? []).every((action) => actionProblems(action).length === 0)) {
        context.addIssue({ code: 'custom', message: 'actions are event names' });
      }
    })
    .describe('The range to download, its actions, and the format.'),
  response: {
    201: z
      .object({
        export: z
          .object({
            id: z.uuid().describe('The download’s own record in the log.'),
            fileName: z.string().describe('A name to save it as.'),
            contentType: z.enum(Object.values(CONTENT_TYPES)).describe('The file’s type.'),
            content: z.string().describe('The file, whole: its events newest first.'),
            events: z.int().min(0).describe('How many events it holds.'),
            upToSeq: SEQ.nullable().describe('The newest event it holds; null for none.'),
          })
          .register(API_SCHEMAS, { id: 'AuditLogExport', description: 'A download of the audit log, logged.' }),
      })
      .describe('The download, recorded in the log first.'),
  },
};

/** The most a download's body may be: a range, 20 actions and a format, with room to spare. */
const EXPORT_BODY_LIMIT = 4096;

/** The download's route. Without `exports` it is still documented, and no one reaches it. */
export function registerAuditLogExports(app: FastifyInstance, { exports }: { exports: AuditLogExports | undefined }) {
  const routes = app.withTypeProvider<ZodTypeProvider>();

  routes.post(
    '/v1/audit-log/exports',
    {
      schema: EXPORT_SCHEMA,
      bodyLimit: EXPORT_BODY_LIMIT,
      config: { access: [...EXPORTING_ROLES], operation: EXPORT_OPERATION },
    },
    async (request, reply) => {
      const member = memberInSessionOf(request);
      const { body } = request;
      const written = await need(exports).export(
        member,
        idempotentRequest(request, member.orgId),
        { from: new Date(body.from), to: new Date(body.to), actions: body.actions, format: body.format },
        request.id,
      );
      if (written.outcome !== 'exported') return answerRefusal(written, request, reply);
      const { file } = written;
      return reply.code(201).send({ export: { ...file, upToSeq: file.upToSeq?.toString() ?? null } });
    },
  );
}
