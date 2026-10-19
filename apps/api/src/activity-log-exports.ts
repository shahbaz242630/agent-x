// Downloading the organisation's activity log (Phase 3 L5; decision 26:
// admins only), as the audit log's own download is made (audit-log-exports.ts):
//
// - `POST /v1/access-log/exports {from, to, actor?, format}`: up to 12
//   months, the range counted first and refused past MOST_EXPORTED_REQUESTS
//   (ACTIVITY_EXPORT_TOO_LARGE) with nothing written; an admin's sixth in an
//   hour is ACTIVITY_EXPORTS_SPENT. Then the download is recorded,
//   `access_log.exported` on the organisation's audit chain, naming the
//   range, the actor, the format, how many requests and the last of them
//   written, before a row is read: so reading the activity log out is on the
//   audit log.
// - Its answer carries the file whole: the requests written by the count
//   (activityInRange), newest first, read in batches of EXPORT_BATCH; a retry
//   with its key reads the same ones again.
// - One download of the activity log is built at a time on a server
//   (MOST_BUILDING): 50,000 requests take some 200 MB while their file is
//   made. Another asked meanwhile is ACTIVITY_EXPORTS_BUSY, nothing logged.
//   A longer range is a background download (decision 31, L5c).
// - NDJSON: one request a line, as a page shows it. CSV: one row a request,
//   every cell a spreadsheet would read as a formula made text (SEC-EVD-04).
//   Both credit DB-IP beside every place (CC BY 4.0).
import {
  ACTIVITY_ACTOR_TYPES,
  type ActivityActor,
  type ActivityCursor,
  activityInRange,
} from '@agentx/core/modules/activity';
import { createAuditTrail } from '@agentx/core/modules/audit';
import {
  activityActorsOf,
  ACTIVITY_EXPORT_REQUESTED,
  ACTIVITY_LOG_EXPORTED,
  createActorNamer,
  EXPORT_BATCH,
  type HeldActivityPage,
  MOST_EXPORT_DAYS,
  MOST_EXPORTED_REQUESTS,
} from '@agentx/core/modules/evidence';
import type { DirectoryNames } from '@agentx/core/modules/identity';
import { type Clock, DAY_MS, type IdGenerator } from '@agentx/core/shared-kernel';
import { type Database, type IdempotentRequest, isUnwritten } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { memberInSessionOf, need } from './access.ts';
import { ACTIVITY_CSV_HEADER, activityLineOf } from './activity-lines.ts';
import { ActivityLogRefused, type ActivityLogTables, heldActivity } from './activity-log.ts';
import { API_SCHEMAS } from './api-schemas.ts';
import {
  CONTENT_TYPES,
  EXPORT_BODY_LIMIT,
  EXPORT_FORMATS,
  exportFile,
  type ExportFormat,
  EXPORTING_ROLES,
  exportsSpent,
} from './audit-log-exports.ts';
import { answerRefusal, idempotentRequest } from './idempotent-writes.ts';
import { type Refused, refused } from './refused.ts';
import { createUseCaseWork, type Member } from './use-case-work.ts';

export const ACTIVITY_EXPORT_OPERATION = 'access-log.export';

/** The advisory lock an admin's activity log downloads count their hourly budget under (ADR-006 §6, 2b). */
export const ACTIVITY_EXPORTS_LOCK = 'access-log-exports';

/** The downloads of the activity log an admin's hourly budget counts: instant and background alike (decision 31). */
export const ACTIVITY_DOWNLOAD_ACTIONS = [ACTIVITY_LOG_EXPORTED, ACTIVITY_EXPORT_REQUESTED];

/** How many activity log downloads one server builds at once: each holds its whole file in memory. */
const MOST_BUILDING = 1;

/** A download as asked for: its range, its actor (everyone when none), its format. */
export interface ActivityExportAsked {
  readonly from: Date;
  readonly to: Date;
  readonly actor: ActivityActor | undefined;
  readonly format: ExportFormat;
}

/** A download made: its record's ID, its file's name, type and text, and how many requests. */
interface ActivityExportFile {
  readonly id: string;
  readonly fileName: string;
  readonly contentType: (typeof CONTENT_TYPES)[ExportFormat];
  readonly content: string;
  readonly requests: number;
}

export type ActivityExportWrite =
  | { readonly outcome: 'exported'; readonly file: ActivityExportFile }
  | { readonly outcome: 'conflict' }
  | { readonly outcome: 'busy' }
  | Refused;

export interface ActivityLogExports {
  export(
    member: Member,
    idempotent: IdempotentRequest,
    asked: ActivityExportAsked,
    correlationId: string,
  ): Promise<ActivityExportWrite>;
}

export function createActivityLogExports({
  database,
  keys,
  ids,
  clock,
  logger,
  directory,
  mostRequests = MOST_EXPORTED_REQUESTS,
}: {
  readonly database: Database<ActivityLogTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly logger: Logger;
  /** The login service's names; undefined when none is set up, and people are named from the kept copy. */
  readonly directory: DirectoryNames | undefined;
  /** The cap, MOST_EXPORTED_REQUESTS unless a test sets it lower: 50,000 requests are too many to write in a test. */
  readonly mostRequests?: number;
}): ActivityLogExports {
  const work = createUseCaseWork({ database, keys, ids, logger, Refusal: ActivityLogRefused });
  const trail = createAuditTrail({ keys, ids });
  let building = 0;

  /** The download's file: its requests written up to `writtenUpTo`, newest first, a batch to a transaction. */
  const fileOf = async (
    orgId: string,
    id: string,
    asked: ActivityExportAsked,
    writtenUpTo: string | null,
    correlationId: string,
  ) => {
    const lines: string[] = [];
    // One namer for the whole download: once the login service fails, no later batch waits on it.
    const namer = createActorNamer({ directory, logger: logger.child({ correlationId }) });
    // undefined: the first batch, from the newest; null: none left.
    let before: ActivityCursor | null | undefined = undefined;
    while (writtenUpTo !== null && before !== null) {
      const start = before;
      const read: HeldActivityPage = await work.inOrganisation(orgId, correlationId, (tx, states) =>
        heldActivity(tx, states, keys, orgId, { ...asked, before: start, writtenUpTo, limit: EXPORT_BATCH }),
      );
      const names = await namer.namesOf(activityActorsOf(read.rows), read.held);
      for (const row of read.rows) lines.push(activityLineOf(asked.format, row, names));
      before = read.next;
    }
    const requests = lines.length;
    return { id, ...exportFile('activity', asked, ACTIVITY_CSV_HEADER, lines), requests };
  };

  /** The download, recorded on the audit log first, then its file. */
  const exported = async (
    member: Member,
    idempotent: IdempotentRequest,
    asked: ActivityExportAsked,
    correlationId: string,
  ): Promise<ActivityExportWrite> => {
    const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
      await work.memberIn(tx, states, member, EXPORTING_ROLES);
      if (await exportsSpent(tx, clock, member, { lock: ACTIVITY_EXPORTS_LOCK, actions: ACTIVITY_DOWNLOAD_ACTIONS })) {
        throw new ActivityLogRefused(409, 'ACTIVITY_EXPORTS_SPENT');
      }
      const range = await activityInRange(tx, member.orgId, asked);
      if (range.rows > mostRequests) throw new ActivityLogRefused(409, 'ACTIVITY_EXPORT_TOO_LARGE');
      const recorded = await createAuditTrail({ keys, ids, correlationId }).record(tx, member.orgId, {
        actor: { type: 'user', id: member.userId },
        action: ACTIVITY_LOG_EXPORTED,
        subject: { type: 'access_log', id: member.orgId, version: 1 },
        details: {
          from: asked.from.toISOString(),
          to: asked.to.toISOString(),
          actor: asked.actor === undefined ? null : `${asked.actor.type}:${asked.actor.id}`,
          format: asked.format,
          requests: range.rows,
          writtenUpTo: range.writtenUpTo,
        },
      });
      return { status: 201, resourceId: recorded.id };
    });
    if (isUnwritten(done)) return done;
    // A retry reads its own record for the last row it was made to, so it answers the same requests.
    const id = done.result.resourceId;
    const made = await work.answered(member.orgId, correlationId, async (tx) => {
      const found = await trail.recordedEvent(tx, member.orgId, { eventId: id });
      if (found.kind !== 'recorded') throw new ActivityLogRefused(503, 'INTEGRITY_FAILED');
      const { writtenUpTo } = found.event.details;
      return { writtenUpTo: typeof writtenUpTo === 'string' ? writtenUpTo : null };
    });
    if ('outcome' in made) return made;
    try {
      return { outcome: 'exported', file: await fileOf(member.orgId, id, asked, made.writtenUpTo, correlationId) };
    } catch (error) {
      if (error instanceof ActivityLogRefused) return refused(error.status, error.code);
      throw error;
    }
  };

  return {
    async export(member, idempotent, asked, correlationId) {
      if (building >= MOST_BUILDING) return refused(503, 'ACTIVITY_EXPORTS_BUSY');
      building += 1;
      try {
        return await exported(member, idempotent, asked, correlationId);
      } finally {
        building -= 1;
      }
    },
  };
}

const EXPORT_SCHEMA = {
  summary: 'Download your organisation’s activity log, as CSV or NDJSON: the download is itself on the audit log',
  body: z
    .strictObject({
      from: z.iso.datetime().describe('Requests made at or after it.'),
      to: z.iso.datetime().describe('Requests made before it.'),
      actor: z
        .strictObject({
          type: z.enum(ACTIVITY_ACTOR_TYPES).describe('A person or an AI agent.'),
          id: z.uuid().describe('Their Agent X ID.'),
        })
        .optional()
        .describe('Only requests by this person or agent; everyone’s when left out.'),
      format: z
        .enum(EXPORT_FORMATS)
        .describe('`csv`, for a spreadsheet; `ndjson`, one request a line, as a page shows it.'),
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
    .describe('The range to download, its actor, and the format.'),
  response: {
    201: z
      .object({
        export: z
          .object({
            id: z.uuid().describe('The download’s own record in the audit log.'),
            fileName: z.string().describe('A name to save it as.'),
            contentType: z.enum(Object.values(CONTENT_TYPES)).describe('The file’s type.'),
            content: z.string().describe('The file, whole: its requests newest first.'),
            requests: z.int().min(0).describe('How many requests it holds.'),
          })
          .register(API_SCHEMAS, {
            id: 'ActivityLogExport',
            description: 'A download of the activity log, on the audit log.',
          }),
      })
      .describe('The download, recorded on the audit log first.'),
  },
};

/** The download's route. Without `exports` it is still documented, and no one reaches it. */
export function registerActivityLogExports(
  app: FastifyInstance,
  { exports }: { exports: ActivityLogExports | undefined },
) {
  const routes = app.withTypeProvider<ZodTypeProvider>();

  routes.post(
    '/v1/access-log/exports',
    {
      schema: EXPORT_SCHEMA,
      bodyLimit: EXPORT_BODY_LIMIT,
      config: { access: [...EXPORTING_ROLES], operation: ACTIVITY_EXPORT_OPERATION },
    },
    async (request, reply) => {
      const member = memberInSessionOf(request);
      const { body } = request;
      const written = await need(exports).export(
        member,
        idempotentRequest(request, member.orgId),
        {
          from: new Date(body.from),
          to: new Date(body.to),
          actor: body.actor === undefined ? undefined : { type: body.actor.type, id: body.actor.id.toLowerCase() },
          format: body.format,
        },
        request.id,
      );
      if (written.outcome !== 'exported') return answerRefusal(written, request, reply);
      return reply.code(201).send({ export: written.file });
    },
  );
}
