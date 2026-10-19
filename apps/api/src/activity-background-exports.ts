// The activity log's background downloads, asked for and followed by an
// organisation's admins (Phase 3 L5c; partner decision 31):
//
// - `POST /v1/access-log/background-exports {from, to, actor?, format}`: up
//   to 366 days, however many requests; recorded first as
//   `access_log.export_requested` on the organisation's audit chain (the
//   download's ID is the event's), naming the range, the actor, the format,
//   its months and the newest request written then, beyond which none is in
//   it. The same hourly budget as an instant download (5, shared); one still
//   being built at a time an organisation (ACTIVITY_EXPORT_UNDER_WAY).
//   Answered 202: the download is built in the background, a UTC month a file
//   (activity-export-builder.ts), and the admin who asked is told by email
//   once it is ready, in words alone (decision 30).
// - `GET /v1/access-log/background-exports[?before][&limit]` and
//   `GET /v1/access-log/background-exports/{id}`: each download, newest
//   first: building, ready (kept 7 days from its last file), expired or
//   failed, each month's file with its count, size and SHA-256 once ready.
//   This is the notice in the app: the Phase 6 console shows it.
//
// With no download store set up (AGENTX_ACTIVITY_DOWNLOADS_*) the routes are
// documented and answer NOT_FOUND: the feature is not available there.
import {
  ACTIVITY_ACTOR_TYPES,
  type ActivityExportTables,
  addBackgroundExport,
  type BackgroundExport,
  backgroundExportOf,
  backgroundExportsOf,
  DOWNLOAD_FORMATS,
  type DownloadFormat,
  downloadUnderWay,
  monthsOf,
  newestWritten,
} from '@agentx/core/modules/activity';
import { createAuditTrail } from '@agentx/core/modules/audit';
import { ACTIVITY_EXPORT_REQUESTED, MOST_EXPORT_DAYS } from '@agentx/core/modules/evidence';
import { type Clock, DAY_MS, type IdGenerator } from '@agentx/core/shared-kernel';
import { type Database, type IdempotentRequest, isUnwritten } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { memberInSessionOf } from './access.ts';
import { ACTIVITY_DOWNLOAD_ACTIONS, ACTIVITY_EXPORTS_LOCK } from './activity-log-exports.ts';
import { ActivityLogRefused, type ActivityLogTables } from './activity-log.ts';
import { API_SCHEMAS } from './api-schemas.ts';
import { EXPORT_BODY_LIMIT, EXPORTING_ROLES, exportsSpent } from './audit-log-exports.ts';
import { answerRefusal, idempotentRequest } from './idempotent-writes.ts';
import { type Refused, refused } from './refused.ts';
import { createUseCaseWork, type Member } from './use-case-work.ts';

export const BACKGROUND_EXPORT_OPERATION = 'access-log.background-export';

/** The most downloads a page of the list holds. */
const MOST_A_PAGE = 20;

/** A download as asked for: its range, its actor (everyone when none), its format. */
export interface BackgroundExportAskedFor {
  readonly from: Date;
  readonly to: Date;
  readonly actor: { readonly type: (typeof ACTIVITY_ACTOR_TYPES)[number]; readonly id: string } | undefined;
  readonly format: DownloadFormat;
}

export type BackgroundExportWrite =
  | { readonly outcome: 'asked'; readonly download: BackgroundExport }
  // The key's own answers: a write under way with it (`busy`), or one made of another body (`conflict`).
  | { readonly outcome: 'conflict' }
  | { readonly outcome: 'busy' }
  | Refused;

export interface BackgroundExports {
  ask(
    member: Member,
    idempotent: IdempotentRequest,
    asked: BackgroundExportAskedFor,
    correlationId: string,
  ): Promise<BackgroundExportWrite>;
  list(
    orgId: string,
    page: { readonly before: string | undefined; readonly limit: number },
    correlationId: string,
  ): Promise<{ readonly downloads: readonly BackgroundExport[]; readonly next: string | null } | Refused>;
  one(orgId: string, id: string, correlationId: string): Promise<BackgroundExport | undefined | Refused>;
}

type BackgroundExportTables = ActivityLogTables & ActivityExportTables;

export function createBackgroundExports({
  database,
  keys,
  ids,
  clock,
  logger,
}: {
  readonly database: Database<BackgroundExportTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly logger: Logger;
}): BackgroundExports {
  const work = createUseCaseWork({ database, keys, ids, logger, Refusal: ActivityLogRefused });

  /** The download as it stands, read after its write committed. */
  const downloadOf = async (orgId: string, id: string, correlationId: string) => {
    const read = await work.answered(orgId, correlationId, async (tx) => ({
      download: await backgroundExportOf(tx, orgId, id),
    }));
    if ('outcome' in read) return read;
    if (read.download === undefined) return refused(503, 'INTEGRITY_FAILED');
    return { outcome: 'asked' as const, download: read.download };
  };

  return {
    async ask(member, idempotent, asked, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        await work.memberIn(tx, states, member, EXPORTING_ROLES);
        if (
          await exportsSpent(tx, clock, member, { lock: ACTIVITY_EXPORTS_LOCK, actions: ACTIVITY_DOWNLOAD_ACTIONS })
        ) {
          throw new ActivityLogRefused(409, 'ACTIVITY_EXPORTS_SPENT');
        }
        if (await downloadUnderWay(tx, member.orgId)) throw new ActivityLogRefused(409, 'ACTIVITY_EXPORT_UNDER_WAY');
        const writtenUpTo = await newestWritten(tx, member.orgId);
        const recorded = await createAuditTrail({ keys, ids, correlationId }).record(tx, member.orgId, {
          actor: { type: 'user', id: member.userId },
          action: ACTIVITY_EXPORT_REQUESTED,
          subject: { type: 'access_log', id: member.orgId, version: 1 },
          details: {
            from: asked.from.toISOString(),
            to: asked.to.toISOString(),
            actor: asked.actor === undefined ? null : `${asked.actor.type}:${asked.actor.id}`,
            format: asked.format,
            months: monthsOf(asked).length,
            writtenUpTo,
          },
        });
        await addBackgroundExport(tx, member.orgId, {
          ...asked,
          id: recorded.id,
          requestedBy: member.userId,
          writtenUpTo,
        });
        return { status: 202, resourceId: recorded.id };
      });
      if (isUnwritten(done)) return done;
      return downloadOf(member.orgId, done.result.resourceId, correlationId);
    },

    async list(orgId, page, correlationId) {
      return work.answered(orgId, correlationId, (tx) => backgroundExportsOf(tx, orgId, page));
    },

    async one(orgId, id, correlationId) {
      const read = await work.answered(orgId, correlationId, async (tx) => ({
        download: await backgroundExportOf(tx, orgId, id),
      }));
      return 'outcome' in read ? read : read.download;
    },
  };
}

const FILE = z
  .object({
    month: z.string().describe('The UTC month it holds, YYYY-MM: the first and last cut to the range.'),
    state: z
      .enum(['waiting', 'building', 'ready', 'failed'])
      .describe('`waiting` to be built, `building`, `ready` to download, or `failed`.'),
    requests: z.int().min(0).nullable().describe('How many requests it holds, once ready.'),
    bytes: z.int().min(1).nullable().describe('Its size, compressed, once ready.'),
    sha256: z.string().nullable().describe('Its SHA-256 (hex), once ready, as its audit event records it.'),
  })
  .describe('One month of the download: one gzip-compressed file.');

const DOWNLOAD = z
  .object({
    id: z.uuid().describe('The download, by its record in the audit log.'),
    requestedBy: z.uuid().describe('The admin who asked for it.'),
    requestedAt: z.iso.datetime().describe('When it was asked for.'),
    from: z.iso.datetime().describe('Requests made at or after it.'),
    to: z.iso.datetime().describe('Requests made before it.'),
    actor: z
      .object({ type: z.enum(ACTIVITY_ACTOR_TYPES), id: z.uuid() })
      .nullable()
      .describe('Only this person’s or agent’s requests; null for everyone’s.'),
    format: z.enum(DOWNLOAD_FORMATS).describe('`csv` or `ndjson`, each file gzip-compressed.'),
    state: z
      .enum(['building', 'ready', 'expired', 'failed'])
      .describe('`building`; `ready` to download until `expiresAt`; `expired`, deleted; or `failed`, to ask again.'),
    expiresAt: z.iso.datetime().nullable().describe('When it is, or was, deleted: 7 days after it was ready.'),
    files: z.array(FILE).describe('Its months, oldest first.'),
  })
  .register(API_SCHEMAS, {
    id: 'ActivityLogBackgroundExport',
    description: 'A background download of the activity log, a month a file, on the audit log.',
  });

/** A download as the API answers it. */
const shown = (download: BackgroundExport) => ({
  id: download.id,
  requestedBy: download.requestedBy,
  requestedAt: download.requestedAt.toISOString(),
  from: download.from.toISOString(),
  to: download.to.toISOString(),
  actor: download.actor,
  format: download.format,
  state: download.state,
  expiresAt: download.expiresAt?.toISOString() ?? null,
  files: download.files.map(({ month, state, requests, bytes, sha256 }) => ({ month, state, requests, bytes, sha256 })),
});

const ASK_SCHEMA = {
  summary: 'Ask for a long range of your organisation’s activity log, built in the background a month a file',
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
        .enum(DOWNLOAD_FORMATS)
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
    202: z.object({ download: DOWNLOAD }).describe('The download, recorded on the audit log, to be built.'),
  },
};

const LIST_SCHEMA = {
  summary: 'Your organisation’s background downloads of the activity log, newest first',
  querystring: z.strictObject({
    before: z.uuid().optional().describe('The page starts after this download: the page before’s `next`.'),
    limit: z.coerce
      .number()
      .int()
      .min(1)
      .max(MOST_A_PAGE)
      .optional()
      .describe(
        `How many at most, 1 to ${String(MOST_A_PAGE)}; all ${String(MOST_A_PAGE)} unless fewer are asked for.`,
      ),
  }),
  response: {
    200: z
      .object({
        downloads: z.array(DOWNLOAD).describe('The downloads, newest first.'),
        next: z.uuid().nullable().describe('Where the next page starts after (`before`); null at the end.'),
      })
      .describe('A page of the background downloads.'),
  },
};

const ONE_SCHEMA = {
  summary: 'One background download of your organisation’s activity log, with its files',
  params: z.object({ id: z.uuid().describe('The download, by its ID.') }),
  response: { 200: z.object({ download: DOWNLOAD }).describe('The download as it stands.') },
};

/** The background downloads' routes; without `downloads` (no store set up) each answers NOT_FOUND. */
export function registerBackgroundExports(
  app: FastifyInstance,
  { downloads }: { downloads: BackgroundExports | undefined },
): void {
  const routes = app.withTypeProvider<ZodTypeProvider>();
  const off = refused(404, 'NOT_FOUND');

  routes.post(
    '/v1/access-log/background-exports',
    {
      schema: ASK_SCHEMA,
      bodyLimit: EXPORT_BODY_LIMIT,
      config: { access: [...EXPORTING_ROLES], operation: BACKGROUND_EXPORT_OPERATION },
    },
    async (request, reply) => {
      if (downloads === undefined) return answerRefusal(off, request, reply);
      const member = memberInSessionOf(request);
      const { body } = request;
      const written = await downloads.ask(
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
      if (written.outcome !== 'asked') return answerRefusal(written, request, reply);
      return reply.code(202).send({ download: shown(written.download) });
    },
  );

  routes.get(
    '/v1/access-log/background-exports',
    { schema: LIST_SCHEMA, config: { access: [...EXPORTING_ROLES] } },
    async (request, reply) => {
      if (downloads === undefined) return answerRefusal(off, request, reply);
      const { orgId } = memberInSessionOf(request);
      const { before, limit } = request.query;
      const page = await downloads.list(
        orgId,
        { before: before?.toLowerCase(), limit: limit ?? MOST_A_PAGE },
        request.id,
      );
      if ('outcome' in page) return answerRefusal(page, request, reply);
      return { downloads: page.downloads.map(shown), next: page.next };
    },
  );

  routes.get(
    '/v1/access-log/background-exports/:id',
    { schema: ONE_SCHEMA, config: { access: [...EXPORTING_ROLES] } },
    async (request, reply) => {
      if (downloads === undefined) return answerRefusal(off, request, reply);
      const { orgId } = memberInSessionOf(request);
      const download = await downloads.one(orgId, request.params.id.toLowerCase(), request.id);
      if (download === undefined) return answerRefusal(off, request, reply);
      if ('outcome' in download) return answerRefusal(download, request, reply);
      return { download: shown(download) };
    },
  );
}
