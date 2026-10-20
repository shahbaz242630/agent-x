// A background download's file, downloaded by an organisation's admin (Phase
// 3 L5c; partner decision 31: each download logged):
//
// - `POST /v1/access-log/background-exports/{id}/files/{month}/downloads`:
//   the month's file, once ready and while kept (7 days; then 410
//   ACTIVITY_EXPORT_EXPIRED), recorded first as `access_log.export_downloaded`
//   on the organisation's audit chain, naming the download, the month, the
//   try whose file it is, its size, SHA-256 and how many parts. Answered from
//   that record: the download's ID, a name to save it as, and how to read it.
// - `GET /v1/access-log/background-exports/{id}/downloads/{downloadId}/parts/{n}`:
//   the file a part at a time (4 MiB, base64 inside JSON: the contract
//   refuses raw bytes), for the admin whose download it is, while the file
//   is kept; read from the store exactly where the record says, so every
//   part is of the one file whose SHA-256 the record names. Each part read
//   is a row of the activity log too.
// - The file's try, size and SHA-256 are the ones its signed
//   `access_log.export_file_made` holds (F1, G4): its row, outside the
//   chain, is believed only when it agrees, and one that doesn't raises the
//   alarm and holds the organisation.
//
// The store is reached from the API alone: the container refuses every
// network but the apps' (decision 28), so no link to it is handed out.
import {
  type ActivityExportTables,
  backgroundExportOf,
  type BackgroundExportFile,
  storedName,
} from '@agentx/core/modules/activity';
import { createAuditTrail, type SignedStates } from '@agentx/core/modules/audit';
import { ACTIVITY_EXPORT_DOWNLOADED, ACTIVITY_EXPORT_FILE_MADE } from '@agentx/core/modules/evidence';
import type { IdGenerator } from '@agentx/core/shared-kernel';
import { type Database, type IdempotentRequest, isUnwritten } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import type { BlockStore } from '@agentx/platform/storage';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { memberInSessionOf } from './access.ts';
import { ActivityLogRefused, type ActivityLogTables } from './activity-log.ts';
import { API_SCHEMAS } from './api-schemas.ts';
import { EXPORTING_ROLES } from './audit-log-exports.ts';
import { answerRefusal, idempotentRequest } from './idempotent-writes.ts';
import { type Refused, refused } from './refused.ts';
import { NOTHING, NOTHING_BODY_LIMIT } from './route-schemas.ts';
import { createUseCaseWork, type Member } from './use-case-work.ts';

export const FILE_DOWNLOAD_OPERATION = 'access-log.background-export.download';

/** How large a part of a file one read answers: 4 MiB, some 5.6 MB as base64. */
const PART_BYTES = 4 * 1024 * 1024;

/** A month of a download as a path names it. */
const MONTH = /^\d{4}-(?:0[1-9]|1[0-2])$/;

/** A file's download, as its record holds it. */
export interface FileDownload {
  readonly id: string;
  readonly exportId: string;
  readonly month: string;
  readonly fileName: string;
  readonly contentType: 'application/gzip';
  readonly bytes: number;
  readonly sha256: string;
  readonly parts: number;
  readonly partBytes: number;
}

export type FileDownloadWrite =
  | { readonly outcome: 'started'; readonly download: FileDownload }
  // The key's own answers: a write under way with it (`busy`), or one made of another body (`conflict`).
  | { readonly outcome: 'conflict' }
  | { readonly outcome: 'busy' }
  | Refused;

export interface DownloadFiles {
  start(
    member: Member,
    idempotent: IdempotentRequest,
    file: { readonly exportId: string; readonly month: string },
    correlationId: string,
  ): Promise<FileDownloadWrite>;
  part(
    member: Member,
    part: { readonly exportId: string; readonly downloadId: string; readonly index: number },
    correlationId: string,
  ): Promise<{ readonly outcome: 'part'; readonly index: number; readonly content: Buffer } | Refused>;
}

/** What a download's record holds of its file, read back. */
const RECORDED = z.object({
  exportId: z.uuid(),
  month: z.string().regex(MONTH),
  attempt: z.int().min(1),
  fileName: z.string(),
  bytes: z.int().min(1),
  sha256: z.string().regex(/^[0-9a-f]{64}$/),
  parts: z.int().min(1),
  partBytes: z.int().min(1),
});

const dayOf = (at: Date) => at.toISOString().slice(0, 10);

/** How far from a file's `readyAt` its signed `export_file_made` is looked for: the same transaction recorded both. */
const MADE_WITHIN_MS = 5 * 60_000;

/** How many events a page of that search reads; it pages on until the window is read. */
const MADE_A_PAGE = 50;

/**
 * The ready file as its signed `access_log.export_file_made` holds it (F1,
 * G4): that event's try, size and SHA-256, the row's believed only when they
 * agree. None found, or one that differs, is a row changed past the app:
 * the alarm raised and the organisation held, and 503 INTEGRITY_FAILED.
 */
async function signedFile(
  tx: Parameters<SignedStates['logPageOf']>[0],
  states: SignedStates,
  orgId: string,
  exportId: string,
  file: ReturnType<typeof readyFile>,
) {
  const at = file.readyAt?.getTime() ?? 0;
  const window = { from: new Date(at - MADE_WITHIN_MS), to: new Date(at + MADE_WITHIN_MS) };
  let beforeSeq: bigint | undefined;
  for (;;) {
    const page = await states.logPageOf(tx, orgId, {
      ...window,
      actions: [ACTIVITY_EXPORT_FILE_MADE],
      beforeSeq,
      limit: MADE_A_PAGE,
    });
    if (page.outcome === 'tampered') throw new ActivityLogRefused(503, 'INTEGRITY_FAILED');
    const made = page.events.find(
      ({ event }) =>
        event.details.exportId === exportId &&
        event.details.month === file.month &&
        event.details.attempt === file.attempts,
    )?.event.details;
    if (made !== undefined) {
      if (made.bytes !== file.bytes || made.sha256 !== file.sha256 || made.requests !== file.requests) break;
      return file;
    }
    if (page.next === null) break;
    beforeSeq = page.next;
  }
  states.mismatch('access_log', { orgId, id: orgId });
  throw new ActivityLogRefused(503, 'INTEGRITY_FAILED');
}

/** The month's file of a ready download, or why it can't be downloaded. */
function readyFile(
  download: { readonly state: string; readonly files: readonly BackgroundExportFile[] },
  month: string,
) {
  const file = download.files.find((each) => each.month === month);
  if (file === undefined) throw new ActivityLogRefused(404, 'NOT_FOUND');
  if (download.state === 'expired') throw new ActivityLogRefused(410, 'ACTIVITY_EXPORT_EXPIRED');
  if (download.state !== 'ready' || file.bytes === null || file.sha256 === null) {
    throw new ActivityLogRefused(409, 'ACTIVITY_EXPORT_NOT_READY');
  }
  return { ...file, bytes: file.bytes, sha256: file.sha256 };
}

export function createDownloadFiles({
  database,
  keys,
  ids,
  store,
  logger,
  partBytes = PART_BYTES,
}: {
  readonly database: Database<ActivityLogTables & ActivityExportTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly store: BlockStore;
  readonly logger: Logger;
  /** PART_BYTES, but for the tests. */
  readonly partBytes?: number;
}): DownloadFiles {
  const work = createUseCaseWork({ database, keys, ids, logger, Refusal: ActivityLogRefused });
  type DownloadTx = Parameters<SignedStates['eventOf']>[0];

  /** The download's record, whole and this admin's, with what it holds of its file; one that can't be believed raises the alarm (G2). */
  const recordOf = async (
    tx: DownloadTx,
    states: SignedStates,
    member: Member,
    downloadId: string,
  ): Promise<z.infer<typeof RECORDED>> => {
    const found = await states.eventOf(tx, member.orgId, { eventId: downloadId });
    if (found.outcome === 'tampered') throw new ActivityLogRefused(503, 'INTEGRITY_FAILED');
    const event = found.event?.event;
    const recorded = RECORDED.safeParse(event?.details);
    if (
      event?.action !== ACTIVITY_EXPORT_DOWNLOADED ||
      event.actor.type !== 'user' ||
      event.actor.id !== member.userId ||
      !recorded.success
    ) {
      throw new ActivityLogRefused(404, 'NOT_FOUND');
    }
    return recorded.data;
  };

  return {
    async start(member, idempotent, { exportId, month }, correlationId) {
      const done = await work.write(member, idempotent, correlationId, async (tx, states) => {
        await work.memberIn(tx, states, member, EXPORTING_ROLES);
        const download = await backgroundExportOf(tx, member.orgId, exportId);
        if (download === undefined) throw new ActivityLogRefused(404, 'NOT_FOUND');
        const file = await signedFile(tx, states, member.orgId, exportId, readyFile(download, month));
        const recorded = await createAuditTrail({ keys, ids, correlationId }).record(tx, member.orgId, {
          actor: { type: 'user', id: member.userId },
          action: ACTIVITY_EXPORT_DOWNLOADED,
          subject: { type: 'access_log', id: member.orgId, version: 1 },
          details: {
            exportId,
            month,
            attempt: file.attempts,
            fileName: `activity-log-${dayOf(download.from)}-to-${dayOf(download.to)}-${month}.${download.format}.gz`,
            bytes: file.bytes,
            sha256: file.sha256,
            parts: Math.ceil(file.bytes / partBytes),
            partBytes,
          },
        });
        return { status: 201, resourceId: recorded.id };
      });
      if (isUnwritten(done)) return done;
      // Answered from the record, so a retry with its key answers the same download.
      const id = done.result.resourceId;
      const read = await work.answered(member.orgId, correlationId, async (tx, states) => ({
        recorded: await recordOf(tx, states, member, id),
      }));
      if ('outcome' in read) return read;
      const { attempt: _attempt, ...shown } = read.recorded;
      return { outcome: 'started', download: { id, ...shown, contentType: 'application/gzip' } };
    },

    async part(member, { exportId, downloadId, index }, correlationId) {
      const read = await work.answered(member.orgId, correlationId, async (tx, states) => {
        await work.memberIn(tx, states, member, EXPORTING_ROLES);
        const recorded = await recordOf(tx, states, member, downloadId);
        if (recorded.exportId !== exportId || index >= recorded.parts) throw new ActivityLogRefused(404, 'NOT_FOUND');
        // Still kept: a download started before its file expired reads nothing after.
        const download = await backgroundExportOf(tx, member.orgId, exportId);
        if (download === undefined) throw new ActivityLogRefused(404, 'NOT_FOUND');
        readyFile(download, recorded.month);
        return { recorded, format: download.format };
      });
      if ('outcome' in read) return read;
      const { recorded, format } = read;
      const offset = index * recorded.partBytes;
      const length = Math.min(recorded.partBytes, recorded.bytes - offset);
      const name = storedName(member.orgId, {
        exportId,
        month: `${recorded.month}-01`,
        attempt: recorded.attempt,
        format,
      });
      try {
        const content = await store.read(name, offset, length);
        if (content.length !== length) throw new RangeError('the store answered another length than its file holds');
        return { outcome: 'part', index, content };
      } catch (error) {
        logger
          .child({ correlationId, orgId: member.orgId })
          .warn('access_log.export_read_failed', { exportId, month: recorded.month, index, err: error });
        return refused(503, 'ACTIVITY_EXPORT_UNREADABLE');
      }
    },
  };
}

const DOWNLOAD = z
  .object({
    id: z.uuid().describe('The download, by its record in the audit log: name it to read each part.'),
    exportId: z.uuid().describe('The background download it is a file of.'),
    month: z.string().describe('The UTC month the file holds, YYYY-MM.'),
    fileName: z.string().describe('A name to save it as.'),
    contentType: z.literal('application/gzip').describe('The file’s type: gzip-compressed CSV or NDJSON.'),
    bytes: z.int().min(1).describe('The file’s size.'),
    sha256: z.string().describe('The file’s SHA-256 (hex): check the parts joined against it.'),
    parts: z.int().min(1).describe('How many parts to read, from 0.'),
    partBytes: z.int().min(1).describe('The size of every part but the last.'),
  })
  .register(API_SCHEMAS, {
    id: 'ActivityLogFileDownload',
    description: 'A download of one file of a background download, on the audit log.',
  });

const START_SCHEMA = {
  summary: 'Download one month’s file of a background download of your activity log: the download is on the audit log',
  params: z.object({
    id: z.uuid().describe('The background download, by its ID.'),
    month: z.string().regex(MONTH).describe('The UTC month of its file, YYYY-MM.'),
  }),
  body: NOTHING,
  response: {
    201: z.object({ download: DOWNLOAD }).describe('The download, recorded on the audit log, and how to read it.'),
  },
};

const PART_SCHEMA = {
  summary: 'One part of a file downloaded, as base64',
  params: z.object({
    id: z.uuid().describe('The background download, by its ID.'),
    downloadId: z.uuid().describe('Your download of its file, by its ID.'),
    index: z.coerce.number().int().min(0).max(50_000).describe('Which part, from 0.'),
  }),
  response: {
    200: z
      .object({
        part: z.object({
          index: z.int().min(0).describe('Which part it is.'),
          content: z.string().describe('Its bytes, base64.'),
        }),
      })
      .describe('The part.'),
  },
};

/** The file download routes; without `files` (no store set up) each answers NOT_FOUND. */
export function registerDownloadFiles(app: FastifyInstance, { files }: { files: DownloadFiles | undefined }): void {
  const routes = app.withTypeProvider<ZodTypeProvider>();
  const off = refused(404, 'NOT_FOUND');

  routes.post(
    '/v1/access-log/background-exports/:id/files/:month/downloads',
    {
      schema: START_SCHEMA,
      bodyLimit: NOTHING_BODY_LIMIT,
      config: { access: [...EXPORTING_ROLES], operation: FILE_DOWNLOAD_OPERATION },
    },
    async (request, reply) => {
      if (files === undefined) return answerRefusal(off, request, reply);
      const member = memberInSessionOf(request);
      const { id, month } = request.params;
      const written = await files.start(
        member,
        idempotentRequest(request, member.orgId),
        { exportId: id.toLowerCase(), month },
        request.id,
      );
      if (written.outcome !== 'started') return answerRefusal(written, request, reply);
      return reply.code(201).send({ download: written.download });
    },
  );

  routes.get(
    '/v1/access-log/background-exports/:id/downloads/:downloadId/parts/:index',
    { schema: PART_SCHEMA, config: { access: [...EXPORTING_ROLES] } },
    async (request, reply) => {
      if (files === undefined) return answerRefusal(off, request, reply);
      const member = memberInSessionOf(request);
      const { id, downloadId, index } = request.params;
      const part = await files.part(
        member,
        { exportId: id.toLowerCase(), downloadId: downloadId.toLowerCase(), index },
        request.id,
      );
      if (part.outcome !== 'part') return answerRefusal(part, request, reply);
      return { part: { index: part.index, content: part.content.toString('base64') } };
    },
  );
}
