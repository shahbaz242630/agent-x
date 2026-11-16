// The organisation's two logs as the console reads them (6C2; decision 24 and
// 26: admins only): the audit log (GET /v1/audit-log), every signed event,
// filtered by date, action, actor and object (CO7), and the access log (GET
// /v1/access-log), every request its people and agents made, filtered by date
// and actor. Both newest first, a page at a time, the filters kept in the
// page's own address (as 6C1's `?status=`), so a reload, a link or a step-up
// keeps them. Each downloads as CSV or NDJSON (POST .../exports, each download
// itself logged); an access log range past the instant download's cap is built
// in the background, a month a file (decision 31), and read here a part at a
// time. The shapes are the contract's (audit-log.ts, activity-log.ts and their
// exports in the API); the console only shows them.
import { useInfiniteQuery, useQuery } from '@tanstack/react-query';

import { api, ApiError, isIntegrityFailed, isRefusal } from './api.ts';
import { saveFile } from './download.ts';
import { refusalText } from './refusals.ts';
import { t, type TextKey } from './text.ts';

/** Who an event or a request was by, as the API names them (decision 25). */
export interface Actor {
  readonly type: 'user' | 'agent' | 'system';
  readonly id: string;
  readonly name: string | null;
  readonly email: string | null;
}

/** One signed event of the audit log (AuditLogEvent): the platform's own seals left out, its chain hashes kept. */
export interface LogEvent {
  readonly seq: string;
  readonly id: string;
  readonly recordedAt: string;
  readonly actor: Actor;
  readonly action: string;
  readonly subject: { readonly type: string; readonly id: string; readonly version: number };
  readonly details: readonly { readonly name: string; readonly value: string | number | boolean | null }[];
  readonly hash: string;
  readonly prevHash: string;
}

/** One request of the access log (ActivityLogRow): what its client says of where it may be are clues, never proof. */
export interface ActivityRow {
  readonly id: string;
  readonly recordedAt: string;
  readonly localTime: string | null;
  readonly actor: Actor;
  readonly method: string;
  readonly route: string;
  readonly pathIds: readonly string[];
  readonly status: number;
  readonly reason: string | null;
  readonly correlationId: string;
  readonly sealed: boolean;
  readonly client: {
    readonly ip: string | null;
    readonly place: {
      readonly country: string;
      readonly city: string | null;
      readonly by: string;
      readonly link: string;
    } | null;
    readonly timeZone: { readonly name: string; readonly from: 'browser' | 'organisation' } | null;
  };
}

/** Which log: the audit log's filters are its actions, actor and object; the access log's its actor alone. */
const LOGS = {
  audit: {
    path: '/v1/audit-log',
    page: '/more/audit-log',
    key: 'events',
    filters: ['actions', 'actorType', 'actorId', 'subjectType', 'subjectId'],
  },
  access: { path: '/v1/access-log', page: '/more/access-log', key: 'rows', filters: ['actorType', 'actorId'] },
} as const;
export type Log = keyof typeof LOGS;

export type FilterName = (typeof LOGS)[Log]['filters'][number];

/** A log's filters as the address holds them: its range as days (`to` the last day in it), the rest as typed. */
export type Filters = Readonly<Record<'from' | 'to', string> & Partial<Record<FilterName, string>>>;

/** How many days back the range starts when the address names none: the last 7 days and today. */
const DEFAULT_DAYS = 7;

const DAY = /^\d{4}-\d{2}-\d{2}$/;

/** A day as a date field holds it, in the browser's own calendar: `2026-11-16`. */
const dayText = (at: Date): string =>
  `${String(at.getFullYear())}-${String(at.getMonth() + 1).padStart(2, '0')}-${String(at.getDate()).padStart(2, '0')}`;

/** The browser's midnight starting `day`, `after` days on. */
function midnight(day: string, after = 0): Date {
  const [year = 0, month = 1, date = 1] = day.split('-').map(Number);
  return new Date(year, month - 1, date + after);
}

/** Whether text is a day a date field could hold (a 31 February reads as another day, so is none). */
const isDay = (text: string | null): text is string =>
  text !== null && DAY.test(text) && dayText(midnight(text)) === text;

/** A log's filters in an address's query: the last 7 days for a range it names none of, empty for any other. */
export function filtersIn(log: Log, search: string, now: Date = new Date()): Filters {
  const query = new URLSearchParams(search);
  const from = query.get('from');
  const to = query.get('to');
  const today = dayText(now);
  const filters: Record<string, string> = {
    from: isDay(from) ? from : dayText(midnight(today, -DEFAULT_DAYS)),
    to: isDay(to) ? to : today,
  };
  for (const name of LOGS[log].filters) filters[name] = query.get(name) ?? '';
  return filters as Filters;
}

/** A filter as sent: trimmed, and each of the actions too, so a page never refuses what its download takes. */
const trimmed = (name: string, value: string): string =>
  name === 'actions'
    ? value
        .split(',')
        .map((action) => action.trim())
        .join(',')
    : value.trim();

/** The filters set, trimmed: only those with a value. */
const nonEmpty = (filters: Filters): [string, string][] =>
  Object.entries(filters)
    .map(([name, value]): [string, string] => [name, trimmed(name, value)])
    .filter(([, value]) => value.length > 0);

/** The log's page's own address for these filters. */
export const pageAddress = (log: Log, filters: Filters): string =>
  `${LOGS[log].page}?${new URLSearchParams(nonEmpty(filters)).toString()}`;

/** The range the API takes: from the first day's midnight to the midnight after the last day, as instants. */
const rangeOf = ({ from, to }: Filters) => ({
  from: midnight(from).toISOString(),
  to: midnight(to, 1).toISOString(),
});

/** A page's query: the range as instants, every other filter as typed, after the cursor its last page gave. */
const logQuery = (filters: Filters, before: string | undefined): string =>
  new URLSearchParams({
    ...Object.fromEntries(nonEmpty(filters)),
    ...rangeOf(filters),
    ...(before !== undefined && { before }),
  }).toString();

/** A failure on the way is read again, twice, as every query is; a refusal or a record failing its check never changes. */
export const readRetry = (count: number, error: Error): boolean =>
  !isRefusal(error) && !isIntegrityFailed(error) && count < 2;

interface Page<T> {
  readonly items: readonly T[];
  readonly next: string | null;
}

/** One log, a page at a time, newest first: mounted only for an admin, as only an admin may read it (decision 24). */
function useLog<T>(log: Log, filters: Filters, organization: string) {
  return useInfiniteQuery({
    queryKey: ['logs', organization, log, logQuery(filters, undefined)],
    retry: readRetry,
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last: Page<T>) => last.next ?? undefined,
    queryFn: async ({ pageParam }): Promise<Page<T>> => {
      const { key, path } = LOGS[log];
      const answer = await api.get<Readonly<Record<typeof key, readonly T[]>> & { readonly next: string | null }>(
        `${path}?${logQuery(filters, pageParam)}`,
        { organization },
      );
      return { items: answer[key], next: answer.next };
    },
  });
}

export const useAuditLog = (filters: Filters, organization: string) => useLog<LogEvent>('audit', filters, organization);

export const useAccessLog = (filters: Filters, organization: string) =>
  useLog<ActivityRow>('access', filters, organization);

export const FORMATS = ['csv', 'ndjson'] as const;
export type Format = (typeof FORMATS)[number];

/**
 * A download's body: the range as instants, the actions as a list, the actor
 * and object each as one (sent as typed once either half is: the API says
 * which half is missing), and the format.
 */
function exportBody(filters: Filters, format: Format) {
  const set = Object.fromEntries(nonEmpty(filters));
  const pair = (type: string | undefined, id: string | undefined) =>
    type === undefined && id === undefined ? undefined : { type: type ?? '', id: id ?? '' };
  return {
    ...rangeOf(filters),
    actions: set.actions?.split(','),
    actor: pair(set.actorType, set.actorId),
    subject: pair(set.subjectType, set.subjectId),
    format,
  };
}

interface ExportFile {
  readonly fileName: string;
  readonly contentType: string;
  readonly content: string;
}

/** Downloads the log as filtered, in `format`, and saves the file its answer carries: the download is itself logged. */
export async function downloadLog(log: Log, filters: Filters, format: Format, organization: string): Promise<void> {
  const { export: file } = await api.post<{ readonly export: ExportFile }>(`${LOGS[log].path}/exports`, {
    organization,
    body: exportBody(filters, format),
  });
  saveFile(file.fileName, [file.content], file.contentType);
}

/** A background download of the access log (ActivityLogBackgroundExport): a month a gzip file. */
export interface BackgroundDownload {
  readonly id: string;
  readonly requestedAt: string;
  readonly from: string;
  readonly to: string;
  readonly format: Format;
  readonly state: 'building' | 'ready' | 'expired' | 'failed';
  readonly expiresAt: string | null;
  readonly files: readonly {
    readonly month: string;
    readonly state: 'waiting' | 'building' | 'ready' | 'failed';
    readonly requests: number | null;
  }[];
}

const BACKGROUND = '/v1/access-log/background-exports';

/** How often the list is read again while a download is still being built: its state moves on its own. */
const BUILDING_POLL_MS = 15_000;

/**
 * The organisation's background downloads, newest first, read again every
 * 15 s while any is still being built (not while the page is hidden, react
 * query's default): a store-less API answers NOT_FOUND, said as none set up.
 */
export function useBackgroundDownloads(organization: string) {
  return useQuery({
    queryKey: ['logs', organization, 'background'],
    retry: readRetry,
    refetchInterval: (query) =>
      query.state.data?.downloads.some((download) => download.state === 'building') === true ? BUILDING_POLL_MS : false,
    queryFn: () =>
      api.get<{ readonly downloads: readonly BackgroundDownload[] }>(`${BACKGROUND}?limit=20`, { organization }),
  });
}

/** Asks for the access log as filtered to be built in the background, emailed to the admin once ready. */
export const askBackground = (filters: Filters, format: Format, organization: string) =>
  api.post(BACKGROUND, { organization, body: exportBody(filters, format) });

interface FileDownload {
  readonly id: string;
  readonly fileName: string;
  readonly contentType: string;
  readonly bytes: number;
  readonly sha256: string;
  readonly parts: number;
}

const bytesOf = (base64: string): Uint8Array<ArrayBuffer> =>
  Uint8Array.from(atob(base64), (char) => char.charCodeAt(0));

const hexOf = (digest: ArrayBuffer): string =>
  Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');

/**
 * Downloads one month's file of a background download (logged first), a part
 * at a time, one after another as the API reads only a few at once, and saves
 * it once its SHA-256 matches the one its record names: a file that doesn't is
 * never saved (ACTIVITY_FILE_DAMAGED, said in plain words).
 */
export async function downloadMonth(exportId: string, month: string, organization: string): Promise<void> {
  const base = `${BACKGROUND}/${encodeURIComponent(exportId)}`;
  const { download } = await api.post<{ readonly download: FileDownload }>(
    `${base}/files/${encodeURIComponent(month)}/downloads`,
    { organization, body: {} },
  );
  const whole = new Uint8Array(download.bytes);
  let at = 0;
  for (let index = 0; index < download.parts; index += 1) {
    const { part } = await api.get<{ readonly part: { readonly content: string } }>(
      `${base}/downloads/${encodeURIComponent(download.id)}/parts/${String(index)}`,
      { organization },
    );
    const bytes = bytesOf(part.content);
    if (at + bytes.length > whole.length) throw new ApiError(200, 'ACTIVITY_FILE_DAMAGED');
    whole.set(bytes, at);
    at += bytes.length;
  }
  const digest = hexOf(await crypto.subtle.digest('SHA-256', whole));
  if (at !== whole.length || digest !== download.sha256.toLowerCase()) throw new ApiError(200, 'ACTIVITY_FILE_DAMAGED');
  saveFile(download.fileName, [whole], download.contentType);
}

/** The refusals a log's reads and downloads can meet that the person can act on, in plain words; any other by its code. */
const REFUSALS = new Set([
  'BAD_REQUEST',
  'FORBIDDEN',
  'NOT_FOUND',
  'AUDIT_EXPORT_TOO_LARGE',
  'AUDIT_EXPORTS_SPENT',
  'ACTIVITY_EXPORT_TOO_LARGE',
  'ACTIVITY_EXPORTS_SPENT',
  'ACTIVITY_EXPORT_UNDER_WAY',
  'ACTIVITY_EXPORT_EXPIRED',
  'ACTIVITY_EXPORT_NOT_READY',
  'ACTIVITY_FILE_DAMAGED',
]);

/** The failures (5xx) with words of their own: a record failing its check, a server busy with another download. */
const FAILURES: Readonly<Record<string, TextKey>> = {
  INTEGRITY_FAILED: 'logs.integrity',
  ACTIVITY_EXPORTS_BUSY: 'logs.busy',
  ACTIVITY_EXPORT_UNREADABLE: 'logs.unreadable',
};

/** What a refused or failed read or download of a log says. */
export function logRefusal(error: unknown): string {
  const own = error instanceof ApiError ? FAILURES[error.code] : undefined;
  return own === undefined ? refusalText(error, REFUSALS, 'logs.refused') : t(own);
}

/** Who an event or request was by, in words: their name and email where known, else what kind they are. */
export function actorText(actor: Actor): string {
  const named = actor.name ?? t(`logs.actor.${actor.type}`);
  return actor.email === null ? named : `${named} (${actor.email})`;
}
