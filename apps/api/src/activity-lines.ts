// One request of the activity log as a download's file holds it (Phase 3
// L5, L5c), the instant download's and the background one's alike: NDJSON,
// one request a line as a page shows it; CSV, one row a request, every cell
// a spreadsheet would read as a formula made text (SEC-EVD-04). Both credit
// DB-IP beside every place (CC BY 4.0), and mark each request sealed or not (L6).
import type { ActivityRow } from '@agentx/core/modules/activity';
import { activityNdjsonLine, activityShown, type ActorName } from '@agentx/core/modules/evidence';

import { csvRow, type ExportFormat } from './audit-log-exports.ts';

/** A CSV download's header: one column a field of a request as shown. */
export const ACTIVITY_CSV_HEADER = [
  'id',
  'recordedAt',
  'localTime',
  'actorType',
  'actorId',
  'actorName',
  'actorEmail',
  'actorNameFrom',
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

/** One request as a download's file holds it, its actor named, sealed or not by `sealedDay`: one NDJSON line, or one CSV row. */
export const activityLineOf = (
  format: ExportFormat,
  row: ActivityRow,
  names: ReadonlyMap<string, ActorName>,
  sealedDay: string | null,
): string => {
  if (format === 'ndjson') return activityNdjsonLine(row, names, sealedDay);
  const shown = activityShown(row, names, sealedDay);
  const { actor, client } = shown;
  const { place } = client;
  return csvRow(
    [shown.id, shown.recordedAt, shown.localTime ?? '', actor.type, actor.id, actor.name ?? '']
      .concat([actor.email ?? '', actor.shownFrom ?? '', shown.method, shown.route, shown.pathIds.join(' ')])
      .concat([String(shown.status), shown.reason ?? '', shown.correlationId, String(shown.durationMs)])
      .concat([String(shown.sealed)])
      .concat([client.ip ?? '', place?.country ?? '', place?.city ?? ''])
      .concat([place === null ? '' : `${place.by} (${place.link})`])
      .concat([client.timeZone?.name ?? '', client.timeZone?.from ?? '']),
  );
};
