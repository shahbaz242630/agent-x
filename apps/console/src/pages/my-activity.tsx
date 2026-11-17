// My activity (6E1a, CO8, PL-48; decision 26's L8): the signed-in person's own
// activity log, read like a statement: every request they made outside an
// organisation (their profile, their session, an invitation, an organisation
// they turned out not to be in), newest first, by date, the range kept in the
// address. Each row says when (and the clock where its time zone says), what
// (method, route, status, reason) and whether its day is sealed; where it came
// from (address, approximate place credited to DB-IP, time zone) is folded
// away, labelled clues, never proof. What they did inside an organisation is
// that organisation's own log, its admins' record: said in one line. It
// downloads as CSV or NDJSON, each download itself recorded. Agent X's own
// exports of their log for a case are listed: a person is always told.
import { useState } from 'react';

import { ApiError } from '../api.ts';

import {
  downloadLog,
  type ExportByAgentX,
  type Format,
  logRefusal,
  type MyActivityRow,
  useMyActivity,
} from '../logs.ts';
import { timeText } from '../requests.ts';
import { t } from '../text.ts';
import { Clues } from './access-log.tsx';
import { Said, useChange } from './change.tsx';
import { FilterForm, FormatField, Pages, useFilters } from './log-parts.tsx';

/** A download's refusals in a person's own words (no background build, no admin); any other as the logs say it. */
const myRefusal = (error: unknown): string => {
  if (error instanceof ApiError && error.code === 'ACTIVITY_EXPORT_TOO_LARGE') return t('myActivity.tooLarge');
  if (error instanceof ApiError && error.code === 'ACTIVITY_EXPORTS_SPENT') return t('myActivity.spent');
  return logRefusal(error);
};

function Row({ row }: { readonly row: MyActivityRow }) {
  const said = row.reason === null ? String(row.status) : `${String(row.status)} ${row.reason}`;
  return (
    <li className="row">
      <span className="row-main">
        <span>
          <span className="mono">
            {row.method} {row.route}
          </span>
          {row.sealed && <span className="tag">{t('logs.access.sealed')}</span>}
        </span>
        <span className="muted">
          {timeText(row.recordedAt)} · <span className="mono">{said}</span>
          {row.localTime !== null && (
            <>
              {' · '}
              {t('myActivity.yourClock', { time: row.localTime })}
            </>
          )}
        </span>
        {row.claimedOrganizationId !== null && (
          <span className="muted">
            {t('myActivity.claimed')} <span className="mono">{row.claimedOrganizationId}</span>
          </span>
        )}
        <details>
          <summary>{t('logs.access.clues')}</summary>
          <Clues row={row} />
        </details>
      </span>
    </li>
  );
}

/** Agent X's exports of the person's log for a case, newest first, or that there are none. */
function ExportsByAgentX({ exports }: { readonly exports: readonly ExportByAgentX[] | undefined }) {
  return (
    <section className="stack" aria-label={t('myActivity.exports.title')}>
      <h2>{t('myActivity.exports.title')}</h2>
      <p className="muted">{t('myActivity.exports.intro')}</p>
      {exports === undefined || exports.length === 0 ? (
        <p className="muted">{t('myActivity.exports.none')}</p>
      ) : (
        <ul className="rows">
          {exports.map((one) => (
            <li key={one.id} className="row">
              <span className="row-main">
                <span>{t('myActivity.exports.at', { time: timeText(one.at) })}</span>
                <span className="muted">
                  {t('myActivity.exports.range', {
                    from: one.from === null ? '?' : timeText(one.from),
                    to: one.to === null ? '?' : timeText(one.to),
                    count: one.requests === null ? '?' : String(one.requests),
                  })}
                  {one.caseRef !== null && ` · ${t('myActivity.exports.case', { ref: one.caseRef })}`}
                </span>
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

export function MyActivity() {
  const { search, filters, go } = useFilters('mine');
  const [format, setFormat] = useState<Format>('csv');
  const { busy, said, run } = useChange(myRefusal);
  const pages = useMyActivity(filters);
  return (
    <section className="stack">
      <h1>{t('myActivity.title')}</h1>
      <p className="muted">{t('myActivity.intro')}</p>
      <p className="notice">{t('myActivity.organisations')}</p>
      {/* Keyed by the address, as the organisation's logs. */}
      <FilterForm key={search} filters={filters} fields={[]} onApply={go} />
      <FormatField format={format} onChange={setFormat} />
      <button
        type="button"
        className="secondary"
        disabled={busy}
        onClick={() =>
          void run(() => downloadLog('mine', filters, format, undefined), { done: t('myActivity.downloaded') })
        }
      >
        {t('logs.download')}
      </button>
      <p className="fine">{t('myActivity.downloadLogged')}</p>
      <Said said={said} />
      <Pages pages={pages} row={(row: MyActivityRow) => <Row key={row.id} row={row} />} />
      <ExportsByAgentX exports={pages.data?.pages[0]?.exportsByAgentX} />
    </section>
  );
}
