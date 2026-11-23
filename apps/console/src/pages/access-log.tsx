// The access log (6C2; decision 26: admins only): every request the
// organisation's people and agents made, newest first, filtered by date and by
// person or agent, the filters kept in the address. Each row says when (and the
// clock where its time zone says), who, what (method, route, status, reason)
// and whether its day is sealed; its client's clues (address, approximate
// place credited to DB-IP, time zone) are folded away, clues never proof.
// What is shown downloads as CSV or NDJSON, itself logged; a range past the
// instant download's cap is built in the background, a month a gzip file,
// emailed when ready (decision 31) and downloaded here.
import { Fragment, useId, useState } from 'react';

import { ApiError } from '../api.ts';
import {
  type ActivityRow,
  askBackground,
  type BackgroundDownload,
  downloadMonth,
  type Filters,
  type Format,
  logRefusal,
  useAccessLog,
  useBackgroundDownloads,
} from '../logs.ts';
import { timeText } from '../requests.ts';
import { useActing } from '../session.tsx';
import { t } from '../text.ts';
import { Said, useChange } from './change.tsx';
import { Loading, Retry } from './failed.tsx';
import { ActorLine } from './log-event.tsx';
import { Download, type Field, FilterForm, FormatField, LogScreen, Pages, useFilters } from './log-parts.tsx';
import { Tag } from './tag.tsx';

const FIELDS: readonly Field[] = [{ name: 'actorType', options: ['', 'user', 'agent'] }, { name: 'actorId' }];

/** Its client's clues, each only where the API has one: an organisation's row's and a person's own alike (6E1a). */
export function Clues({ row }: { readonly row: Pick<ActivityRow, 'client' | 'correlationId' | 'pathIds'> }) {
  const { ip, place, timeZone } = row.client;
  return (
    <dl className="facts">
      <dt>{t('logs.access.correlation')}</dt>
      <dd className="mono">{row.correlationId}</dd>
      {row.pathIds.length > 0 && (
        <>
          <dt>{t('logs.access.pathIds')}</dt>
          <dd className="mono">{row.pathIds.join(' ')}</dd>
        </>
      )}
      {ip !== null && (
        <>
          <dt>{t('logs.access.ip')}</dt>
          <dd className="mono">{ip}</dd>
        </>
      )}
      {place !== null && (
        <>
          <dt>{t('logs.access.place')}</dt>
          <dd>
            {[place.city, place.country].filter((part) => part !== null).join(', ')} ·{' '}
            {/* CC BY 4.0: the place's source credited beside it. */}
            <a href={place.link} target="_blank" rel="noreferrer">
              {t('logs.access.placeBy', { by: place.by })}
            </a>
          </dd>
        </>
      )}
      {timeZone !== null && (
        <>
          <dt>{t('logs.access.timeZone')}</dt>
          <dd>{t(`logs.access.zoneFrom.${timeZone.from}`, { zone: timeZone.name })}</dd>
        </>
      )}
    </dl>
  );
}

function Row({ row, narrow }: { readonly row: ActivityRow; readonly narrow: (more: Partial<Filters>) => void }) {
  const said = row.reason === null ? String(row.status) : `${String(row.status)} ${row.reason}`;
  return (
    <li className="row">
      <span className="row-main">
        <span>
          <span className="mono">
            {row.method} {row.route}
          </span>
          {row.sealed && <Tag>{t('logs.access.sealed')}</Tag>}
        </span>
        <span className="muted">
          {timeText(row.recordedAt)} · <span className="mono">{said}</span>
          {row.localTime !== null && (
            <>
              {' · '}
              {t('logs.access.theirClock', { time: row.localTime })}
            </>
          )}
        </span>
        <ActorLine
          actor={row.actor}
          onOnly={() => {
            narrow({ actorType: row.actor.type, actorId: row.actor.id });
          }}
        />
        <details>
          <summary>{t('logs.access.clues')}</summary>
          <Clues row={row} />
        </details>
      </span>
    </li>
  );
}

/** One background download: its range, format and state, and each month's file to download once ready. */
function Built({ download }: { readonly download: BackgroundDownload }) {
  const { organization } = useActing();
  const { busy, said, run } = useChange(logRefusal);
  return (
    <li className="row">
      <span className="row-main">
        <span>
          {timeText(download.from)} – {timeText(download.to)} · {t(`logs.format.${download.format}`)}
        </span>
        <span className="muted">
          {t(`logs.background.state.${download.state}`)}
          {download.expiresAt !== null && ` · ${t('logs.background.kept', { time: timeText(download.expiresAt) })}`}
        </span>
        {download.state === 'ready' &&
          download.files.map((file) => (
            <Fragment key={file.month}>
              {file.state === 'ready' ? (
                <button
                  type="button"
                  className="link"
                  disabled={busy}
                  onClick={() =>
                    void run(() => downloadMonth(download.id, file.month, organization.id), {
                      done: t('logs.downloaded'),
                    })
                  }
                >
                  {t('logs.background.month', { month: file.month, count: String(file.requests ?? 0) })}
                </button>
              ) : (
                <span className="muted">{t('logs.background.monthFailed', { month: file.month })}</span>
              )}
            </Fragment>
          ))}
        <Said said={said} />
      </span>
    </li>
  );
}

/** Long ranges: built in the background, a month a file, and the downloads asked for so far. */
function Background({ filters, format }: { readonly filters: Filters; readonly format: Format }) {
  const { organization } = useActing();
  const downloads = useBackgroundDownloads(organization.id);
  const { busy, said, run } = useChange(logRefusal);
  const titleId = useId();
  if (downloads.error instanceof ApiError && downloads.error.status === 404) {
    // No download store where this API runs: the feature isn't there, said once, with nothing to press.
    return <p className="muted">{t('logs.background.unavailable')}</p>;
  }
  let list;
  if (downloads.isError) {
    list = <Retry onRetry={() => void downloads.refetch()} />;
  } else if (downloads.isPending) {
    list = <Loading />;
  } else if (downloads.data.downloads.length === 0) {
    list = <p className="muted">{t('logs.background.none')}</p>;
  } else {
    list = (
      <ul className="rows">
        {downloads.data.downloads.map((download) => (
          <Built key={download.id} download={download} />
        ))}
      </ul>
    );
  }
  return (
    <section className="stack" aria-labelledby={titleId}>
      <h2 id={titleId}>{t('logs.background.title')}</h2>
      <p className="muted">{t('logs.background.intro')}</p>
      <button
        type="button"
        className="secondary"
        disabled={busy}
        onClick={() =>
          void run(() => askBackground(filters, format, organization.id), { done: t('logs.background.asked') })
        }
      >
        {t('logs.background.ask')}
      </button>
      <Said said={said} />
      {list}
    </section>
  );
}

/** What an admin sees: the filters, the download, the requests and the long ranges. */
function Requests() {
  const { organization } = useActing();
  const { search, filters, go, narrow } = useFilters('access');
  const [format, setFormat] = useState<Format>('csv');
  return (
    <>
      {/* Keyed by the address: a person set from a row (only this person) shows in the form at once. */}
      <FilterForm key={search} filters={filters} fields={FIELDS} onApply={go} />
      <FormatField format={format} onChange={setFormat} />
      <Download log="access" filters={filters} format={format} />
      <Pages
        pages={useAccessLog(filters, organization.id)}
        row={(row: ActivityRow) => <Row key={row.id} row={row} narrow={narrow} />}
      />
      <Background filters={filters} format={format} />
    </>
  );
}

export const AccessLog = () => (
  <LogScreen title={t('logs.access.title')} intro={t('logs.access.intro')}>
    <Requests />
  </LogScreen>
);
