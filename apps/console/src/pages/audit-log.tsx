// The audit log (6C2; partner rule S119; decision 24: admins only): every
// signed event of the organisation, newest first, filtered by date, action,
// person and object (CO7), the filters kept in the address. Each event says
// when, what, who and about what, its facts folded away and its chain hashes
// shown; its actor or object narrows the log to it in one press. What is shown
// downloads as CSV or NDJSON, the download itself logged.
import { Fragment, useState } from 'react';

import { type Filters, type Format, type LogEvent, useAuditLog } from '../logs.ts';
import { timeText } from '../requests.ts';
import { useActing } from '../session.tsx';
import { t } from '../text.ts';
import { ActorLine, Hashes } from './log-event.tsx';
import { Download, type Field, FilterForm, FormatField, LogScreen, Pages, useFilters } from './log-parts.tsx';

const FIELDS: readonly Field[] = [
  { name: 'actions' },
  { name: 'actorType', options: ['', 'user', 'agent', 'system'] },
  { name: 'actorId' },
  { name: 'subjectType' },
  { name: 'subjectId' },
];

function Event({ event, narrow }: { readonly event: LogEvent; readonly narrow: (more: Partial<Filters>) => void }) {
  return (
    <li className="row">
      <span className="row-main">
        <span className="mono">{event.action}</span>
        <span className="muted">
          {timeText(event.recordedAt)} · <span className="mono">#{event.seq}</span>
        </span>
        <ActorLine
          actor={event.actor}
          onOnly={() => {
            narrow({ actorType: event.actor.type, actorId: event.actor.id });
          }}
        />
        <span className="muted">
          {t('logs.about')} <span className="mono">{event.subject.type}</span>{' '}
          <span className="mono">{event.subject.id}</span>{' '}
          <button
            type="button"
            className="link"
            onClick={() => {
              narrow({ subjectType: event.subject.type, subjectId: event.subject.id });
            }}
          >
            {t('logs.onlyObject')}
          </button>
        </span>
        {event.details.length > 0 && (
          <details>
            <summary>{t('logs.facts', { count: String(event.details.length) })}</summary>
            <dl className="facts">
              {event.details.map(({ name, value }) => (
                <Fragment key={name}>
                  <dt className="mono">{name}</dt>
                  <dd className="mono">{value === null ? '—' : String(value)}</dd>
                </Fragment>
              ))}
            </dl>
          </details>
        )}
        <Hashes hash={event.hash} prevHash={event.prevHash} />
      </span>
    </li>
  );
}

/** What an admin sees: the filters, the download and the events. */
function Events() {
  const { organization } = useActing();
  const { search, filters, go, narrow } = useFilters('audit');
  const [format, setFormat] = useState<Format>('csv');
  return (
    <>
      {/* Keyed by the address: a filter set from an event (only this object) shows in the form at once. */}
      <FilterForm key={search} filters={filters} fields={FIELDS} onApply={go} />
      <FormatField format={format} onChange={setFormat} />
      <Download log="audit" filters={filters} format={format} />
      <Pages
        pages={useAuditLog(filters, organization.id)}
        row={(event: LogEvent) => <Event key={event.id} event={event} narrow={narrow} />}
      />
    </>
  );
}

export const AuditLog = () => (
  <LogScreen title={t('logs.audit.title')} intro={t('logs.audit.intro')}>
    <Events />
  </LogScreen>
);
