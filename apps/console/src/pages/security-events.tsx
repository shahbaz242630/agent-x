// The organisation's security events (6E1b, CO7b; decision 26: admins only):
// its people's and AI agents' rate-limit hits and failed step-ups, newest
// first, filtered by date and kind, the filters kept in the address. Each row
// says the minute it was counted in, what happened and how many times, who it
// was about, and, folded away, the address it came from: a clue, never proof.
// Failed sign-ins before anyone is known are no organisation's, so never here.
import { type SecurityEventRow, useSecurityEvents } from '../logs.ts';
import { timeText } from '../requests.ts';
import { useActing } from '../session.tsx';
import { t } from '../text.ts';
import { type Field, FilterForm, LogScreen, Pages, useFilters } from './log-parts.tsx';

const FIELDS: readonly Field[] = [{ name: 'kind', options: ['', 'rate_limited', 'sign_in_failed'] }];

/** Who it was about, in words: their name where known, else what kind they are, and their ID. */
function Actor({ actor }: { readonly actor: SecurityEventRow['actor'] }) {
  if (actor === null) return <span className="muted">{t('securityEvents.noActor')}</span>;
  return (
    <span className="muted">
      {actor.name ?? t(`logs.actor.${actor.type}`)} · <span className="mono">{actor.id}</span>
    </span>
  );
}

function Row({ row }: { readonly row: SecurityEventRow }) {
  return (
    <li className="row">
      <span className="row-main">
        <span>
          {t(`securityEvents.kind.${row.kind}`)} · <span className="mono">{row.reason}</span>
        </span>
        <span className="muted">
          {timeText(row.windowStart)} · {t('securityEvents.count', { count: String(row.count) })}
        </span>
        <Actor actor={row.actor} />
        <details>
          <summary>{t('securityEvents.clues')}</summary>
          <dl className="facts">
            <dt>{t('logs.access.ip')}</dt>
            <dd className="mono">{row.ip ?? t('securityEvents.noIp')}</dd>
          </dl>
        </details>
      </span>
    </li>
  );
}

/** What an admin sees: the filters and the events. */
function Events() {
  const { organization } = useActing();
  const { search, filters, go } = useFilters('security');
  return (
    <>
      <FilterForm key={search} filters={filters} fields={FIELDS} onApply={go} />
      <Pages
        pages={useSecurityEvents(filters, organization.id)}
        row={(row: SecurityEventRow) => <Row key={row.id} row={row} />}
      />
    </>
  );
}

export const SecurityEvents = () => (
  <LogScreen title={t('securityEvents.title')} intro={t('securityEvents.intro')}>
    <Events />
  </LogScreen>
);
