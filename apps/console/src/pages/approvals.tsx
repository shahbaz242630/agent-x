// Approvals (6B1): the requests waiting for approval, soonest to expire at the
// top, and every request the organisation's agents made, newest first. Each
// row opens the request's own page, where it is approved, rejected or
// cancelled. Look A "Statement": amounts in a column, nothing shouts.
import { Link } from '@tanstack/react-router';

import { amountText, leftText, type ListedRequest, timeText, useRequestList } from '../requests.ts';
import { useActing } from '../session.tsx';
import { t } from '../text.ts';
import { Retry } from './failed.tsx';

/** What's left before a waiting request expires, as its row and page say it. */
export function leftWords(expiresAt: string): string {
  const left = leftText(expiresAt);
  if (left === null) return t('approvals.left.past');
  return 'hours' in left
    ? t('approvals.left.hours', { n: String(left.hours) })
    : t('approvals.left.minutes', { n: String(left.minutes) });
}

function Row({ request }: { readonly request: ListedRequest }) {
  const when =
    request.status === 'APPROVAL_REQUIRED' && request.expiresAt !== null
      ? leftWords(request.expiresAt)
      : [t(`status.${request.status}`), timeText(request.changedAt)].join(' · ');
  return (
    <li>
      <Link to="/approvals/$id" params={{ id: request.id }} className="row">
        <span className="row-main">
          <span>{request.supplier.name}</span>
          <span className="muted">
            {request.agent.name} · {when}
          </span>
        </span>
        <b className="amount">{amountText(request.amountMinor, request.currency)}</b>
      </Link>
    </li>
  );
}

export function Approvals({ list }: { readonly list: 'waiting' | 'all' }) {
  const { organization } = useActing();
  const requests = useRequestList(list, organization.id);
  const pages = requests.data?.pages ?? [];
  const shown = pages.flatMap((page) => page.requests);
  const unchecked = pages.reduce((count, page) => count + page.unchecked.length, 0);
  return (
    <section className="stack">
      <h1>{t('approvals.title')}</h1>
      <nav className="subtabs" aria-label={t('approvals.title')}>
        <Link to="/approvals" activeOptions={{ exact: true }} activeProps={{ className: 'on', 'aria-current': 'page' }}>
          {t('approvals.waiting')}
        </Link>
        <Link to="/approvals/all" activeProps={{ className: 'on', 'aria-current': 'page' }}>
          {t('approvals.all')}
        </Link>
      </nav>
      {requests.isPending && (
        <p className="loading" role="status">
          {t('loading')}
        </p>
      )}
      {requests.isError && <Retry onRetry={() => void requests.refetch()} />}
      {requests.isSuccess && shown.length === 0 && (
        <p className="muted">{t(list === 'waiting' ? 'approvals.none' : 'approvals.noneAll')}</p>
      )}
      {shown.length > 0 && (
        <ul className="rows">
          {shown.map((request) => (
            <Row key={request.id} request={request} />
          ))}
        </ul>
      )}
      {unchecked > 0 && (
        <p className="notice" role="status">
          {t('approvals.unchecked', { count: String(unchecked) })}
        </p>
      )}
      {requests.hasNextPage && (
        <button
          type="button"
          className="secondary"
          disabled={requests.isFetchingNextPage}
          onClick={() => void requests.fetchNextPage()}
        >
          {t('approvals.more')}
        </button>
      )}
    </section>
  );
}
