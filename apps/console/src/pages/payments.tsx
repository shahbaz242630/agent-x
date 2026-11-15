// Payments (6C1): every payment the organisation's agents made, newest first,
// filtered to one group by the page's own address (`?status=`, so a reload or
// a link keeps it), and the exception list (BR-17): the payments to follow up
// with the bank, each saying why it is there. Each row opens the payment's own
// page, with its history. Look A "Statement": amounts in a column, nothing
// shouts; a payment the bank contradicts is tagged.
import { Link, useNavigate, useRouterState } from '@tanstack/react-router';

import { type Group, GROUPS, groupIn, type ListedPayment, usePaymentList, type Which } from '../payments.ts';
import { amountText, timeText } from '../requests.ts';
import { useActing } from '../session.tsx';
import { t } from '../text.ts';
import { Loading, Retry } from './failed.tsx';

/** Why a payment is on the exception list: its outcome never came, or the bank's word disagrees with its status. */
function Why({ payment }: { readonly payment: ListedPayment }) {
  return (
    <>
      {payment.status === 'UNKNOWN' && <span className="muted">{t('payments.why.unknown')}</span>}
      {payment.contradicted && <span className="muted">{t('payments.why.contradicted')}</span>}
    </>
  );
}

function Row({ payment, exceptions }: { readonly payment: ListedPayment; readonly exceptions: boolean }) {
  return (
    <li>
      <Link to="/payments/$id" params={{ id: payment.id }} className="row">
        <span className="row-main">
          <span>
            {payment.supplier.name}
            {/* On the exception list the why line says it already. */}
            {payment.contradicted && !exceptions && <span className="tag warn">{t('payments.contradicted')}</span>}
          </span>
          <span className="muted">
            {t(`payments.status.${payment.status}`)} · <span className="mono">{payment.bankReference}</span> ·{' '}
            {timeText(payment.changedAt)}
          </span>
          {exceptions && <Why payment={payment} />}
        </span>
        <b className="amount">{amountText(payment.amountMinor, payment.currency)}</b>
      </Link>
    </li>
  );
}

/** The filter by group, kept in the address: a change replaces nothing else the person sees. */
function Filter({ group }: { readonly group: Group | 'all' }) {
  const navigate = useNavigate();
  return (
    <>
      <label className="field" htmlFor="payments-status">
        {t('payments.filter')}
      </label>
      <select
        id="payments-status"
        value={group}
        onChange={(event) => {
          const status = event.target.value;
          // The raw address, not the router's search, which would write the value as JSON.
          void navigate({
            href: status === 'all' ? '/payments' : `/payments?${new URLSearchParams({ status }).toString()}`,
          });
        }}
      >
        <option value="all">{t('payments.group.all')}</option>
        {GROUPS.map((one) => (
          <option key={one} value={one}>
            {t(`payments.group.${one}`)}
          </option>
        ))}
      </select>
    </>
  );
}

export function Payments({ list }: { readonly list: 'all' | 'exceptions' }) {
  const { organization } = useActing();
  // The raw query, not the router's parsed one, which reads values as JSON.
  const group = useRouterState({ select: ({ location }) => groupIn(location.searchStr) });
  const which: Which = list === 'exceptions' ? 'exceptions' : group;
  const payments = usePaymentList(which, organization.id);
  const pages = payments.data?.pages ?? [];
  const shown = pages.flatMap((page) => page.payments);
  const unchecked = pages.reduce((count, page) => count + page.unchecked.length, 0);
  let none: 'payments.none' | 'payments.noneInGroup' | 'payments.noneExceptions' = 'payments.none';
  if (which === 'exceptions') none = 'payments.noneExceptions';
  else if (which !== 'all') none = 'payments.noneInGroup';
  return (
    <section className="stack">
      <h1>{t('payments.title')}</h1>
      <nav className="subtabs" aria-label={t('payments.title')}>
        <Link to="/payments" activeOptions={{ exact: true }} activeProps={{ className: 'on', 'aria-current': 'page' }}>
          {t('payments.all')}
        </Link>
        <Link to="/payments/exceptions" activeProps={{ className: 'on', 'aria-current': 'page' }}>
          {t('payments.exceptions')}
        </Link>
      </nav>
      {list === 'all' ? <Filter group={group} /> : <p className="muted">{t('payments.exceptionsIntro')}</p>}
      {payments.isPending && <Loading />}
      {payments.isError && <Retry onRetry={() => void payments.refetch()} />}
      {payments.isSuccess && shown.length === 0 && <p className="muted">{t(none)}</p>}
      {shown.length > 0 && (
        <ul className="rows">
          {shown.map((payment) => (
            <Row key={payment.id} payment={payment} exceptions={list === 'exceptions'} />
          ))}
        </ul>
      )}
      {unchecked > 0 && (
        <p className="notice" role="status">
          {t('payments.unchecked', { count: String(unchecked) })}
        </p>
      )}
      {payments.hasNextPage && (
        <button
          type="button"
          className="secondary"
          disabled={payments.isFetchingNextPage}
          onClick={() => void payments.fetchNextPage()}
        >
          {t('approvals.more')}
        </button>
      )}
    </section>
  );
}
