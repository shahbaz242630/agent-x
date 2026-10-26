// One spend request's page (6B1): what it asks, in full, and the decision on
// it. The approver's email links here (PL-51). Approving and rejecting ask
// for a passkey (the shared step-up, step-up.ts): the change is asked here,
// the browser signs in again, and it is confirmed on this same page. A
// request whose supplier details changed and were verified again is approved
// re-checked, confirmed in the API's own words first (`recheck`). Cancelling
// is the instant brake (partner decision 10): one click, no step-up and no
// confirm, then said done. Who may decide is the API's to say: the buttons show for an
// admin or approver only, and the API checks again whatever is pressed.
import { useQueryClient } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { useId, useState } from 'react';

import { api, ApiError, isSignedOut } from '../api.ts';
import { Confirm } from '../confirm.tsx';
import { amountText, isCancellable, type RequestDetails, timeText, useRequest } from '../requests.ts';
import { endSession, useActing } from '../session.tsx';
import { ask } from '../step-up.ts';
import { t, type TextKey } from '../text.ts';
import { leftWords } from './approvals.tsx';
import { Retry } from './failed.tsx';

/** The plain words for a refusal the person can act on; the code for any other. */
const REFUSALS = new Set([
  'REQUEST_NOT_WAITING',
  'REQUEST_EXPIRED',
  'REQUEST_CHANGED',
  'ADMIN_APPROVAL_ONLY',
  'REQUEST_NOT_CANCELLABLE',
  'ORG_FROZEN',
  'FORBIDDEN',
]);

function refusalWords(error: unknown): string {
  if (!(error instanceof ApiError) || error.status >= 500) return t('request.failed');
  return REFUSALS.has(error.code)
    ? t(`request.refused.${error.code}` as TextKey)
    : t('request.refused.other', { code: error.code });
}

type Open = 'none' | 'recheck' | 'reject';

function Facts({ request }: { readonly request: RequestDetails }) {
  return (
    <dl className="facts">
      <dt>{t('request.supplier')}</dt>
      <dd>{request.supplier.name}</dd>
      <dt>{t('request.invoice')}</dt>
      <dd className="mono">{request.agentWrote.orderReference}</dd>
      <dt>{t('request.purpose')}</dt>
      <dd>{request.agentWrote.purpose}</dd>
      <dt>{t('request.agent')}</dt>
      <dd>{request.agent.name}</dd>
      {request.reasons.length > 0 && (
        <>
          <dt>{t('request.why')}</dt>
          <dd>
            {request.reasons.map((reason) => (
              <span key={reason.code} className="reason">
                {reason.message}
              </span>
            ))}
          </dd>
        </>
      )}
      {request.expiresAt !== null && (
        <>
          <dt>{t('request.expires')}</dt>
          <dd>{timeText(request.expiresAt)}</dd>
        </>
      )}
      <dt>{t('request.changed')}</dt>
      <dd>{timeText(request.changedAt)}</dd>
      <dt>{t('request.bankReference')}</dt>
      <dd className="mono">{request.bankReference}</dd>
      <dt>{t('request.id')}</dt>
      <dd className="mono">{request.id}</dd>
    </dl>
  );
}

function Decided({ request }: { readonly request: RequestDetails }) {
  return (
    <>
      {request.rejection !== null && (
        <p className="notice">
          {t('request.rejected', { time: timeText(request.rejection.at), reason: request.rejection.reason })}
        </p>
      )}
      {request.voiding !== null && (
        <div className="notice">
          <p>{t('request.voided', { time: timeText(request.voiding.at) })}</p>
          {request.voiding.reasons.map((reason) => (
            <p key={reason.code}>{reason.message}</p>
          ))}
        </div>
      )}
    </>
  );
}

function Actions({ request }: { readonly request: RequestDetails }) {
  const { organization } = useActing();
  const queries = useQueryClient();
  const [open, setOpen] = useState<Open>('none');
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [said, setSaid] = useState<string | null>(null);
  const reasonId = useId();
  const amount = amountText(request.amountMinor, request.currency);
  const names = { amount, supplier: request.supplier.name };
  const path = `/v1/spend-requests/${encodeURIComponent(request.id)}`;
  const waiting = request.status === 'APPROVAL_REQUIRED';
  const deciding = organization.role === 'admin' || organization.role === 'approver';
  if (!deciding)
    return waiting || isCancellable(request.status) ? <p className="muted">{t('request.viewOnly')}</p> : null;

  /** Sends a change; a refusal or failure is said, a 401 goes to sign-in (the console's queries). */
  const run = async (send: () => Promise<unknown>, done?: string) => {
    setBusy(true);
    setSaid(null);
    try {
      const sent = await send();
      if (sent === 'stepping') return;
      setOpen('none');
      if (done !== undefined) setSaid(done);
      await queries.invalidateQueries({ queryKey: ['requests', organization.id] });
    } catch (error) {
      if (isSignedOut(error)) {
        endSession(queries);
        return;
      }
      setOpen('none');
      setSaid(refusalWords(error));
    } finally {
      setBusy(false);
    }
  };
  const approve = (recheck: boolean) =>
    run(() =>
      ask({
        label: t('request.approveLabel', names),
        askPath: `${path}/approve`,
        confirmPath: `${path}/approve/confirm`,
        body: recheck ? { recheck: true } : {},
        organization: organization.id,
      }),
    );
  const reject = () =>
    run(() =>
      ask({
        label: t('request.rejectLabel', names),
        askPath: `${path}/reject`,
        confirmPath: `${path}/reject/confirm`,
        body: { reason: reason.trim() },
        organization: organization.id,
      }),
    );
  const cancel = () =>
    run(() => api.post(`${path}/cancel`, { organization: organization.id, body: {} }), t('request.cancelled'));

  return (
    <>
      {waiting && request.needsRecheck && <p className="notice">{t('request.recheck')}</p>}
      {waiting && (
        <>
          <div className="decide">
            <button
              type="button"
              className="secondary"
              disabled={busy}
              onClick={() => {
                setOpen('reject');
              }}
            >
              {t('request.reject')}
            </button>
            <button
              type="button"
              className="primary"
              disabled={busy}
              onClick={() => {
                if (request.needsRecheck) setOpen('recheck');
                else void approve(false);
              }}
            >
              {t('request.approve')}
            </button>
          </div>
          <p className="fine">{t('request.fine')}</p>
        </>
      )}
      {isCancellable(request.status) && (
        <button type="button" className="secondary" disabled={busy} onClick={() => void cancel()}>
          {t('request.cancel')}
        </button>
      )}
      {said !== null && (
        <p className="notice" role="status">
          {said}
        </p>
      )}
      {open === 'recheck' && (
        <Confirm
          statement="recheck"
          title={t('request.recheckTitle')}
          confirmLabel={t('request.recheckConfirm')}
          busy={busy}
          onCancel={() => {
            setOpen('none');
          }}
          onConfirm={() => void approve(true)}
        >
          <p className="amount">{t('request.approveLabel', names)}</p>
        </Confirm>
      )}
      {open === 'reject' && (
        <Confirm
          text={t('request.rejectText')}
          title={t('request.rejectTitle')}
          confirmLabel={t('request.rejectConfirm')}
          busy={busy}
          ready={reason.trim().length > 0}
          onCancel={() => {
            setOpen('none');
          }}
          onConfirm={() => void reject()}
        >
          <p className="amount">{t('request.rejectLabel', names)}</p>
          <label className="field" htmlFor={reasonId}>
            {t('request.rejectReason')}
          </label>
          <textarea
            id={reasonId}
            maxLength={1600}
            rows={3}
            value={reason}
            onChange={(event) => {
              setReason(event.target.value);
            }}
          />
        </Confirm>
      )}
    </>
  );
}

export function RequestPage({ id }: { readonly id: string }) {
  const { organization } = useActing();
  const request = useRequest(id, organization.id);
  const back = (
    <Link to="/approvals" className="back">
      {t('request.back')}
    </Link>
  );
  if (request.isPending) {
    return (
      <p className="loading" role="status">
        {t('loading')}
      </p>
    );
  }
  if (request.isError) {
    const missing = request.error instanceof ApiError && request.error.status === 404;
    return (
      <section className="stack">
        {back}
        {missing ? <p className="notice">{t('request.notFound')}</p> : <Retry onRetry={() => void request.refetch()} />}
      </section>
    );
  }
  const shown = request.data;
  const kicker =
    shown.status === 'APPROVAL_REQUIRED' && shown.expiresAt !== null
      ? t('request.waiting', { left: leftWords(shown.expiresAt) })
      : t(`status.${shown.status}`);
  return (
    <section className="stack request">
      {back}
      <span className="kicker">{kicker}</span>
      <h1 className="amount big">{amountText(shown.amountMinor, shown.currency)}</h1>
      <Facts request={shown} />
      <Decided request={shown} />
      <Actions request={shown} />
    </section>
  );
}
