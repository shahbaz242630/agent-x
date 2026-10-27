// One spend request's page (6B1): what it asks, in full, and the decision on
// it. The approver's email links here (PL-51). Approving and rejecting ask
// for a passkey (the shared step-up, step-up.ts): the change is asked here,
// the browser signs in again, and it is confirmed on this same page.
// Approving is asked first and its answer shown before the passkey, as the
// API may say how it would come out: a request whose supplier changed and
// was verified again is weighed again (`recheck`: as it was decided and as
// it is weighed now, with the API's own words), and one its rules now stop
// can't be approved, so confirming rejects it instead (decision 18), which
// is said with each rule and what to do. Cancelling is the instant brake
// (partner decision 10): one click, no step-up and no confirm, then said
// done. Who may decide is the API's to say: the buttons show for an admin or
// approver only, and the API checks again whatever is pressed.
import { useQueryClient } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { useId, useState } from 'react';

import { api, ApiError, isRefusal, isSignedOut } from '../api.ts';
import { Confirm } from '../confirm.tsx';
import {
  amountText,
  type ApproveAsked,
  isCancellable,
  type Reason,
  type RequestDetails,
  timeText,
  useRequest,
  waitingLeft,
} from '../requests.ts';
import { endSession, useActing } from '../session.tsx';
import { type Asked, askFirst, StepUpStorageBlocked } from '../step-up.ts';
import { t, type TextKey } from '../text.ts';
import { Loading, Retry } from './failed.tsx';

/** The plain words for a refusal the person can act on; the code for any other. */
const REFUSALS = new Set([
  'REQUEST_NOT_WAITING',
  'REQUEST_EXPIRED',
  'REQUEST_CHANGED',
  'RECHECK_REQUIRED',
  'RECHECK_NOT_OFFERED',
  'ADMIN_APPROVAL_ONLY',
  'REQUEST_NOT_CANCELLABLE',
  'ORG_FROZEN',
  'FORBIDDEN',
  'NOT_FOUND',
]);

function refusalWords(error: unknown): string {
  if (error instanceof StepUpStorageBlocked) return t('request.storageBlocked');
  if (!isRefusal(error)) return t('request.failed');
  return REFUSALS.has(error.code)
    ? t(`request.refused.${error.code}` as TextKey)
    : t('request.refused.other', { code: error.code });
}

/** What's open over the page: the reject's reason, or an approve's answer to look at before the passkey. */
type Open =
  | { readonly kind: 'none' }
  | { readonly kind: 'reject' }
  | { readonly kind: 'weighed'; readonly answer: ApproveAsked; readonly stepUp: Asked['stepUp'] };

const NONE: Open = { kind: 'none' };

function Reasons({ reasons }: { readonly reasons: readonly Reason[] }) {
  return (
    <>
      {reasons.map((reason) => (
        <span key={reason.code} className="reason">
          {reason.message}
        </span>
      ))}
    </>
  );
}

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
            <Reasons reasons={request.reasons} />
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

/** An approve's answer, before the passkey: how it is weighed now, and what stops it, if anything. */
function Weighed({ answer }: { readonly answer: ApproveAsked }) {
  return (
    <>
      {answer.recheck !== null && (
        <dl className="facts">
          <dt>{t('request.decidedAs')}</dt>
          <dd>
            <b>{t(`decision.${answer.recheck.decidedAs}`)}</b>
            <Reasons reasons={answer.recheck.decidedReasons} />
          </dd>
          <dt>{t('request.weighedNow')}</dt>
          <dd>
            <b>{t(`decision.${answer.recheck.decision}`)}</b>
            <Reasons reasons={answer.recheck.reasons} />
          </dd>
        </dl>
      )}
      {answer.rejection !== null && (
        <div className="notice" role="alert">
          <p>{t('request.cannotApproveText')}</p>
          {answer.rejection.map((rule) => (
            <p key={rule.code}>
              {rule.message} {rule.whatToDo}
            </p>
          ))}
        </div>
      )}
    </>
  );
}

function Actions({ request }: { readonly request: RequestDetails }) {
  const { organization } = useActing();
  const queries = useQueryClient();
  const [open, setOpen] = useState<Open>(NONE);
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [said, setSaid] = useState<string | null>(null);
  const reasonId = useId();
  const names = { amount: amountText(request.amountMinor, request.currency), supplier: request.supplier.name };
  const path = `/v1/spend-requests/${encodeURIComponent(request.id)}`;
  const waiting = request.status === 'APPROVAL_REQUIRED';
  const deciding = organization.role === 'admin' || organization.role === 'approver';
  if (!deciding) return isCancellable(request.status) ? <p className="muted">{t('request.viewOnly')}</p> : null;

  const close = (): void => {
    setOpen(NONE);
  };
  const reread = () => queries.invalidateQueries({ queryKey: ['requests', organization.id] });
  /**
   * Sends a change. Left to sign in again, or held open for the person to
   * look at: nothing more. Otherwise read again, done or refused (a refusal
   * says the request moved on, so its page must show where it stands); a
   * failure on the way is said, and a 401 goes to sign-in.
   */
  const run = async (send: () => Promise<unknown>, done?: string) => {
    setBusy(true);
    setSaid(null);
    try {
      const sent = await send();
      if (sent === 'stepping' || sent === 'held') return;
      close();
      if (done !== undefined) setSaid(done);
      await reread();
    } catch (error) {
      if (isSignedOut(error)) {
        endSession(queries);
        return;
      }
      close();
      setSaid(refusalWords(error));
      if (isRefusal(error)) await reread();
    } finally {
      setBusy(false);
    }
  };
  const decide = (action: 'approve' | 'reject', body: Readonly<Record<string, unknown>>) =>
    askFirst({
      label: t(`request.${action}Label`, names),
      askPath: `${path}/${action}`,
      confirmPath: `${path}/${action}/confirm`,
      body,
      organization: organization.id,
    });
  // Asked first: an answer that weighs it again, or would reject it, is shown before the passkey; any other goes on.
  const approve = () =>
    run(async () => {
      const asked = await decide('approve', request.needsRecheck ? { recheck: true } : {});
      if ('done' in asked) return asked;
      const answer = asked.answer as ApproveAsked;
      if (answer.recheck === null && answer.rejection === null) return asked.stepUp();
      setOpen({ kind: 'weighed', answer, stepUp: asked.stepUp });
      return 'held';
    });
  const reject = () =>
    run(async () => {
      const asked = await decide('reject', { reason: reason.trim() });
      return 'done' in asked ? asked : asked.stepUp();
    });
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
                setOpen({ kind: 'reject' });
              }}
            >
              {t('request.reject')}
            </button>
            <button type="button" className="primary" disabled={busy} onClick={() => void approve()}>
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
      {open.kind === 'weighed' && (
        <WeighedConfirm
          open={open}
          names={names}
          busy={busy}
          onCancel={close}
          onConfirm={(label) => void run(() => Promise.resolve(open.stepUp(label)))}
        />
      )}
      {open.kind === 'reject' && (
        <Confirm
          text={t('request.rejectText')}
          title={t('request.rejectTitle')}
          confirmLabel={t('request.rejectConfirm')}
          busy={busy}
          ready={reason.trim().length > 0}
          onCancel={close}
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

/**
 * An approve's answer to confirm before the passkey. Re-checked: in the
 * API's `recheck` words. Stopped by its rules now: confirming rejects it, so
 * the change is kept as a reject, and said so on the way back.
 */
function WeighedConfirm({
  open,
  names,
  busy,
  onCancel,
  onConfirm,
}: {
  readonly open: Extract<Open, { kind: 'weighed' }>;
  readonly names: Readonly<Record<'amount' | 'supplier', string>>;
  readonly busy: boolean;
  readonly onCancel: () => void;
  readonly onConfirm: (label: string) => void;
}) {
  const rejects = open.answer.rejection !== null;
  const label = t(rejects ? 'request.rejectInsteadLabel' : 'request.approveLabel', names);
  const shared = {
    title: t(rejects ? 'request.cannotApproveTitle' : 'request.recheckTitle'),
    confirmLabel: t(rejects ? 'request.cannotApproveConfirm' : 'request.recheckConfirm'),
    busy,
    onCancel,
    onConfirm: () => {
      onConfirm(label);
    },
  };
  const body = (
    <>
      <p className="amount">{label}</p>
      <Weighed answer={open.answer} />
    </>
  );
  // Re-checked, the API's words are confirmed (its signed event names their version); otherwise the console's own.
  return open.answer.recheck !== null ? (
    <Confirm statement="recheck" {...shared}>
      {body}
    </Confirm>
  ) : (
    <Confirm text={t('request.cannotApproveConfirmText')} {...shared}>
      {body}
    </Confirm>
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
  if (request.isPending) return <Loading />;
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
  const left = waitingLeft(shown);
  return (
    <section className="stack request">
      {back}
      <span className="kicker">{left !== null ? t('request.waiting', { left }) : t(`status.${shown.status}`)}</span>
      <h1 className="amount big">{amountText(shown.amountMinor, shown.currency)}</h1>
      <Facts request={shown} />
      <Decided request={shown} />
      <Actions request={shown} />
    </section>
  );
}
