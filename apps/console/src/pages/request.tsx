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
// approver only, and the API checks again whatever is pressed. The agent is
// named with its ID, as two agents may share a name (SEC-AG-10).
import { Link } from '@tanstack/react-router';
import { useState } from 'react';

import { api, isMissing } from '../api.ts';
import { Confirm } from '../confirm.tsx';
import {
  amountText,
  type ApproveAsked,
  isCancellable,
  type Reason,
  type RequestDetails,
  timeText,
  useRequest,
  useTicking,
  waitingLeft,
} from '../requests.ts';
import { refusalText } from '../refusals.ts';
import { useActing } from '../session.tsx';
import { type Asked, askFirst, changeAt } from '../step-up.ts';
import { t } from '../text.ts';
import { Said, useChange } from './change.tsx';
import { Loading, NotShown } from './failed.tsx';
import { LineField, NOTE_MOST } from './line-field.tsx';

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
  'BAD_REQUEST',
  'FORBIDDEN',
  'NOT_FOUND',
]);

const refusalWords = (error: unknown): string => refusalText(error, REFUSALS, 'request.refused');

/** A reject's own words for a code: what it sent that can be refused is its reason. */
const rejectWords = (error: unknown): string =>
  refusalText(error, REFUSALS, 'request.refused', { BAD_REQUEST: 'request.refused.badReason' });

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
      <dd>{request.supplier.name ?? t('request.supplierUnknown')}</dd>
      <dt>{t('request.invoice')}</dt>
      {/* The agent's own words, each isolated (<bdi>): a right-to-left mark or override in them can't reorder the page around them. */}
      <dd className="mono">
        <bdi>{request.agentWrote.orderReference}</bdi>
      </dd>
      <dt>{t('request.purpose')}</dt>
      <dd>
        <bdi>{request.agentWrote.purpose}</bdi>
      </dd>
      <dt>{t('request.agent')}</dt>
      <dd>
        {request.agent.name} <span className="mono">{request.agent.id}</span>
      </dd>
      {request.reasons.length > 0 && (
        <>
          {/* Rejected, the rules' reasons are why it waited for a person, not why it ended (E6-P8). */}
          <dt>{t(request.rejection === null ? 'request.why' : 'request.whyWaited')}</dt>
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
      {/* Its own story ends with the bank (HANDED_OFF): the payment says how it came out (S212 G2). */}
      {request.payment !== null && (
        <>
          <dt>{t('request.payment')}</dt>
          <dd>
            {t(`payments.status.${request.payment.status}`)}{' '}
            <Link to="/payments/$id" params={{ id: request.payment.id }}>
              {t('request.seePayment')}
            </Link>
          </dd>
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
  const [open, setOpen] = useState<Open>(NONE);
  const [reason, setReason] = useState('');
  const { busy, said, run } = useChange(refusalWords);
  const names = {
    amount: amountText(request.amountMinor, request.currency),
    supplier: request.supplier.name ?? t('request.supplierUnknown'),
  };
  const path = `/v1/spend-requests/${encodeURIComponent(request.id)}`;
  const waiting = request.status === 'APPROVAL_REQUIRED';
  const deciding = organization.role === 'admin' || organization.role === 'approver';
  if (!deciding) return isCancellable(request.status) ? <p className="muted">{t('request.viewOnly')}</p> : null;

  const close = (): void => {
    setOpen(NONE);
  };
  const decide = (action: 'approve' | 'reject', body: Readonly<Record<string, unknown>>) =>
    askFirst(changeAt(`${path}/${action}`, t(`request.${action}Label`, names), body, organization.id));
  // Asked first: an answer that weighs it again, or would reject it, is shown before the passkey; any other goes on.
  const approve = () =>
    run(
      async () => {
        const asked = await decide('approve', request.needsRecheck ? { recheck: true } : {});
        if ('done' in asked) return asked;
        const answer = asked.answer as ApproveAsked;
        if (answer.recheck === null && answer.rejection === null) return asked.stepUp();
        setOpen({ kind: 'weighed', answer, stepUp: asked.stepUp });
        return 'held';
      },
      { after: close },
    );
  const reject = () =>
    run(
      async () => {
        const asked = await decide('reject', { reason: reason.trim() });
        return 'done' in asked ? asked : asked.stepUp();
      },
      { after: close, refusal: rejectWords },
    );
  const cancel = () =>
    run(() => api.post(`${path}/cancel`, { organization: organization.id, body: {} }), {
      done: t('request.cancelled'),
      after: close,
    });

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
      <Said said={said} />
      {open.kind === 'weighed' && (
        <WeighedConfirm
          open={open}
          names={names}
          busy={busy}
          onCancel={close}
          onConfirm={(label, confirmed) =>
            void run(() => Promise.resolve(open.stepUp(label, confirmed)), { after: close })
          }
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
          {/* One line of up to 200 characters, as the reason is kept for good (rejectReason): no long numbers. */}
          <LineField
            label={t('request.rejectReason')}
            hint={t('request.rejectReasonHint')}
            most={NOTE_MOST}
            value={reason}
            onChange={setReason}
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
  /** With the label kept, and what the confirm sends back: the version of the API's words shown, if any (CO3). */
  readonly onConfirm: (label: string, confirmed: Readonly<Record<string, unknown>>) => void;
}) {
  const rejects = open.answer.rejection !== null;
  const label = t(rejects ? 'request.rejectInsteadLabel' : 'request.approveLabel', names);
  const shared = {
    title: t(rejects ? 'request.cannotApproveTitle' : 'request.recheckTitle'),
    confirmLabel: t(rejects ? 'request.cannotApproveConfirm' : 'request.recheckConfirm'),
    busy,
    onCancel,
    onConfirm: (_choice: string, statementVersion?: number) => {
      onConfirm(label, statementVersion === undefined ? {} : { statementVersion });
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

/** The request's evidence, for an admin (decision 24): every request has it, a denied one too (BR-16). */
function EvidenceLink({ id }: { readonly id: string }) {
  const { organization } = useActing();
  if (organization.role !== 'admin') return null;
  return (
    <>
      <Link to="/approvals/$id/evidence" params={{ id }} className="secondary button">
        {t('evidence.open')}
      </Link>
      <p className="fine">{t('evidence.openFine')}</p>
    </>
  );
}

export function RequestPage({ id }: { readonly id: string }) {
  const { organization } = useActing();
  const request = useRequest(id, organization.id);
  useTicking();
  const back = (
    <Link to="/approvals" className="back">
      {t('request.back')}
    </Link>
  );
  const missing = isMissing(id, request.error);
  if (missing || request.isError) {
    return (
      <NotShown
        back={back}
        missing={missing}
        error={request.error}
        notFound={t('request.notFound')}
        onRetry={() => void request.refetch()}
      />
    );
  }
  if (request.isPending) return <Loading />;
  const shown = request.data;
  const left = waitingLeft(shown);
  return (
    <section className="stack request">
      {back}
      <span className="kicker">{left !== null ? t('request.waiting', { left }) : t(`status.${shown.status}`)}</span>
      <h1 className="amount big">{amountText(shown.amountMinor, shown.currency)}</h1>
      {/* How it ended first, then its facts (E6-P8: a reject's reason sat at the bottom, under the rules' "Why"). */}
      <Decided request={shown} />
      <Facts request={shown} />
      <Actions request={shown} />
      <EvidenceLink id={shown.id} />
    </section>
  );
}
