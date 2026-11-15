// One payment's page (6C1): everything the team is shown of it, with its
// history newest first, downloadable as the API gave it (CO6: the trail
// downloadable). An UNKNOWN payment can be marked failed by two admins once
// their bank has confirmed in writing it never accepted it (decision 38;
// payment-marks.ts in the API): one proposes with the bank's reference, a
// second confirms the proposal, and any admin may withdraw it. Each step is
// confirmed in the API's own words (`mark_failed`, the invoice could be paid
// twice) or, to withdraw, the console's, then by passkey (the shared step-up).
// The buttons show for an admin only; the API checks again whatever is pressed.
import { Link } from '@tanstack/react-router';
import { useState } from 'react';

import { ApiError, isUuid } from '../api.ts';
import { Confirm } from '../confirm.tsx';
import {
  downloadHistory,
  EVIDENCE_MOST,
  EVIDENCE_REFERENCE,
  isIntegrityFailed,
  MARK_FAILED_CONFIRMED,
  markRefusal,
  type PaymentDetails,
  type Proposal,
  type TimelineEntry,
  usePayment,
} from '../payments.ts';
import { amountText, timeText } from '../requests.ts';
import { useActing } from '../session.tsx';
import { type Asked, ask, askFirst } from '../step-up.ts';
import { t } from '../text.ts';
import { Said, useChange } from './brakes.tsx';
import { Loading, Retry } from './failed.tsx';
import { LineField } from './line-field.tsx';

/** A fact shown only when the API has one (the partner's reference, the bank's word, a reject code). */
function Maybe({ label, value }: { readonly label: string; readonly value: string | null }) {
  return value === null ? null : (
    <>
      <dt>{label}</dt>
      <dd className="mono">{value}</dd>
    </>
  );
}

function Facts({ payment }: { readonly payment: PaymentDetails }) {
  return (
    <dl className="facts">
      <dt>{t('payments.supplier')}</dt>
      <dd>
        {payment.supplier.name} <span className="mono">{payment.supplier.id}</span>
      </dd>
      <dt>{t('request.bankReference')}</dt>
      <dd className="mono">{payment.bankReference}</dd>
      <Maybe label={t('payments.partnerReference')} value={payment.partnerReference} />
      <Maybe label={t('payments.bankStatus')} value={payment.bankStatus} />
      <Maybe label={t('payments.rejectCode')} value={payment.rejectCode} />
      <dt>{t('payments.handedOff')}</dt>
      <dd>{timeText(payment.createdAt)}</dd>
      <dt>{t('request.changed')}</dt>
      <dd>{timeText(payment.changedAt)}</dd>
      <dt>{t('payments.request')}</dt>
      <dd>
        <Link to="/approvals/$id" params={{ id: payment.spendRequestId }} className="mono">
          {payment.spendRequestId}
        </Link>
      </dd>
      <dt>{t('payments.id')}</dt>
      <dd className="mono">{payment.id}</dd>
    </dl>
  );
}

function Event({ entry }: { readonly entry: TimelineEntry }) {
  const said = [timeText(entry.at)];
  if (entry.status !== null) said.push(t(`payments.status.${entry.status}`));
  return (
    <li className="row">
      <span className="row-main">
        <span className="mono">{entry.what}</span>
        <span className="muted">{said.join(' · ')}</span>
        <span className="muted">
          {t(`payments.by.${entry.by.type}`)} <span className="mono">{entry.by.id}</span>
          {entry.via !== null && (
            <>
              {' · '}
              {t('payments.via', { via: entry.via })}
            </>
          )}
        </span>
        {entry.evidenceRef !== null && (
          <span className="muted">
            {t('payments.evidence')} <span className="mono">{entry.evidenceRef}</span>
          </span>
        )}
      </span>
    </li>
  );
}

/** Its history, newest first (the API gives it oldest first), saying when older events were left out. */
function History({ payment }: { readonly payment: PaymentDetails }) {
  return (
    <section className="stack" aria-labelledby="history-title">
      <h2 id="history-title">{t('payments.history')}</h2>
      <ol className="rows">
        {payment.timeline.toReversed().map((entry, at) => (
          // Two events may share their time: their place in the history, never reordered while shown, tells them apart.
          <Event key={`${entry.at}-${String(at)}`} entry={entry} />
        ))}
      </ol>
      {payment.earlier && <p className="muted">{t('payments.earlier')}</p>}
      <button
        type="button"
        className="secondary"
        onClick={() => {
          downloadHistory(payment);
        }}
      >
        {t('payments.download')}
      </button>
    </section>
  );
}

/** What's open over the page: a step's confirm, an approve's with the proposal its ask answered. */
type Open =
  | { readonly kind: 'none' }
  | { readonly kind: 'propose' }
  | { readonly kind: 'withdraw' }
  | { readonly kind: 'approve'; readonly proposal: Proposal; readonly stepUp: Asked['stepUp'] };

const NONE: Open = { kind: 'none' };

function Proposed({ proposal, mine }: { readonly proposal: Proposal; readonly mine: boolean }) {
  return (
    <dl className="facts">
      <dt>{t('payments.proposedBy')}</dt>
      <dd>
        <span className="mono">{proposal.proposedBy}</span>
        {mine && ` ${t('payments.you')}`}
      </dd>
      <dt>{t('payments.proposedAt')}</dt>
      <dd>{timeText(proposal.proposedAt)}</dd>
      <dt>{t('payments.evidence')}</dt>
      <dd className="mono">{proposal.evidenceRef}</dd>
    </dl>
  );
}

/** Marking an UNKNOWN payment failed: from when, the proposal open if any, and each admin's step. */
function MarkFailed({ payment }: { readonly payment: PaymentDetails }) {
  const { organization, session } = useActing();
  const { busy, said, run } = useChange(markRefusal);
  const [open, setOpen] = useState<Open>(NONE);
  const [reference, setReference] = useState('');
  const [broken, setBroken] = useState(false);
  const mark = payment.markFailed;
  if (mark === null || organization.role !== 'admin') return null;
  const names = { amount: amountText(payment.amountMinor, payment.currency), supplier: payment.supplier.name };
  const path = `/v1/payments/${encodeURIComponent(payment.id)}/failure-proposal`;
  const change = (step: 'propose' | 'approve' | 'withdraw', body: Readonly<Record<string, unknown>>) => {
    const at = step === 'propose' ? path : `${path}/${step}`;
    return {
      label: t(`payments.${step}Label`, names),
      askPath: at,
      confirmPath: `${at}/confirm`,
      body,
      organization: organization.id,
    };
  };
  const close = () => {
    setOpen(NONE);
  };
  const done = t('payments.markDone');
  // The reference and the consequence are asked with; the version of the words shown goes with the confirm (CO3).
  const propose = (statementVersion?: number) =>
    run(
      () =>
        ask(change('propose', { evidenceRef: reference.trim(), confirmed: MARK_FAILED_CONFIRMED }), {
          statementVersion,
        }),
      done,
      close,
    );
  // Asked first, as its answer names the proposal confirmed: shown with the words before the passkey.
  const approve = () =>
    run(
      async () => {
        const asked = await askFirst(change('approve', { confirmed: MARK_FAILED_CONFIRMED }));
        if ('done' in asked) return asked;
        const { proposal } = asked.answer as { readonly proposal: Proposal };
        setOpen({ kind: 'approve', proposal, stepUp: asked.stepUp });
        return 'held';
      },
      done,
      close,
    );
  const withdraw = () => run(() => ask(change('withdraw', {})), done, close);
  const proposal = mark.openProposal;
  const markable = Date.now() > new Date(mark.markableFrom).getTime();

  let step;
  if (proposal !== null) {
    step = (
      <>
        <p>{t('payments.proposalOpen')}</p>
        <Proposed proposal={proposal} mine={proposal.proposedBy === session.userId.toLowerCase()} />
        <div className="decide">
          <button
            type="button"
            className="secondary"
            disabled={busy}
            onClick={() => {
              setOpen({ kind: 'withdraw' });
            }}
          >
            {t('payments.withdraw')}
          </button>
          <button type="button" className="primary" disabled={busy} onClick={() => void approve()}>
            {t('payments.approve')}
          </button>
        </div>
      </>
    );
  } else if (markable) {
    step = (
      <>
        <LineField
          label={t('payments.evidenceLabel')}
          hint={t('payments.evidenceHint')}
          most={EVIDENCE_MOST}
          value={reference}
          onChange={(value) => {
            setReference(value);
            setBroken(false);
          }}
          broken={broken ? t('payments.evidenceBroken') : undefined}
        />
        <button
          type="button"
          className="primary"
          disabled={busy}
          onClick={() => {
            // Checked here by the API's own rule before anything is sent: a reference it would refuse is said in place.
            if (EVIDENCE_REFERENCE.test(reference.trim())) setOpen({ kind: 'propose' });
            else setBroken(true);
          }}
        >
          {t('payments.propose')}
        </button>
      </>
    );
  } else {
    step = <p className="muted">{t('payments.markableFrom', { time: timeText(mark.markableFrom) })}</p>;
  }

  return (
    <section className="stack" aria-labelledby="mark-title">
      <h2 id="mark-title">{t('payments.markTitle')}</h2>
      <p className="muted">{t('payments.markIntro')}</p>
      {step}
      <Said said={said} />
      {open.kind === 'propose' && (
        <Confirm
          statement="mark_failed"
          title={t('payments.proposeTitle')}
          confirmLabel={t('brakes.passkeyConfirm')}
          busy={busy}
          onCancel={close}
          onConfirm={(_choice, version) => void propose(version)}
        >
          <p className="amount">{t('payments.proposeLabel', names)}</p>
          <p>
            {t('payments.evidence')} <span className="mono">{reference.trim()}</span>
          </p>
        </Confirm>
      )}
      {open.kind === 'approve' && (
        <Confirm
          statement="mark_failed"
          title={t('payments.approveTitle')}
          confirmLabel={t('brakes.passkeyConfirm')}
          busy={busy}
          onCancel={close}
          onConfirm={(_choice, statementVersion) =>
            void run(() => Promise.resolve(open.stepUp(undefined, { statementVersion })), done, close)
          }
        >
          <p className="amount">{t('payments.approveLabel', names)}</p>
          <Proposed proposal={open.proposal} mine={open.proposal.proposedBy === session.userId.toLowerCase()} />
        </Confirm>
      )}
      {open.kind === 'withdraw' && (
        <Confirm
          text={t('payments.withdrawText')}
          title={t('payments.withdrawTitle')}
          confirmLabel={t('brakes.passkeyConfirm')}
          busy={busy}
          onCancel={close}
          onConfirm={() => void withdraw()}
        >
          <p className="amount">{t('payments.withdrawLabel', names)}</p>
        </Confirm>
      )}
    </section>
  );
}

export function PaymentPage({ id }: { readonly id: string }) {
  const { organization } = useActing();
  const payment = usePayment(id, organization.id);
  const back = (
    <Link to="/payments" className="back">
      {t('payments.back')}
    </Link>
  );
  // An address that isn't a payment's ID names none: not found, as the API's 404 is, never a failure to retry.
  const missing = !isUuid(id) || (payment.error instanceof ApiError && payment.error.status === 404);
  if (missing || payment.isError) {
    let said = <Retry onRetry={() => void payment.refetch()} />;
    if (missing) said = <p className="notice">{t('payments.notFound')}</p>;
    else if (isIntegrityFailed(payment.error)) said = <p className="notice">{t('payments.integrity')}</p>;
    return (
      <section className="stack">
        {back}
        {said}
      </section>
    );
  }
  if (payment.isPending) return <Loading />;
  const shown = payment.data;
  return (
    <section className="stack request">
      {back}
      <span className="kicker">{t(`payments.status.${shown.status}`)}</span>
      <h1 className="amount big">{amountText(shown.amountMinor, shown.currency)}</h1>
      {shown.contradicted && <p className="notice">{t('payments.why.contradicted')}</p>}
      {shown.status === 'UNKNOWN' && <p className="notice">{t('payments.why.unknown')}</p>}
      <Facts payment={shown} />
      <MarkFailed payment={shown} />
      <History payment={shown} />
    </section>
  );
}
