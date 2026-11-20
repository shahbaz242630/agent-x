// A spend request's evidence, printable (6C2, 6C2c; BR-16; decision 24:
// admins only): `/approvals/<id>/evidence`. Opening it reads the bundle
// (evidence.ts), a page read the audit log doesn't record, as the page says;
// it is shown in plain sections, from the request as asked to its payment,
// then every signed event about it with its chain hashes. "Print" prints what
// was read without the console's frame (styles.css, @media print); "Download
// JSON" is the logged download (capped at 20 an hour), saving the API's answer
// as it came, `evidence-<id>.json`, to check outside Agent X.
import { Link } from '@tanstack/react-router';
import type { ReactNode } from 'react';

import { isMissing } from '../api.ts';
import { type Evidence, type EvidencePayment, evidenceRefusal, useEvidence, useEvidenceDownload } from '../evidence.ts';
import type { LogEvent } from '../logs.ts';
import { amountText, type Reason, timeText } from '../requests.ts';
import { useActing } from '../session.tsx';
import { t } from '../text.ts';
import { Loading } from './failed.tsx';
import { ActorLine, EventTable } from './log-event.tsx';

/** A fact; one the API has none for says so, so a printed record never leaves a blank to guess at. */
function Fact({
  label,
  value,
  mono = false,
}: {
  readonly label: string;
  readonly value: ReactNode;
  readonly mono?: boolean;
}) {
  return (
    <>
      <dt>{label}</dt>
      <dd className={mono ? 'mono' : undefined}>{value ?? t('evidence.none')}</dd>
    </>
  );
}

const timeOrNone = (at: string | null): string | null => (at === null ? null : timeText(at));

/** The reasons in the API's own words, one after another. */
const reasonsText = (reasons: readonly Reason[]): string => reasons.map((reason) => reason.message).join(' ');

function Part({ title, children }: { readonly title: string; readonly children: ReactNode }) {
  return (
    <section className="stack evidence-part">
      <h2>{title}</h2>
      {children}
    </section>
  );
}

/** A signed event the bundle names apart (an acceptance, a verification): when, who, and where it sits in the chain. */
function Signed({ event }: { readonly event: LogEvent | null }) {
  if (event === null) return t('evidence.notFound');
  return (
    <>
      {timeText(event.recordedAt)} · <span className="mono">#{event.seq}</span> <ActorLine actor={event.actor} />
    </>
  );
}

/** Who a person's decision was by: as its signed event in the bundle names them, else by their ID alone. */
function byWhom(evidence: Evidence, eventId: string, userId: string): ReactNode {
  const event = evidence.events.find((one) => one.id === eventId);
  return event === undefined ? <span className="mono">{userId}</span> : <ActorLine actor={event.actor} />;
}

function Request({ evidence }: { readonly evidence: Evidence }) {
  const asked = evidence.spendRequest;
  return (
    <Part title={t('evidence.request')}>
      <dl className="facts">
        <Fact label={t('evidence.status')} value={t(`status.${asked.status}`)} />
        <Fact label={t('request.supplier')} value={evidence.supplier.name ?? t('request.supplierUnknown')} />
        {/* The agent's own words, each isolated (<bdi>): a right-to-left mark or override in them can't reorder the page around them. */}
        <Fact label={t('request.invoice')} value={<bdi>{asked.orderReference}</bdi>} mono />
        <Fact label={t('request.purpose')} value={<bdi>{asked.purpose}</bdi>} />
        <Fact label={t('request.bankReference')} value={asked.bankReference} mono />
        <Fact label={t('evidence.idempotencyKey')} value={<bdi>{asked.idempotencyKey}</bdi>} mono />
        <Fact label={t('request.changed')} value={timeText(asked.changedAt)} />
        <Fact label={t('request.expires')} value={timeOrNone(asked.expiresAt)} />
        <Fact label={t('request.id')} value={asked.id} mono />
      </dl>
    </Part>
  );
}

function Decision({ evidence }: { readonly evidence: Evidence }) {
  const asked = evidence.spendRequest;
  const { mandate, policies } = evidence;
  return (
    <Part title={t('evidence.decision')}>
      <dl className="facts">
        <Fact label={t('evidence.decided')} value={t(`decision.${asked.decision}`)} />
        <Fact label={t('request.why')} value={asked.reasons.length === 0 ? null : reasonsText(asked.reasons)} />
        <Fact label={t('evidence.decidedAt')} value={timeOrNone(asked.decidedAt)} />
        <Fact label={t('evidence.inputHash')} value={asked.inputHash} mono />
        <Fact label={t('request.agent')} value={evidence.agent.name} />
        <Fact label={t('evidence.agentId')} value={evidence.agent.id} mono />
        <Fact label={t('evidence.agentKey')} value={evidence.agent.keyId} mono />
        <Fact label={t('evidence.mandate')} value={mandate?.id ?? t('evidence.noMandate')} mono={mandate !== null} />
        {mandate !== null && (
          <>
            <Fact label={t('evidence.mandateVersion')} value={mandate.versionId} mono />
            <Fact label={t('evidence.acceptance')} value={<Signed event={mandate.acceptance} />} />
          </>
        )}
        <Fact label={t('evidence.orgPolicy')} value={policies.organizationPolicyVersionId} mono />
        <Fact label={t('evidence.mandatePolicy')} value={policies.mandatePolicyVersionId} mono />
      </dl>
    </Part>
  );
}

function Supplier({ evidence }: { readonly evidence: Evidence }) {
  const { supplier, fundingSource } = evidence;
  return (
    <Part title={t('evidence.supplier')}>
      <dl className="facts">
        <Fact label={t('request.supplier')} value={supplier.name ?? t('request.supplierUnknown')} />
        <Fact label={t('evidence.supplierId')} value={supplier.id} mono />
        {/* None for a supplier the organisation doesn't have (S206 V8): no details it was decided under. */}
        <Fact
          label={t('evidence.supplierVersion')}
          value={
            supplier.version === null
              ? null
              : t('evidence.versionNamed', { number: String(supplier.version.number), name: supplier.version.name })
          }
        />
        <Fact
          label={t('evidence.verification')}
          value={supplier.version === null ? null : <Signed event={supplier.version.verification} />}
        />
        <Fact
          label={t('evidence.source')}
          value={
            fundingSource.holderName === null
              ? t('evidence.sourceUnknown')
              : `${fundingSource.holderName} · ${fundingSource.hint ?? ''}`
          }
        />
        <Fact label={t('evidence.sourcePartner')} value={fundingSource.partner} />
        <Fact label={t('evidence.sourceId')} value={fundingSource.id} mono />
      </dl>
    </Part>
  );
}

/** A person's approval or reject, a void, and the money held: each said as none where it didn't happen. */
function Outcome({ evidence }: { readonly evidence: Evidence }) {
  const { approval, rejection, voiding, reservation } = evidence;
  const changeHash = approval?.changeHash ?? null;
  return (
    <Part title={t('evidence.outcome')}>
      <dl className="facts">
        <Fact
          label={t('evidence.approval')}
          value={
            approval && (
              <>
                {timeText(approval.at)} {byWhom(evidence, approval.eventId, approval.byUserId)}
              </>
            )
          }
        />
        {changeHash !== null && <Fact label={t('evidence.changeHash')} value={changeHash} mono />}
        <Fact
          label={t('evidence.rejection')}
          value={
            rejection && (
              <>
                {timeText(rejection.at)} · {rejection.reason} {byWhom(evidence, rejection.eventId, rejection.byUserId)}
              </>
            )
          }
        />
        <Fact
          label={t('evidence.voiding')}
          value={
            voiding && [timeText(voiding.at), reasonsText(voiding.reasons)].filter((part) => part !== '').join(' · ')
          }
        />
        <Fact
          label={t('evidence.reservation')}
          value={
            reservation &&
            t('evidence.reserved', {
              state: t(`evidence.reservationState.${reservation.state}`),
              amount: amountText(reservation.amountMinor, reservation.currency),
              month: reservation.month,
              time: timeText(reservation.reservedAt),
            })
          }
        />
      </dl>
    </Part>
  );
}

function Payment({ payment }: { readonly payment: EvidencePayment | null }) {
  if (payment === null) {
    return (
      <Part title={t('evidence.payment')}>
        <p className="muted">{t('evidence.noPayment')}</p>
      </Part>
    );
  }
  const { instruction, reconciliation } = payment;
  return (
    <Part title={t('evidence.payment')}>
      <dl className="facts">
        <Fact label={t('evidence.status')} value={t(`payments.status.${payment.status}`)} />
        <Fact label={t('payments.partnerReference')} value={payment.partnerReference} mono />
        <Fact label={t('payments.bankStatus')} value={payment.bankStatus} mono />
        <Fact label={t('payments.rejectCode')} value={payment.rejectCode} mono />
        <Fact label={t('evidence.bankChanged')} value={timeOrNone(payment.bankChangedAt)} />
        <Fact label={t('payments.handedOff')} value={timeText(payment.createdAt)} />
        <Fact label={t('request.changed')} value={timeText(payment.changedAt)} />
        <Fact label={t('payments.id')} value={payment.id} mono />
        <Fact label={t('evidence.route')} value={`${instruction.route} · ${instruction.routeReason}`} />
        <Fact label={t('evidence.partner')} value={instruction.partner} />
        <Fact label={t('evidence.partnerEntity')} value={instruction.partnerLegalEntityId} mono />
        <Fact label={t('evidence.partnerLicence')} value={instruction.partnerLicenceRef} mono />
        <Fact label={t('evidence.paymentReference')} value={instruction.paymentReference} mono />
        <Fact label={t('evidence.intentHash')} value={instruction.intentHash} mono />
        <Fact label={t('evidence.instructionId')} value={instruction.id} mono />
        <Fact
          label={t('evidence.reconciliation')}
          value={t(reconciliation.contradicted ? 'payments.why.contradicted' : 'evidence.agrees')}
        />
        <Fact label={t('evidence.markableFrom')} value={timeOrNone(reconciliation.markableFrom)} />
        <Fact label={t('evidence.openProposal')} value={reconciliation.openProposalId} mono />
      </dl>
    </Part>
  );
}

/** "Download JSON": the logged download, one a press; its refusal said beside it, pressing again the same download. */
function Download({ id, organization }: { readonly id: string; readonly organization: string }) {
  const { press, download } = useEvidenceDownload(id, organization);
  return (
    <>
      <button type="button" className="secondary" disabled={download.isPending} onClick={press}>
        {t('evidence.downloadJson')}
      </button>
      {download.isError && (
        <p className="notice" role="alert">
          {evidenceRefusal(download.error)}
        </p>
      )}
    </>
  );
}

function Bundle({ evidence, organization }: { readonly evidence: Evidence; readonly organization: string }) {
  const asked = evidence.spendRequest;
  return (
    <>
      <h1 className="amount big">{amountText(asked.amountMinor, asked.currency)}</h1>
      <p className="muted">{t('evidence.moment', { upTo: evidence.upToSeq })}</p>
      <div className="decide no-print">
        <button
          type="button"
          className="secondary"
          onClick={() => {
            window.print();
          }}
        >
          {t('evidence.print')}
        </button>
        <Download id={asked.id} organization={organization} />
      </div>
      <Request evidence={evidence} />
      <Decision evidence={evidence} />
      <Supplier evidence={evidence} />
      <Outcome evidence={evidence} />
      <Payment payment={evidence.payment} />
      <Part title={t('evidence.events', { count: String(evidence.events.length) })}>
        <EventTable events={evidence.events} />
      </Part>
    </>
  );
}

export function EvidencePage({ id }: { readonly id: string }) {
  const { organization } = useActing();
  const admin = organization.role === 'admin';
  const evidence = useEvidence(id, organization.id, admin);
  const back = (
    <Link to="/approvals/$id" params={{ id }} className="back no-print">
      {t('evidence.back')}
    </Link>
  );
  let shown;
  if (!admin) shown = <p className="notice">{t('evidence.adminsOnly')}</p>;
  else if (isMissing(id, evidence.error)) shown = <p className="notice">{t('request.notFound')}</p>;
  else if (evidence.isError) {
    shown = (
      <div className="notice" role="alert">
        <p>{evidenceRefusal(evidence.error)}</p>
        {/* A read, not logged: asked again as it is. */}
        <button
          type="button"
          className="secondary"
          onClick={() => {
            void evidence.refetch();
          }}
        >
          {t('error.retry')}
        </button>
      </div>
    );
  } else if (evidence.isSuccess) shown = <Bundle evidence={evidence.data.evidence} organization={organization.id} />;
  else shown = <Loading />;
  return (
    <section className="stack request">
      {back}
      <span className="kicker">{t('evidence.title')}</span>
      {admin && <p className="fine no-print">{t('evidence.logged')}</p>}
      {shown}
    </section>
  );
}
