// One mandate's page (6D3a): `/more/mandates/<id>`, from its row on the
// Mandates list. Everything the API gives in plain words: its agent (linked to
// the agent's page), status, time zone and split window (fixed when drafted),
// who accepted the version in force and when, the agent's monthly cap and
// where it comes from, and the terms: the version in force, the waiting draft,
// or both side by side with what the draft changes marked. An admin accepts
// the draft, drafts a new version, and suspends, resumes, revokes or makes the
// over-limit choice here (mandate-actions.tsx).
import { Link } from '@tanstack/react-router';

import { useAgent, useMembers } from '../agents.ts';
import { isMissing } from '../api.ts';
import { isEnded, MANAGING, type MandateDetails, useMandate } from '../mandates.ts';
import { amountText, timeText } from '../requests.ts';
import { useActing } from '../session.tsx';
import { t } from '../text.ts';
import { memberText } from './agent.tsx';
import { Loading, NotShown, Retry } from './failed.tsx';
import { MandateActions } from './mandate-actions.tsx';
import { TermsTable } from './mandate-terms.tsx';

/** The agent's monthly cap the organisation's policies hold it to, and where it comes from. */
function capText({ agentMonthlyCap: cap }: MandateDetails): string {
  const from = t(`mandates.cap.${cap.from}`);
  return cap.capMinor === null || cap.currency === null ? from : `${amountText(cap.capMinor, cap.currency)} · ${from}`;
}

function MandateShown({ mandate }: { readonly mandate: MandateDetails }) {
  const { organization, session } = useActing();
  const agent = useAgent(mandate.agentId, organization.id);
  const members = useMembers(organization.id);
  const me = session.userId.toLowerCase();
  const accepter = (members.data ?? []).find((member) => member.id === mandate.acceptedBy);
  const { current, pending } = mandate;
  return (
    <>
      <span className="kicker">{t(`mandates.status.${mandate.status}`)}</span>
      <h1>{(current ?? pending)?.purpose ?? mandate.id}</h1>
      <p className="muted">{t(`mandates.statusSays.${mandate.status}`)}</p>
      <dl className="facts">
        <dt>{t('mandates.id')}</dt>
        <dd className="mono">{mandate.id}</dd>
        <dt>{t('mandates.agent')}</dt>
        <dd>
          <Link to="/agents/$id" params={{ id: mandate.agentId }}>
            {agent.data?.agent.name ?? mandate.agentId}
          </Link>
        </dd>
        <dt>{t('mandates.timeZone')}</dt>
        <dd>{mandate.timeZone}</dd>
        <dt>{t('mandates.splitWindow')}</dt>
        <dd>{t('mandates.hours', { hours: String(mandate.splitWindowHours) })}</dd>
        {mandate.acceptedAt !== null && (
          <>
            <dt>{t('mandates.acceptedBy')}</dt>
            <dd>
              {memberText(accepter, me)} · {timeText(mandate.acceptedAt)}
            </dd>
          </>
        )}
        <dt>{t('mandates.cap')}</dt>
        <dd>{capText(mandate)}</dd>
      </dl>
      <section className="stack" aria-labelledby="terms-title">
        <h2 id="terms-title">{t('mandates.terms')}</h2>
        {current !== null && pending !== null && <p className="muted">{t('mandates.compare')}</p>}
        {current === null && pending === null ? (
          <p className="muted">{t('mandates.noVersion')}</p>
        ) : (
          <TermsTable current={current} pending={pending} />
        )}
      </section>
      {MANAGING.includes(organization.role) && !isEnded(mandate.status) && (current ?? pending) !== null && (
        <Link to="/more/mandates/$id/new-version" params={{ id: mandate.id }}>
          {t('mandates.redraft.open')}
        </Link>
      )}
      <MandateActions mandate={mandate} />
    </>
  );
}

export function MandatePage({ id }: { readonly id: string }) {
  const { organization } = useActing();
  const shown = useMandate(id, organization.id);
  const back = (
    <Link to="/more/mandates" className="back">
      {t('mandates.back')}
    </Link>
  );
  const missing = isMissing(id, shown.error);
  const mandate = shown.data;
  if (missing || (shown.isError && mandate === undefined)) {
    return (
      <NotShown
        back={back}
        missing={missing}
        error={shown.error}
        notFound={t('mandates.notFound')}
        integrity={t('mandates.integrity')}
        onRetry={() => void shown.refetch()}
      />
    );
  }
  if (mandate === undefined) return <Loading />;
  return (
    <section className="stack request">
      {back}
      {shown.isError && <Retry onRetry={() => void shown.refetch()} />}
      <MandateShown mandate={mandate} />
    </section>
  );
}
