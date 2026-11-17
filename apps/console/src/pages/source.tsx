// One bank account's page (6D4a): `/more/sources/<id>`, from its row on the
// Bank accounts list (where its brake stays, 6B2). The account as the API
// gives it: the holder, the masked account, Agent X's status and the bank's,
// the consent and when it runs out, the bank's limits, and the admin's choice
// for when the consent runs out; never a number or balance, which the API
// never gives. An admin may ask the bank how it stands now (refresh) and
// change the consent-expiry choice, in the API's `consent_expiry` words with
// none picked. Neither asks a passkey of the API today; if it ever does, the
// shared step-up takes it (ask). Buttons show by role; the API checks again.
import { Link } from '@tanstack/react-router';
import { useState } from 'react';

import { isIntegrityFailed, isMissing } from '../api.ts';
import { Confirm } from '../confirm.tsx';
import { leftText, leftWords, timeText, useTicking } from '../requests.ts';
import { useActing } from '../session.tsx';
import { limitText, LINKING, type Source, sourceAt, sourceRefusal, useSource } from '../sources.ts';
import { ask, changeAt } from '../step-up.ts';
import { t } from '../text.ts';
import { Said, useChange } from './change.tsx';
import { Loading, NotShown, Retry } from './failed.tsx';

/** The account's facts, as the API gives them. */
function Facts({ source }: { readonly source: Source }) {
  const { controls } = source;
  const period = t(`sources.period.${controls.period}`);
  return (
    <dl className="facts">
      <dt>{t('sources.account')}</dt>
      <dd className="mono">{source.hint}</dd>
      <dt>{t('sources.accountType')}</dt>
      <dd>{t(`sources.accountType.${source.accountType}`)}</dd>
      <dt>{t('sources.id')}</dt>
      <dd className="mono">{source.id}</dd>
      <dt>{t('sources.status')}</dt>
      <dd>{t(`sources.status.${source.status}`)}</dd>
      <dt>{t('sources.availability')}</dt>
      <dd>{t(`sources.availability.${source.availability}`)}</dd>
      <dt>{t('sources.consent')}</dt>
      <dd>
        <span className="mono">{source.consentStatus}</span> <span className="muted">{t('sources.consentWord')}</span>
      </dd>
      <dt>{t('sources.consentEnds')}</dt>
      <dd>
        {timeText(source.consentExpiresAt)}{' '}
        <span className="muted">
          {leftText(source.consentExpiresAt) === null ? t('sources.consentRanOut') : leftWords(source.consentExpiresAt)}
        </span>
      </dd>
      <dt>{t('sources.maxPayment')}</dt>
      <dd>{limitText(controls.maxPaymentMinor, controls.currency)}</dd>
      <dt>{t('sources.maxPeriod', { period })}</dt>
      <dd>{limitText(controls.maxPeriodMinor, controls.currency)}</dd>
      <dt>{t('sources.maxPayments', { period })}</dt>
      <dd>{String(controls.maxPeriodPayments)}</dd>
    </dl>
  );
}

/** Asking the bank partner how the account stands now: an admin's. */
function Refresh({ source }: { readonly source: Source }) {
  const { organization } = useActing();
  const { busy, said, run } = useChange(sourceRefusal);
  const refresh = () =>
    run(
      () =>
        ask(
          changeAt(
            `${sourceAt(source.id)}/refresh`,
            t('sources.refresh.label', { name: source.holderName }),
            {},
            organization.id,
          ),
        ),
      { done: t('sources.refresh.done') },
    );
  return (
    <section className="stack" aria-labelledby="refresh-title">
      <h2 id="refresh-title">{t('sources.refresh.title')}</h2>
      <p className="muted">{t('sources.refresh.body')}</p>
      <button type="button" className="secondary" disabled={busy} onClick={() => void refresh()}>
        {t('sources.refresh.button')}
      </button>
      <Said said={said} />
    </section>
  );
}

/** What the admin chose for when the consent runs out, and an admin's way to choose again, none picked. */
function ConsentExpiry({ source }: { readonly source: Source }) {
  const { organization } = useActing();
  const { busy, said, run } = useChange(sourceRefusal);
  const [open, setOpen] = useState(false);
  const may = LINKING.includes(organization.role) && source.status !== 'ENDED';
  const close = () => {
    setOpen(false);
  };
  const choose = (consentExpiry: string, statementVersion?: number) =>
    run(
      () =>
        ask(
          changeAt(
            `${sourceAt(source.id)}/consent-expiry`,
            t('sources.expiry.label', { name: source.holderName }),
            { consentExpiry, statementVersion },
            organization.id,
          ),
        ),
      { done: t('sources.expiry.done'), after: close },
    );
  return (
    <section className="stack" aria-labelledby="expiry-title">
      <h2 id="expiry-title">{t('sources.expiry.title')}</h2>
      <p>{t(`sources.expiry.${source.consentExpiry ?? 'none'}`)}</p>
      {may && (
        <button
          type="button"
          className="secondary"
          disabled={busy}
          onClick={() => {
            setOpen(true);
          }}
        >
          {t('sources.expiry.button')}
        </button>
      )}
      <Said said={said} />
      {open && (
        <Confirm
          statement="consent_expiry"
          title={t('sources.expiry.confirmTitle', { name: source.holderName })}
          confirmLabel={t('sources.expiry.confirm')}
          busy={busy}
          onCancel={close}
          onConfirm={(choice, version) => void choose(choice, version)}
        >
          <p className="amount">
            {source.holderName} <span className="mono">{source.hint}</span>
          </p>
        </Confirm>
      )}
    </section>
  );
}

function SourceShown({ source }: { readonly source: Source }) {
  const { organization } = useActing();
  // The consent's time left counts down while the page is open.
  useTicking();
  const admin = LINKING.includes(organization.role);
  return (
    <>
      <span className="kicker">{t(`sources.status.${source.status}`)}</span>
      <h1>{source.holderName}</h1>
      <Facts source={source} />
      <p className="muted">{t('sources.brakeOnList')}</p>
      {!admin && <p className="muted">{t('sources.viewOnly')}</p>}
      {admin && source.status !== 'ENDED' && <Refresh source={source} />}
      <ConsentExpiry source={source} />
    </>
  );
}

export function SourcePage({ id }: { readonly id: string }) {
  const { organization } = useActing();
  const shown = useSource(id, organization.id);
  const back = (
    <Link to="/more/sources" className="back">
      {t('sources.back')}
    </Link>
  );
  const missing = isMissing(id, shown.error);
  const source = shown.data;
  // A re-read that fails once the account is shown keeps the page, said in place.
  if (missing || (shown.isError && source === undefined)) {
    return (
      <NotShown
        back={back}
        missing={missing}
        error={shown.error}
        notFound={t('sources.notFound')}
        integrity={t('sources.integrity')}
        onRetry={() => void shown.refetch()}
      />
    );
  }
  if (source === undefined) return <Loading />;
  return (
    <section className="stack request">
      {back}
      {shown.isError &&
        (isIntegrityFailed(shown.error) ? (
          <p className="notice">{t('sources.integrity')}</p>
        ) : (
          <Retry onRetry={() => void shown.refetch()} />
        ))}
      <SourceShown source={source} />
    </section>
  );
}
