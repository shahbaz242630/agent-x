// One supplier's page (6D2): `/more/suppliers/<id>`, from its row on the
// Suppliers list (where its brake stays, 6B2). Its details as the API gives
// them: the call-back phone and since when, the independent source it was
// checked against, who entered and who verified it, its cooling-off; its bank
// details as the payment partner described them, never an account number
// (supplier-bank.tsx); verifying it by a call-back (supplier-verify.tsx); and
// whether it is emailed when it is paid. Every change is by passkey but
// withdrawing new bank details, which is at once. Buttons show by role; the
// API checks again.
import { Link } from '@tanstack/react-router';
import { useState } from 'react';

import { useMembers } from '../agents.ts';
import { isMissing } from '../api.ts';
import { Confirm } from '../confirm.tsx';
import { leftWords, timeText, useTicking } from '../requests.ts';
import { useActing } from '../session.tsx';
import { ask, changeAt, mustStepUp } from '../step-up.ts';
import { ADDING, coolingOff, type Supplier, supplierAt, supplierRefusal, useSupplier } from '../suppliers.ts';
import { t } from '../text.ts';
import { memberText } from './agent.tsx';
import { Said, useChange } from './change.tsx';
import { Loading, NotShown } from './failed.tsx';
import { BankDetails } from './supplier-bank.tsx';
import { Verify } from './supplier-verify.tsx';

/** Whether the supplier is emailed when it is paid, and an admin's way to turn that the other way, by passkey. */
function Remittance({ supplier }: { readonly supplier: Supplier }) {
  const { organization } = useActing();
  const { busy, said, run } = useChange(supplierRefusal);
  const [open, setOpen] = useState(false);
  const now = supplier.remittanceEmail;
  const next = now === 'on' ? 'off' : 'on';
  const names = { name: supplier.displayName };
  const close = () => {
    setOpen(false);
  };
  const change = () =>
    run(
      () =>
        mustStepUp(
          ask(
            changeAt(
              `${supplierAt(supplier.id)}/remittance-email`,
              t(`suppliers.remittance.label.${next}`, names),
              { remittanceEmail: next },
              organization.id,
            ),
          ),
        ),
      { after: close },
    );
  return (
    <section className="stack" aria-labelledby="remittance-title">
      <h2 id="remittance-title">{t('suppliers.remittance.title')}</h2>
      <p>{t(`suppliers.remittance.${now}`)}</p>
      {supplier.email === null && <p className="muted">{t('suppliers.remittance.noEmail')}</p>}
      {ADDING.includes(organization.role) && (
        <button
          type="button"
          className="secondary"
          disabled={busy}
          onClick={() => {
            setOpen(true);
          }}
        >
          {t(`suppliers.remittance.turn.${next}`)}
        </button>
      )}
      <Said said={said} />
      {open && (
        <Confirm
          text={t(`suppliers.remittance.${next}`)}
          title={t(`suppliers.remittance.confirm.${next}`, names)}
          confirmLabel={t('brakes.passkeyConfirm')}
          busy={busy}
          onCancel={close}
          onConfirm={() => void change()}
        />
      )}
    </section>
  );
}

function SupplierShown({ supplier }: { readonly supplier: Supplier }) {
  const { organization, session } = useActing();
  const members = useMembers(organization.id);
  // The cooling-off's time left counts down while the page is open.
  useTicking();
  const me = session.userId.toLowerCase();
  const listed = members.data ?? [];
  const who = (membership: string) =>
    memberText(
      listed.find((member) => member.id === membership),
      me,
    );
  const cooling = coolingOff(supplier) ? supplier.coolingOffUntil : null;
  return (
    <>
      <span className="kicker">{t(`brakes.supplier.${supplier.status}`)}</span>
      <h1>{supplier.displayName}</h1>
      <dl className="facts">
        <dt>{t('suppliers.id')}</dt>
        <dd className="mono">{supplier.id}</dd>
        <dt>{t('suppliers.phone')}</dt>
        <dd>
          <span className="mono">{supplier.phone}</span>{' '}
          <span className="muted">{t('suppliers.phoneSince', { time: timeText(supplier.phoneSince) })}</span>
        </dd>
        <dt>{t('suppliers.email')}</dt>
        <dd>{supplier.email ?? t('suppliers.notGiven')}</dd>
        <dt>{t('suppliers.tradeLicence')}</dt>
        <dd>{supplier.tradeLicence ?? t('suppliers.notGiven')}</dd>
        <dt>{t('suppliers.source')}</dt>
        <dd>{t(`suppliers.source.${supplier.source.kind}`, { ref: supplier.source.ref })}</dd>
        <dt>{t('suppliers.entered')}</dt>
        <dd>
          {who(supplier.enteredBy)} · {timeText(supplier.enteredAt)}
        </dd>
        {supplier.verifiedBy !== null && (
          <>
            <dt>{t('suppliers.verifiedBy')}</dt>
            <dd>{who(supplier.verifiedBy)}</dd>
          </>
        )}
        {cooling !== null && (
          <>
            <dt>{t('suppliers.coolingOff')}</dt>
            <dd>
              {timeText(cooling)} <span className="muted">{leftWords(cooling)}</span>
            </dd>
          </>
        )}
      </dl>
      <p className="muted">{t('suppliers.brakeOnList')}</p>
      <BankDetails supplier={supplier} />
      <Verify supplier={supplier} />
      <Remittance supplier={supplier} />
    </>
  );
}

export function SupplierPage({ id }: { readonly id: string }) {
  const { organization } = useActing();
  const shown = useSupplier(id, organization.id);
  const back = (
    <Link to="/more/suppliers" className="back">
      {t('suppliers.back')}
    </Link>
  );
  const missing = isMissing(id, shown.error);
  if (missing || shown.isError) {
    return (
      <NotShown
        back={back}
        missing={missing}
        error={shown.error}
        notFound={t('suppliers.notFound')}
        integrity={t('suppliers.integrity')}
        onRetry={() => void shown.refetch()}
      />
    );
  }
  if (shown.isPending) return <Loading />;
  return (
    <section className="stack request">
      {back}
      <SupplierShown supplier={shown.data} />
    </section>
  );
}
