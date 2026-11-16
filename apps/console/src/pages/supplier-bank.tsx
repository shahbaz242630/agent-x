// A supplier's bank details (6D2, ADR-012 §1, ADR-014 §3, BR-21): its account
// as the payment partner described it (the last four characters, the holder's
// name as the bank masks it, the name check), never the number.
//
// New or changed details go to the partner, never into Agent X: typed here
// and passed straight through (POST …/payee-registrations/pass-through, held
// in this page's memory alone and cleared once sent), or entered on the
// partner's own page (POST …/payee-registrations, then …/check once done).
// Before either, the person is asked whether the supplier sent the details by
// email or a message (ADR-012: "Did the supplier tell you this by email? Call
// their known number first"): yes, and they are warned this is how payment
// fraud starts and must say they called the number on file first. What
// happens to pending requests is chosen in the API's `payee` words, none
// picked. The details then wait for the admin who entered them to confirm them
// by passkey (…/payee-change/approve), which starts the 24-hour cooling-off;
// an admin or approver can withdraw them at once instead.
import { useState } from 'react';

import { api, ApiError } from '../api.ts';
import { Confirm } from '../confirm.tsx';
import { useActing } from '../session.tsx';
import { ask, changeAt, mustStepUp } from '../step-up.ts';
import {
  ADDING,
  IBAN_MOST,
  isHolderName,
  isUaeIban,
  NAME_MOST,
  type Payee,
  type Registration,
  type Supplier,
  supplierAt,
  supplierRefusal,
  VERIFYING,
} from '../suppliers.ts';
import { t, type TextKey } from '../text.ts';
import { timeText } from '../requests.ts';
import { unitsMost } from '../visible-name.ts';
import { Said, useChange } from './change.tsx';
import { Choices, Tick } from './choices.tsx';
import { LineField } from './line-field.tsx';

function PayeeFacts({ payee }: { readonly payee: Payee }) {
  return (
    <dl className="facts">
      <dt>{t('suppliers.bank.account')}</dt>
      <dd className="mono">{payee.payeeHint ?? t('suppliers.notGiven')}</dd>
      <dt>{t('suppliers.bank.maskedName')}</dt>
      <dd>{payee.maskedName ?? t('suppliers.notGiven')}</dd>
      <dt>{t('suppliers.bank.nameCheck')}</dt>
      <dd>{t(`suppliers.nameCheck.${payee.nameCheck ?? 'none'}`)}</dd>
    </dl>
  );
}

/** New details waiting: confirmed by passkey by the admin who entered them, or withdrawn at once. */
function Waiting({ supplier }: { readonly supplier: Supplier }) {
  const { organization } = useActing();
  const { busy, said, run } = useChange(supplierRefusal);
  const [open, setOpen] = useState<'approve' | 'withdraw' | null>(null);
  const pending = supplier.pendingChange;
  if (pending === null) return null;
  const at = supplierAt(supplier.id);
  const names = { name: supplier.displayName };
  const close = () => {
    setOpen(null);
  };
  const approve = () =>
    run(
      () =>
        mustStepUp(
          ask(changeAt(`${at}/payee-change/approve`, t('suppliers.bank.approveLabel', names), {}, organization.id)),
        ),
      { after: close },
    );
  const withdraw = () =>
    run(() => api.post(`${at}/payee-change/withdraw`, { organization: organization.id }), {
      done: t('suppliers.bank.withdrawn'),
      after: close,
    });
  const role = organization.role;
  return (
    <section className="stack" aria-labelledby="waiting-title">
      <h3 id="waiting-title">{t('suppliers.bank.waitingTitle')}</h3>
      <p className="muted">{t('suppliers.bank.waitingIntro', { time: timeText(pending.enteredAt) })}</p>
      {pending.payee !== null && <PayeeFacts payee={pending.payee} />}
      <div className="actions">
        {VERIFYING.includes(role) && (
          <button
            type="button"
            className="secondary"
            disabled={busy}
            onClick={() => {
              setOpen('withdraw');
            }}
          >
            {t('suppliers.bank.withdraw')}
          </button>
        )}
        {ADDING.includes(role) && (
          <button
            type="button"
            className="primary"
            disabled={busy}
            onClick={() => {
              setOpen('approve');
            }}
          >
            {t('suppliers.bank.approve')}
          </button>
        )}
      </div>
      <Said said={said} />
      {open === 'approve' && (
        <Confirm
          text={t('suppliers.bank.approveText')}
          title={t('suppliers.bank.approveTitle', names)}
          confirmLabel={t('brakes.passkeyConfirm')}
          busy={busy}
          onCancel={close}
          onConfirm={() => void approve()}
        />
      )}
      {open === 'withdraw' && (
        <Confirm
          text={t('suppliers.bank.withdrawText')}
          title={t('suppliers.bank.withdrawTitle', names)}
          confirmLabel={t('suppliers.bank.withdrawConfirm')}
          busy={busy}
          onCancel={close}
          onConfirm={() => void withdraw()}
        />
      )}
    </section>
  );
}

type Told = 'yes' | 'no';
type Route = 'pass_through' | 'hosted';
type Broken = 'none' | 'told' | 'calledFirst' | 'route' | 'holder' | 'iban';

/** A pass-through the partner didn't answer: sent again whole with the same key, the API asks the partner by it. */
interface Unanswered {
  readonly key: string;
  readonly body: Readonly<Record<string, unknown>>;
}

/** What a registration's answer says once the partner has it, or has refused it; none while it waits at the form. */
function registrationWords(registration: Registration): TextKey | undefined {
  if (registration.status === 'REGISTERED') return 'suppliers.bank.registered';
  if (registration.status === 'FAILED') return `suppliers.bank.failed.${registration.failure ?? 'unknown'}`;
  return undefined;
}

/** Giving the supplier new bank details: an admin's, while no change waits. */
function NewDetails({ supplier, onDone }: { readonly supplier: Supplier; readonly onDone: (said: string) => void }) {
  const { organization } = useActing();
  const { busy, said, run } = useChange(supplierRefusal);
  const [told, setTold] = useState<Told | null>(null);
  const [calledFirst, setCalledFirst] = useState(false);
  const [route, setRoute] = useState<Route | null>(null);
  const [holder, setHolder] = useState('');
  const [iban, setIban] = useState('');
  const [broken, setBroken] = useState<Broken>('none');
  const [confirming, setConfirming] = useState(false);
  const [unanswered, setUnanswered] = useState<Unanswered | null>(null);
  const [form, setForm] = useState<Registration | null>(null);
  const [formWaiting, setFormWaiting] = useState(false);
  const at = `${supplierAt(supplier.id)}/payee-registrations`;
  const phone = { phone: supplier.phone };
  const names = { name: supplier.displayName };
  // Any change to what is typed makes it another request: a key kept for the earlier one is dropped.
  const edited = (set: (value: string) => void) => (value: string) => {
    set(value);
    setUnanswered(null);
    setBroken('none');
  };
  const answered = (registration: Registration) => {
    const words = registrationWords(registration);
    if (words === undefined) setForm(registration);
    else onDone(t(words));
  };
  const close = () => {
    setConfirming(false);
  };
  const passThrough = ({ key, body }: Unanswered) =>
    run(
      async () => {
        try {
          answered(
            await api.post<Registration>(`${at}/pass-through`, {
              organization: organization.id,
              body,
              idempotencyKey: key,
            }),
          );
        } catch (error) {
          // The partner's answer was lost: the same request again, with the same key, asks it by our ID (E2-2d).
          if (error instanceof ApiError && error.code === 'PARTNER_UNAVAILABLE') setUnanswered({ key, body });
          throw error;
        }
      },
      { after: close },
    );
  const start = (body: Readonly<Record<string, unknown>>) =>
    run(
      async () => {
        answered(await api.post<Registration>(at, { organization: organization.id, body }));
      },
      { after: close },
    );
  const check = (registration: Registration) =>
    run(async () => {
      const { status, body } = await api.write<Registration>(`${at}/${encodeURIComponent(registration.id)}/check`, {
        organization: organization.id,
      });
      // 202: the partner doesn't have the details yet, and nothing changed.
      setFormWaiting(status === 202);
      if (status !== 202) answered(body);
    });
  const send = (pendingRequests: string, statementVersion?: number) => {
    if (route === 'hosted') {
      void start({ pendingRequests, statementVersion });
      return;
    }
    void passThrough({
      key: crypto.randomUUID(),
      body: { name: holder.trim(), iban, pendingRequests, statementVersion },
    });
  };
  const next = () => {
    // Checked here before anything is sent: what the API would refuse is said in place.
    if (told === null) setBroken('told');
    else if (told === 'yes' && !calledFirst) setBroken('calledFirst');
    else if (route === null) setBroken('route');
    else if (route === 'pass_through' && !isHolderName(holder.trim())) setBroken('holder');
    else if (route === 'pass_through' && !isUaeIban(iban)) setBroken('iban');
    else setConfirming(true);
  };

  const page = form?.form ?? null;
  if (form !== null && page !== null) {
    return (
      <>
        <p>{t('suppliers.bank.formIntro', { time: timeText(page.expiresAt) })}</p>
        <a className="link" href={page.url} target="_blank" rel="noopener noreferrer">
          {t('suppliers.bank.formOpen')}
        </a>
        <button type="button" className="primary" disabled={busy} onClick={() => void check(form)}>
          {t('suppliers.bank.formCheck')}
        </button>
        {formWaiting && <p className="notice">{t('suppliers.bank.formWaiting')}</p>}
        <Said said={said} />
      </>
    );
  }
  return (
    <>
      <Choices
        legend={t('suppliers.told.legend')}
        options={[
          ['yes', t('suppliers.told.yes')],
          ['no', t('suppliers.told.no')],
        ]}
        chosen={told}
        onChoose={(choice) => {
          setTold(choice);
          setBroken('none');
        }}
        broken={broken === 'told' ? t('suppliers.told.broken') : undefined}
      />
      {told === 'yes' && (
        <>
          <p className="notice" role="alert">
            {t('suppliers.told.warning', phone)}
          </p>
          <Tick
            label={t('suppliers.told.called', phone)}
            ticked={calledFirst}
            onTick={(ticked) => {
              setCalledFirst(ticked);
              setBroken('none');
            }}
            broken={broken === 'calledFirst' ? t('suppliers.told.calledBroken', phone) : undefined}
          />
        </>
      )}
      <Choices
        legend={t('suppliers.route.legend')}
        options={[
          ['pass_through', t('suppliers.route.pass_through')],
          ['hosted', t('suppliers.route.hosted')],
        ]}
        chosen={route}
        onChoose={(choice) => {
          setRoute(choice);
          setUnanswered(null);
          setBroken('none');
        }}
        broken={broken === 'route' ? t('suppliers.route.broken') : undefined}
      />
      {route === 'pass_through' && (
        <>
          <LineField
            label={t('suppliers.holder')}
            hint={t('suppliers.holderHint')}
            most={unitsMost(NAME_MOST)}
            value={holder}
            onChange={edited(setHolder)}
            broken={broken === 'holder' ? t('suppliers.holderBroken') : undefined}
          />
          <LineField
            label={t('suppliers.iban')}
            hint={t('suppliers.ibanHint')}
            most={IBAN_MOST}
            value={iban}
            onChange={edited(setIban)}
            broken={broken === 'iban' ? t('suppliers.ibanBroken') : undefined}
          />
        </>
      )}
      <div className="actions">
        {/* Unanswered, the same details go again only as the same request: a fresh one waits for something retyped. */}
        {unanswered === null ? (
          <button type="button" className="primary" disabled={busy} onClick={next}>
            {t('suppliers.bank.continue')}
          </button>
        ) : (
          <button type="button" className="primary" disabled={busy} onClick={() => void passThrough(unanswered)}>
            {t('suppliers.bank.tryAgain')}
          </button>
        )}
      </div>
      <Said said={said} />
      {confirming && (
        <Confirm
          statement="payee"
          title={t(route === 'hosted' ? 'suppliers.bank.hostedTitle' : 'suppliers.bank.passTitle', names)}
          confirmLabel={t(route === 'hosted' ? 'suppliers.bank.hostedConfirm' : 'suppliers.bank.passConfirm')}
          busy={busy}
          onCancel={close}
          onConfirm={send}
        >
          {route === 'pass_through' && (
            <>
              <p>{holder.trim()}</p>
              <p className="mono">{iban}</p>
            </>
          )}
        </Confirm>
      )}
    </>
  );
}

/** The bank details section: as they stand, any new ones waiting, and an admin's way to give new ones. */
export function BankDetails({ supplier }: { readonly supplier: Supplier }) {
  const { organization } = useActing();
  // Open while new details are being given; drawn afresh each time, so nothing typed is kept once closed.
  const [giving, setGiving] = useState(false);
  const [done, setDone] = useState<string | null>(null);
  const canGive = ADDING.includes(organization.role) && !supplier.changeWaiting;
  return (
    <section className="stack" aria-labelledby="bank-title">
      <h2 id="bank-title">{t('suppliers.bank.title')}</h2>
      <p className="muted">{t('suppliers.bank.intro')}</p>
      {supplier.payee === null ? (
        <p className="muted">{t('suppliers.bank.none')}</p>
      ) : (
        <PayeeFacts payee={supplier.payee} />
      )}
      <Waiting supplier={supplier} />
      {canGive && !giving && (
        <button
          type="button"
          className="secondary"
          onClick={() => {
            setGiving(true);
            setDone(null);
          }}
        >
          {t(supplier.payee === null ? 'suppliers.bank.add' : 'suppliers.bank.change')}
        </button>
      )}
      {canGive && giving && (
        <>
          <NewDetails
            supplier={supplier}
            onDone={(said) => {
              setGiving(false);
              setDone(said);
            }}
          />
          <button
            type="button"
            className="secondary"
            onClick={() => {
              setGiving(false);
            }}
          >
            {t('confirm.cancel')}
          </button>
        </>
      )}
      <Said said={done} />
    </section>
  );
}
