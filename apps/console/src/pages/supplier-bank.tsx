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

import { api, isIntegrityFailed, isRefusal } from '../api.ts';
import { Confirm } from '../confirm.tsx';
import { timeText } from '../requests.ts';
import { useActing } from '../session.tsx';
import { byPasskey } from '../step-up.ts';
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

/**
 * The section's one way to send a change: what each part sends with, its
 * outcome said by the section itself (BankDetails), so it stays on screen when
 * the re-read after it removes the part that sent it (new details withdrawn,
 * or a change found waiting).
 */
type Sending = Pick<ReturnType<typeof useChange>, 'busy' | 'run'>;

/** New details waiting: confirmed by passkey by the admin who entered them, or withdrawn at once. */
function Waiting({ supplier, sending }: { readonly supplier: Supplier; readonly sending: Sending }) {
  const { organization } = useActing();
  const { busy, run } = sending;
  const [open, setOpen] = useState<'approve' | 'withdraw' | null>(null);
  const pending = supplier.pendingChange;
  if (pending === null) return null;
  const at = supplierAt(supplier.id);
  const names = { name: supplier.displayName };
  const close = () => {
    setOpen(null);
  };
  const approve = () =>
    run(() => byPasskey(`${at}/payee-change/approve`, t('suppliers.bank.approveLabel', names), {}, organization.id), {
      after: close,
    });
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

/** A pass-through with no answer: sent again whole with the same key, the API asks the partner by it. */
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

/** The partner's own page, open for the details, and the check once the person is back. */
function PartnerForm({
  registration,
  page,
  sending,
  onAnswered,
}: {
  readonly registration: Registration;
  readonly page: NonNullable<Registration['form']>;
  readonly sending: Sending;
  readonly onAnswered: (registration: Registration) => void;
}) {
  const { organization } = useActing();
  const [waiting, setWaiting] = useState(false);
  const at = `${supplierAt(registration.supplierId)}/payee-registrations/${encodeURIComponent(registration.id)}`;
  const check = () =>
    sending.run(async () => {
      const { status, body } = await api.write<Registration>(`${at}/check`, { organization: organization.id });
      // 202: the partner doesn't have the details yet, and nothing changed.
      setWaiting(status === 202);
      if (status !== 202) onAnswered(body);
    });
  return (
    <>
      <p>{t('suppliers.bank.formIntro', { time: timeText(page.expiresAt) })}</p>
      <a className="link" href={page.url} target="_blank" rel="noopener noreferrer">
        {t('suppliers.bank.formOpen')}
      </a>
      <button type="button" className="primary" disabled={sending.busy} onClick={() => void check()}>
        {t('suppliers.bank.formCheck')}
      </button>
      {waiting && <p className="notice">{t('suppliers.bank.formWaiting')}</p>}
    </>
  );
}

/** Giving the supplier new bank details: an admin's, while no change waits. */
function NewDetails({
  supplier,
  sending,
  onDone,
  onCancel,
}: {
  readonly supplier: Supplier;
  readonly sending: Sending;
  readonly onDone: (said: string) => void;
  readonly onCancel: () => void;
}) {
  const { organization } = useActing();
  const { busy, run } = sending;
  const [told, setTold] = useState<Told | null>(null);
  const [calledFirst, setCalledFirst] = useState(false);
  const [route, setRoute] = useState<Route | null>(null);
  const [holder, setHolder] = useState('');
  const [iban, setIban] = useState('');
  const [broken, setBroken] = useState<Broken>('none');
  const [confirming, setConfirming] = useState(false);
  const [unanswered, setUnanswered] = useState<Unanswered | null>(null);
  const [form, setForm] = useState<Registration | null>(null);
  const at = `${supplierAt(supplier.id)}/payee-registrations`;
  const phone = { phone: supplier.phone };
  const names = { name: supplier.displayName };
  const way = route === 'hosted' ? 'hosted' : 'pass';
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
          // No answer, or no decision (a 5xx): the partner may have the details, and a fresh key would register them
          // again (the API carries on an open registration for its form alone). The same request asks it by our ID.
          if (!isRefusal(error)) setUnanswered({ key, body });
          throw error;
        }
      },
      {
        after: close,
        refusal: (error) =>
          isRefusal(error) || isIntegrityFailed(error) ? supplierRefusal(error) : t('suppliers.bank.unanswered'),
      },
    );
  const start = (body: Readonly<Record<string, unknown>>) =>
    run(
      async () => {
        answered(await api.post<Registration>(at, { organization: organization.id, body }));
      },
      { after: close },
    );
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
  const cancel = (
    // Never while sending, nor while a request waits to be asked again: its key would be lost with the form.
    <button type="button" className="secondary" disabled={busy || unanswered !== null} onClick={onCancel}>
      {t('confirm.cancel')}
    </button>
  );

  const page = form?.form ?? null;
  if (form !== null && page !== null) {
    return (
      <>
        <PartnerForm registration={form} page={page} sending={sending} onAnswered={answered} />
        {cancel}
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
          {/* Never saved or offered back by the browser: a supplier's bank details are no one's own to autofill. */}
          <LineField
            label={t('suppliers.holder')}
            hint={t('suppliers.holderHint')}
            most={unitsMost(NAME_MOST)}
            value={holder}
            onChange={edited(setHolder)}
            broken={broken === 'holder' ? t('suppliers.holderBroken') : undefined}
            autoComplete="off"
            spellCheck={false}
          />
          <LineField
            label={t('suppliers.iban')}
            hint={t('suppliers.ibanHint')}
            most={IBAN_MOST}
            value={iban}
            onChange={edited(setIban)}
            broken={broken === 'iban' ? t('suppliers.ibanBroken') : undefined}
            autoComplete="off"
            spellCheck={false}
          />
        </>
      )}
      <div className="actions">
        {cancel}
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
      {confirming && (
        <Confirm
          statement="payee"
          title={t(`suppliers.bank.${way}Title`, names)}
          confirmLabel={t(`suppliers.bank.${way}Confirm`)}
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
  const change = useChange(supplierRefusal);
  // Open while new details are being given; drawn afresh each time, so nothing typed is kept once closed.
  const [giving, setGiving] = useState(false);
  // What the partner answered a registration, said here as the outcomes of every part are.
  const [answer, setAnswer] = useState<string | null>(null);
  const sending: Sending = {
    busy: change.busy,
    run: (send, options) => {
      setAnswer(null);
      return change.run(send, options);
    },
  };
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
      <Waiting supplier={supplier} sending={sending} />
      {canGive && !giving && (
        <button
          type="button"
          className="secondary"
          onClick={() => {
            setGiving(true);
            setAnswer(null);
          }}
        >
          {t(supplier.payee === null ? 'suppliers.bank.add' : 'suppliers.bank.change')}
        </button>
      )}
      {canGive && giving && (
        <NewDetails
          supplier={supplier}
          sending={sending}
          onDone={(said) => {
            setGiving(false);
            setAnswer(said);
          }}
          onCancel={() => {
            setGiving(false);
          }}
        />
      )}
      <Said said={change.said} />
      <Said said={answer} />
    </section>
  );
}
