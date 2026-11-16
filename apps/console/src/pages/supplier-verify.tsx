// Verifying a supplier by a call-back (6D2, ADR-012 §1, partner S74): an
// admin or an approver, a second person, calls the supplier on the phone on
// file (from its registry or official website when it was added, never one
// from an email or an invoice), ticks that the supplier confirmed its bank
// details, and notes the call: a note is needed when the bank's name check
// wasn't a full match. Confirmed in the console's words (the API states none
// for it), then by passkey. Until it can be (new details waiting, none yet,
// the 24-hour cooling-off running, the bank's name check "no match") the page
// says why instead; the people rule (two persons, the verifier's age) only the
// API can tell, and its refusal is said in plain words.
import { useState } from 'react';

import { Confirm } from '../confirm.tsx';
import { useActing } from '../session.tsx';
import { ask, changeAt, mustStepUp } from '../step-up.ts';
import {
  CALL_NOTE_MOST,
  isCallNote,
  notYetVerifiable,
  type Supplier,
  supplierAt,
  supplierRefusal,
  VERIFYING,
} from '../suppliers.ts';
import { t } from '../text.ts';
import { Said, useChange } from './change.tsx';
import { Tick } from './choices.tsx';
import { LineField } from './line-field.tsx';
import { unitsMost } from '../visible-name.ts';

type Broken = 'none' | 'called' | 'note';

function VerifyForm({ supplier }: { readonly supplier: Supplier }) {
  const { organization } = useActing();
  const { busy, said, run } = useChange(supplierRefusal);
  const [called, setCalled] = useState(false);
  const [note, setNote] = useState('');
  const [broken, setBroken] = useState<Broken>('none');
  const [confirming, setConfirming] = useState(false);
  // Anything short of the bank's full match needs the verifier's note of the call (the API's SUPPLIER_CALL_NOTE_NEEDED).
  const noteNeeded = supplier.payee?.nameCheck !== 'match';
  const written = note.trim();
  const phone = { phone: supplier.phone };
  const names = { name: supplier.displayName };
  const verify = () =>
    run(
      () =>
        mustStepUp(
          ask(
            changeAt(
              `${supplierAt(supplier.id)}/verify`,
              t('suppliers.verify.label', names),
              // An optional note not written is left out: the API keeps none.
              { calledBack: true, ...(written !== '' && { note: written }) },
              organization.id,
            ),
          ),
        ),
      {
        after: () => {
          setConfirming(false);
        },
      },
    );
  return (
    <>
      <p className="notice">{t('suppliers.verify.how', phone)}</p>
      <Tick
        label={t('suppliers.verify.called', phone)}
        ticked={called}
        onTick={(ticked) => {
          setCalled(ticked);
          setBroken('none');
        }}
        broken={broken === 'called' ? t('suppliers.verify.calledBroken') : undefined}
      />
      <LineField
        label={t(noteNeeded ? 'suppliers.verify.noteNeeded' : 'suppliers.verify.noteOptional')}
        hint={t('suppliers.verify.noteHint')}
        most={unitsMost(CALL_NOTE_MOST)}
        value={note}
        onChange={(value) => {
          setNote(value);
          setBroken('none');
        }}
        broken={broken === 'note' ? t('suppliers.verify.noteBroken') : undefined}
      />
      <button
        type="button"
        className="primary"
        disabled={busy}
        onClick={() => {
          // Checked here by the API's own rules before anything is sent: what it would refuse is said in place.
          if (!called) setBroken('called');
          else if ((noteNeeded || written !== '') && !isCallNote(written)) setBroken('note');
          else setConfirming(true);
        }}
      >
        {t('suppliers.verify.button')}
      </button>
      <Said said={said} />
      {confirming && (
        <Confirm
          text={t('suppliers.verify.text')}
          title={t('suppliers.verify.confirmTitle', names)}
          confirmLabel={t('brakes.passkeyConfirm')}
          busy={busy}
          onCancel={() => {
            setConfirming(false);
          }}
          onConfirm={() => void verify()}
        >
          <p className="amount">{supplier.displayName}</p>
          {written !== '' && <p>{written}</p>}
        </Confirm>
      )}
    </>
  );
}

/** The verify section, for a supplier waiting to be verified: the form for a verifier, else why not yet or who may. */
export function Verify({ supplier }: { readonly supplier: Supplier }) {
  const { organization } = useActing();
  if (supplier.status !== 'UNVERIFIED') return null;
  const waiting = notYetVerifiable(supplier);
  let shown = <p className="muted">{t('suppliers.verify.viewOnly')}</p>;
  if (waiting !== undefined) shown = <p className="muted">{t(waiting)}</p>;
  else if (VERIFYING.includes(organization.role)) shown = <VerifyForm supplier={supplier} />;
  return (
    <section className="stack" aria-labelledby="verify-title">
      <h2 id="verify-title">{t('suppliers.verify.title')}</h2>
      <p className="muted">{t('suppliers.verify.intro')}</p>
      {shown}
    </section>
  );
}
