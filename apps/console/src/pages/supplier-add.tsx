// Adding a supplier (6D2, ADR-012 §1), on the Suppliers list for an admin
// (ADDING_ROLES): its name, its phone for call-backs, taken from an
// independent source (a trade registry or its official website, never an
// invoice or an email) and that source, its email and trade licence if known,
// and whether it is emailed when it is paid (on offered first, none chosen for
// them: decision 34b). Checked by the API's own rules before anything is sent,
// confirmed in the console's words (the API states none for it), then added at
// once, unverified (POST /v1/suppliers: no passkey), and its page opened.
import { useNavigate } from '@tanstack/react-router';
import { useState } from 'react';

import { api } from '../api.ts';
import { Confirm } from '../confirm.tsx';
import { useActing } from '../session.tsx';
import {
  ADDING,
  NAME_MOST,
  type NewSupplier,
  newSupplierBody,
  newSupplierProblems,
  REMITTANCE_EMAILS,
  SOURCE_REF_MOST,
  type Supplier,
  supplierRefusal,
} from '../suppliers.ts';
import { t, type TextKey } from '../text.ts';
import { unitsMost } from '../visible-name.ts';
import { Said, useChange } from './change.tsx';
import { Choices } from './choices.tsx';
import { LineField } from './line-field.tsx';

const EMPTY: NewSupplier = {
  displayName: '',
  phone: '',
  email: '',
  tradeLicence: '',
  sourceKind: null,
  sourceRef: '',
  remittanceEmail: null,
};

/** The longest an email (254) and a trade licence number (50) may be, as the API takes them. */
const EMAIL_MOST = 254;
const LICENCE_MOST = 50;
/** The longest a phone in international form may be: a plus and 15 digits (E.164). */
const PHONE_MOST = 16;

/** Each text field: its words' keys, and the most it takes. */
const FIELDS = [
  ['displayName', 'suppliers.add.name', unitsMost(NAME_MOST)],
  ['phone', 'suppliers.add.phone', PHONE_MOST],
  ['email', 'suppliers.add.email', EMAIL_MOST],
  ['tradeLicence', 'suppliers.add.licence', LICENCE_MOST],
] as const;

export function AddSupplier() {
  const { organization } = useActing();
  const navigate = useNavigate();
  const { busy, said, run } = useChange(supplierRefusal);
  const [opened, setOpened] = useState(false);
  const [typed, setTyped] = useState<NewSupplier>(EMPTY);
  const [problems, setProblems] = useState<readonly (keyof NewSupplier)[]>([]);
  const [confirming, setConfirming] = useState(false);
  if (!ADDING.includes(organization.role)) return null;
  const set = (part: Partial<NewSupplier>) => {
    setTyped({ ...typed, ...part });
    setProblems([]);
  };
  const broken = (field: keyof NewSupplier, key: TextKey) => (problems.includes(field) ? t(key) : undefined);
  const close = () => {
    setConfirming(false);
  };
  const add = () =>
    run(
      async () => {
        const added = await api.post<Supplier>('/v1/suppliers', {
          organization: organization.id,
          body: newSupplierBody(typed),
        });
        await navigate({ to: '/more/suppliers/$id', params: { id: added.id } });
      },
      { after: close },
    );
  if (!opened) {
    return (
      <>
        <button
          type="button"
          className="primary"
          onClick={() => {
            setOpened(true);
          }}
        >
          {t('suppliers.add.open')}
        </button>
        <Said said={said} />
      </>
    );
  }
  return (
    <section className="stack" aria-labelledby="add-title">
      <h2 id="add-title">{t('suppliers.add.title')}</h2>
      <p className="muted">{t('suppliers.add.intro')}</p>
      {FIELDS.map(([field, words, most]) => (
        <LineField
          key={field}
          label={t(words)}
          hint={t(`${words}Hint`)}
          most={most}
          value={typed[field]}
          onChange={(value) => {
            set({ [field]: value });
          }}
          broken={broken(field, `${words}Broken`)}
        />
      ))}
      <Choices
        legend={t('suppliers.add.sourceLegend')}
        options={[
          ['registry', t('suppliers.add.source.registry')],
          ['official_website', t('suppliers.add.source.official_website')],
        ]}
        chosen={typed.sourceKind}
        onChoose={(sourceKind) => {
          set({ sourceKind });
        }}
        broken={broken('sourceKind', 'suppliers.add.sourceBroken')}
      />
      <LineField
        label={t('suppliers.add.sourceRef')}
        hint={t('suppliers.add.sourceRefHint')}
        most={SOURCE_REF_MOST}
        value={typed.sourceRef}
        onChange={(sourceRef) => {
          set({ sourceRef });
        }}
        broken={broken('sourceRef', 'suppliers.add.sourceRefBroken')}
      />
      <Choices
        legend={t('suppliers.add.remittanceLegend')}
        options={REMITTANCE_EMAILS.map((choice) => [choice, t(`suppliers.add.remittance.${choice}`)] as const)}
        chosen={typed.remittanceEmail}
        onChoose={(remittanceEmail) => {
          set({ remittanceEmail });
        }}
        broken={broken('remittanceEmail', 'suppliers.add.remittanceBroken')}
      />
      <div className="actions">
        <button
          type="button"
          className="secondary"
          disabled={busy}
          onClick={() => {
            setOpened(false);
            setProblems([]);
          }}
        >
          {t('confirm.cancel')}
        </button>
        <button
          type="button"
          className="primary"
          disabled={busy}
          onClick={() => {
            // Checked here by the API's own rules before anything is sent: what it would refuse is said in place.
            const found = newSupplierProblems(typed);
            setProblems(found);
            if (found.length === 0) setConfirming(true);
          }}
        >
          {t('suppliers.add.button')}
        </button>
      </div>
      <Said said={said} />
      {confirming && (
        <Confirm
          text={t('suppliers.add.text')}
          title={t('suppliers.add.confirmTitle', { name: typed.displayName })}
          confirmLabel={t('suppliers.add.confirm')}
          busy={busy}
          onCancel={close}
          onConfirm={() => void add()}
        >
          <p className="amount">{typed.displayName}</p>
          <p className="mono">{typed.phone}</p>
        </Confirm>
      )}
    </section>
  );
}
