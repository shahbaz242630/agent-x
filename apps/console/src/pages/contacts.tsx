// The organisation's registered contacts (6D4b; ADR-012 §1, §8, SEC-OPS-06),
// an admin's alone: `/more/contacts`. Its trust anchor: told of the changes
// that matter, and asked to confirm a reset of a member's lost second factor.
// Each as the API gives it (its address, whether it counts now, or from when:
// 7 days after it is confirmed). Adding one keeps it as a draft, confirmed by
// passkey on the way back (stepped-up.tsx); removing one goes by passkey.
// Both are confirmed first in the console's words (the API states none), the
// removal's dialog pinned to the contact as it showed it.
import { Link } from '@tanstack/react-router';
import { useState } from 'react';

import { Confirm } from '../confirm.tsx';
import { type Contact, contactRefusal, draftConfirm, EMAIL_MOST, isEmail, useContacts } from '../people.ts';
import { timeText } from '../requests.ts';
import { useActing } from '../session.tsx';
import { byPasskey, byPasskeyDraft } from '../step-up.ts';
import { t } from '../text.ts';
import { Said, useChange } from './change.tsx';
import { Loading, Retry } from './failed.tsx';
import { LineField } from './line-field.tsx';
import { Moved, movedSince } from './people-parts.tsx';

const AT = '/v1/registered-contacts';

/** Whether it counts now, or from when. */
const counting = (contact: Contact): string => {
  if (contact.counts) return t('contacts.counts');
  return contact.countsFrom === null
    ? t('contacts.notYet')
    : t('contacts.countsFrom', { time: timeText(contact.countsFrom) });
};

const stateOf = (contact: Contact): string => [contact.status, contact.email, contact.countsFrom].join('/');

/** Adding a contact: its address, checked by the API's rule, confirmed, then by passkey. */
function AddContact() {
  const { organization } = useActing();
  const { busy, said, run } = useChange(contactRefusal);
  const [email, setEmail] = useState('');
  const [broken, setBroken] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const add = () =>
    run(
      () =>
        byPasskeyDraft(AT, t('contacts.addLabel', { email }), { email }, organization.id, draftConfirm('contact', AT)),
      {
        after: () => {
          setConfirming(false);
        },
      },
    );
  return (
    <section className="stack" aria-labelledby="contact-add-title">
      <h2 id="contact-add-title">{t('contacts.addTitle')}</h2>
      <LineField
        label={t('contacts.email')}
        hint={t('contacts.emailHint')}
        most={EMAIL_MOST}
        autoComplete="off"
        spellCheck={false}
        value={email}
        onChange={(value) => {
          setEmail(value);
          setBroken(false);
        }}
        broken={broken ? t('contacts.emailBroken') : undefined}
      />
      <button
        type="button"
        className="primary"
        disabled={busy}
        onClick={() => {
          if (isEmail(email)) setConfirming(true);
          else setBroken(true);
        }}
      >
        {t('contacts.add')}
      </button>
      <Said said={said} />
      {confirming && (
        <Confirm
          text={t('contacts.addText')}
          title={t('contacts.addConfirmTitle')}
          confirmLabel={t('brakes.passkeyConfirm')}
          busy={busy}
          onCancel={() => {
            setConfirming(false);
          }}
          onConfirm={() => void add()}
        >
          <p className="mono">{email}</p>
        </Confirm>
      )}
    </section>
  );
}

function ContactList() {
  const { organization } = useActing();
  const contacts = useContacts(organization.id);
  const { busy, said, run } = useChange(contactRefusal);
  const [seen, setSeen] = useState<Contact | null>(null);
  if (contacts.isPending) return <Loading />;
  if (contacts.isError) return <Retry onRetry={() => void contacts.refetch()} />;
  const close = () => {
    setSeen(null);
  };
  const moved =
    seen !== null &&
    movedSince(
      seen,
      contacts.data.find((one) => one.id === seen.id),
      stateOf,
    );
  const remove = (contact: Contact) =>
    run(
      () =>
        byPasskey(
          `${AT}/${encodeURIComponent(contact.id)}/remove`,
          t('contacts.removeLabel', { email: contact.email }),
          {},
          organization.id,
        ),
      { after: close },
    );
  return (
    <>
      {contacts.data.length === 0 ? (
        <p className="notice">{t('contacts.none')}</p>
      ) : (
        <ul className="rows">
          {contacts.data.map((contact) => (
            <li key={contact.id} className="row">
              <span className="row-main">
                <span className="mono">{contact.email}</span>
                <span className="muted">{counting(contact)}</span>
              </span>
              <span className="actions">
                <button
                  type="button"
                  className="secondary"
                  disabled={busy}
                  aria-label={t('contacts.removeNamed', { email: contact.email })}
                  onClick={() => {
                    setSeen(contact);
                  }}
                >
                  {t('contacts.remove')}
                </button>
              </span>
            </li>
          ))}
        </ul>
      )}
      <Said said={said} />
      {seen !== null && (
        <Confirm
          text={t('contacts.removeText')}
          title={t('contacts.removeTitle')}
          confirmLabel={t('brakes.passkeyConfirm')}
          busy={busy}
          ready={!moved}
          onCancel={close}
          onConfirm={() => void remove(seen)}
        >
          <Moved moved={moved} />
          <p className="mono">{seen.email}</p>
          <p className="muted">{counting(seen)}</p>
        </Confirm>
      )}
    </>
  );
}

/** `/more/contacts`: the registered contacts, and adding one. */
export function Contacts() {
  const { organization } = useActing();
  return (
    <section className="stack">
      <Link to="/more/members" className="back">
        {t('members.back')}
      </Link>
      <h1>{t('contacts.title')}</h1>
      <p className="muted">{t('contacts.intro')}</p>
      {organization.role === 'admin' ? (
        <>
          <ContactList />
          <AddContact />
        </>
      ) : (
        <p className="muted">{t('contacts.adminsOnly')}</p>
      )}
    </section>
  );
}
