// Invitations (6D4b; PRD §7.1, ADR-003 §8, ADR-005 §6), on the Members page
// for an admin. Inviting: the person's address and their role, chosen with
// none picked, checked by the API's rules, confirmed in the console's words
// (the API states none), then kept as a draft and opened by passkey on the
// way back (stepped-up.tsx), where its link is shown once (key-once.tsx): the
// admin sends it to the person, as Agent X sends no email for it and keeps no
// copy. An admin or approver who accepts, or anyone rejoining, waits for an
// admin to confirm them (by passkey) or decline them (at once: it grants
// nothing). The API lists no invitations, so that admin names the invitation
// by the ID the accepting person was shown and passes on.
import { useState } from 'react';

import { api, isUuid } from '../api.ts';
import { Confirm } from '../confirm.tsx';
import { draftConfirm, EMAIL_MOST, invitationRefusal, isEmail, ROLES } from '../people.ts';
import { type Role, useActing } from '../session.tsx';
import { byPasskey, byPasskeyDraft } from '../step-up.ts';
import { t } from '../text.ts';
import { Said, useChange } from './change.tsx';
import { Choices } from './choices.tsx';
import { LineField } from './line-field.tsx';

const AT = '/v1/members/invitations';

/** The most characters an ID takes: a UUID's 36. */
const ID_MOST = 36;

type Broken = 'none' | 'email' | 'role';

/** Inviting a person: their address and role, confirmed, then by passkey. */
export function Invite() {
  const { organization } = useActing();
  const { busy, said, run } = useChange(invitationRefusal);
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<Role | null>(null);
  const [broken, setBroken] = useState<Broken>('none');
  const [confirming, setConfirming] = useState<Role | null>(null);
  const invite = (chosen: Role) =>
    run(
      () =>
        byPasskeyDraft(
          AT,
          t('invitations.label', { email, role: t(`choose.role.${chosen}`) }),
          { email, role: chosen },
          organization.id,
          draftConfirm('invitation', AT),
        ),
      {
        after: () => {
          setConfirming(null);
        },
      },
    );
  return (
    <section className="stack" aria-labelledby="invite-title">
      <h2 id="invite-title">{t('invitations.title')}</h2>
      <p className="muted">{t('invitations.intro')}</p>
      <LineField
        label={t('invitations.email')}
        hint={t('invitations.emailHint')}
        most={EMAIL_MOST}
        autoComplete="off"
        spellCheck={false}
        value={email}
        onChange={(value) => {
          setEmail(value);
          setBroken('none');
        }}
        broken={broken === 'email' ? t('invitations.emailBroken') : undefined}
      />
      <Choices
        legend={t('invitations.roleLegend')}
        options={ROLES.map((one) => [one, t(`members.roleWords.${one}`)] as const)}
        chosen={role}
        onChoose={(one) => {
          setRole(one);
          setBroken('none');
        }}
        broken={broken === 'role' ? t('invitations.roleBroken') : undefined}
      />
      <button
        type="button"
        className="primary"
        disabled={busy}
        onClick={() => {
          // Checked here by the API's own rules before anything is sent: what it would refuse is said in place.
          if (!isEmail(email)) setBroken('email');
          else if (role === null) setBroken('role');
          else setConfirming(role);
        }}
      >
        {t('invitations.button')}
      </button>
      <Said said={said} />
      {confirming !== null && (
        <Confirm
          text={t('invitations.text')}
          title={t('invitations.confirmTitle')}
          confirmLabel={t('brakes.passkeyConfirm')}
          busy={busy}
          onCancel={() => {
            setConfirming(null);
          }}
          onConfirm={() => void invite(confirming)}
        >
          <p className="mono">{email}</p>
          <p>{t(`members.roleWords.${confirming}`)}</p>
        </Confirm>
      )}
    </section>
  );
}

type Deciding = 'approve' | 'decline';

/** Confirming or declining who accepted an admin's or approver's invitation, named by its ID. */
export function WaitingInvitation() {
  const { organization } = useActing();
  const { busy, said, run } = useChange(invitationRefusal);
  const [typed, setTyped] = useState('');
  const [broken, setBroken] = useState(false);
  const [deciding, setDeciding] = useState<{ readonly kind: Deciding; readonly id: string } | null>(null);
  const id = typed.trim().toLowerCase();
  const close = () => {
    setDeciding(null);
  };
  const open = (kind: Deciding) => {
    if (isUuid(id)) setDeciding({ kind, id });
    else setBroken(true);
  };
  const at = (one: string) => `${AT}/${encodeURIComponent(one)}`;
  const approve = (one: string) =>
    run(() => byPasskey(`${at(one)}/approve`, t('invitations.approveLabel', { id: one }), {}, organization.id), {
      after: close,
    });
  const decline = (one: string) =>
    run(() => api.post(`${at(one)}/decline`, { organization: organization.id, body: {} }), {
      after: close,
      done: t('invitations.declined'),
    });
  return (
    <section className="stack" aria-labelledby="waiting-title">
      <h2 id="waiting-title">{t('invitations.waitingTitle')}</h2>
      <p className="muted">{t('invitations.waitingIntro')}</p>
      <LineField
        label={t('invitations.id')}
        hint={t('invitations.idHint')}
        most={ID_MOST}
        autoComplete="off"
        spellCheck={false}
        value={typed}
        onChange={(value) => {
          setTyped(value);
          setBroken(false);
        }}
        broken={broken ? t('invitations.idBroken') : undefined}
      />
      <div className="actions">
        <button
          type="button"
          className="secondary"
          disabled={busy}
          onClick={() => {
            open('decline');
          }}
        >
          {t('invitations.decline')}
        </button>
        <button
          type="button"
          className="primary"
          disabled={busy}
          onClick={() => {
            open('approve');
          }}
        >
          {t('invitations.approve')}
        </button>
      </div>
      <Said said={said} />
      {deciding !== null && (
        <Confirm
          text={t(deciding.kind === 'approve' ? 'invitations.approveText' : 'invitations.declineText')}
          title={t(deciding.kind === 'approve' ? 'invitations.approveTitle' : 'invitations.declineTitle')}
          confirmLabel={deciding.kind === 'approve' ? t('brakes.passkeyConfirm') : t('invitations.declineConfirm')}
          busy={busy}
          onCancel={close}
          onConfirm={() => void (deciding.kind === 'approve' ? approve(deciding.id) : decline(deciding.id))}
        >
          <p className="mono">{deciding.id}</p>
        </Confirm>
      )}
    </section>
  );
}
