// One member's page (6D4b; BR-01, BR-02): `/more/members/<membership ID>`,
// read from the members list (the API reads no member alone). Their role,
// status, since when, their Agent X user ID and membership ID; the API says
// nothing of which sign-in factors they have, so an admin is shown their
// factor resets instead. An admin can, for another active member:
// - change their role, the new one chosen with none picked (the three they
//   don't have), by passkey;
// - deactivate them, by passkey;
// - ask a reset of their lost second factor: kept as a draft, sent to the
//   registered contacts by passkey on the way back (stepped-up.tsx), one of
//   whom confirms it before it is removed after a cooling-off.
// Each is confirmed first in the console's words (the API states none for
// them), the dialog pinned to the member as it showed them. Every session the
// member has ends with a role change or deactivation. Your own membership is
// another admin's to change, so the organisation always keeps an admin.
import { Link } from '@tanstack/react-router';
import { useState } from 'react';

import { type Member, useMembers } from '../agents.ts';
import { isUuid } from '../api.ts';
import { Confirm } from '../confirm.tsx';
import { draftConfirm, memberRefusal, resetRefusal, ROLES } from '../people.ts';
import { timeText } from '../requests.ts';
import { type Role, useActing } from '../session.tsx';
import { byPasskey, byPasskeyDraft } from '../step-up.ts';
import { t } from '../text.ts';
import { memberText } from './agent.tsx';
import { Said, useChange } from './change.tsx';
import { Choices } from './choices.tsx';
import { Loading, NotShown } from './failed.tsx';
import { Moved, movedSince } from './people-parts.tsx';
import { ResetList } from './resets.tsx';

type Opened =
  | { readonly kind: 'role'; readonly seen: Member; readonly role: Role }
  | { readonly kind: 'deactivate' | 'reset'; readonly seen: Member };

const stateOf = (member: Member): string => [member.role, member.status].join('/');

const memberAt = (id: string): string => `/v1/members/${encodeURIComponent(id)}`;

/** What an admin can do with another active member: each opens its dialog. */
function Actions({
  member,
  busy,
  onOpen,
}: {
  readonly member: Member;
  readonly busy: boolean;
  readonly onOpen: (open: Opened) => void;
}) {
  const [role, setRole] = useState<Role | null>(null);
  const [broken, setBroken] = useState(false);
  const others = ROLES.filter((one) => one !== member.role);
  return (
    <>
      <section className="stack" aria-labelledby="role-title">
        <h2 id="role-title">{t('members.role.title')}</h2>
        <Choices
          legend={t('members.role.legend')}
          options={others.map((one) => [one, t(`members.roleWords.${one}`)] as const)}
          chosen={role}
          onChoose={(one) => {
            setRole(one);
            setBroken(false);
          }}
          broken={broken ? t('members.role.broken') : undefined}
        />
        <button
          type="button"
          className="primary"
          disabled={busy}
          onClick={() => {
            if (role === null) setBroken(true);
            else onOpen({ kind: 'role', seen: member, role });
          }}
        >
          {t('members.role.button')}
        </button>
      </section>
      <section className="stack" aria-labelledby="factor-title">
        <h2 id="factor-title">{t('members.reset.title')}</h2>
        <p className="muted">{t('members.reset.intro')}</p>
        <button
          type="button"
          className="secondary"
          disabled={busy}
          onClick={() => {
            onOpen({ kind: 'reset', seen: member });
          }}
        >
          {t('members.reset.button')}
        </button>
      </section>
      <section className="stack" aria-labelledby="deactivate-title">
        <h2 id="deactivate-title">{t('members.deactivate.title')}</h2>
        <p className="muted">{t('members.deactivate.intro')}</p>
        <button
          type="button"
          className="secondary"
          disabled={busy}
          onClick={() => {
            onOpen({ kind: 'deactivate', seen: member });
          }}
        >
          {t('members.deactivate.button')}
        </button>
      </section>
    </>
  );
}

/** Each dialog's words, from the member as it showed them. */
const DIALOGS = {
  role: { title: 'members.role.confirmTitle', text: 'members.role.text' },
  deactivate: { title: 'members.deactivate.confirmTitle', text: 'members.deactivate.text' },
  reset: { title: 'members.reset.confirmTitle', text: 'members.reset.text' },
} as const;

function MemberShown({ member, now }: { readonly member: Member; readonly now: readonly Member[] }) {
  const { organization, session } = useActing();
  const me = session.userId.toLowerCase();
  const mine = member.userId.toLowerCase() === me;
  const admin = organization.role === 'admin';
  const [open, setOpen] = useState<Opened | null>(null);
  const { busy, said, run } = useChange(memberRefusal);
  const close = () => {
    setOpen(null);
  };
  const moved =
    open !== null &&
    movedSince(
      open.seen,
      now.find((one) => one.id === open.seen.id),
      stateOf,
    );
  const name = memberText(member, me);
  const send = (opened: Opened) => {
    const at = memberAt(opened.seen.id);
    if (opened.kind === 'role') {
      const role = t(`choose.role.${opened.role}`);
      return run(
        () =>
          byPasskey(
            `${at}/role`,
            t('members.role.label', { id: opened.seen.id, role }),
            { role: opened.role },
            organization.id,
          ),
        { after: close },
      );
    }
    if (opened.kind === 'deactivate') {
      return run(
        () => byPasskey(`${at}/deactivate`, t('members.deactivate.label', { id: opened.seen.id }), {}, organization.id),
        { after: close },
      );
    }
    return run(
      () =>
        byPasskeyDraft(
          `${at}/factor-reset`,
          t('members.reset.label', { id: opened.seen.id }),
          {},
          organization.id,
          draftConfirm('reset', '/v1/factor-resets'),
        ),
      // A reset's refusals are its own (one under way, no contact to confirm it…).
      { after: close, refusal: resetRefusal },
    );
  };
  return (
    <>
      <span className="kicker">{t(`members.status.${member.status}`)}</span>
      <h1>{name}</h1>
      <dl className="facts">
        <dt>{t('members.role.now')}</dt>
        <dd>{t(`choose.role.${member.role}`)}</dd>
        <dt>{t('members.since.label')}</dt>
        <dd>{timeText(member.joinedAt)}</dd>
        <dt>{t('members.membershipId')}</dt>
        <dd className="mono">{member.id}</dd>
        <dt>{t('members.userId')}</dt>
        <dd className="mono">{member.userId}</dd>
      </dl>
      {admin && (
        <section className="stack" aria-labelledby="resets-title">
          <h2 id="resets-title">{t('members.resets')}</h2>
          <p className="muted">{t('members.factorsUnknown')}</p>
          <ResetList person={member.id} />
        </section>
      )}
      {admin && mine && <p className="muted">{t('members.ownMembership')}</p>}
      {admin && !mine && member.status === 'ACTIVE' && <Actions member={member} busy={busy} onOpen={setOpen} />}
      {!admin && <p className="muted">{t('members.adminsChange')}</p>}
      <Said said={said} />
      {open !== null && (
        <Confirm
          text={t(DIALOGS[open.kind].text)}
          title={t(DIALOGS[open.kind].title)}
          confirmLabel={t('brakes.passkeyConfirm')}
          busy={busy}
          ready={!moved}
          onCancel={close}
          onConfirm={() => void send(open)}
        >
          <Moved moved={moved} />
          <p>
            {memberText(open.seen, me)} <span className="mono">{open.seen.id}</span>
          </p>
          {open.kind === 'role' && (
            <p>
              {t('members.role.fromTo', {
                from: t(`choose.role.${open.seen.role}`),
                to: t(`choose.role.${open.role}`),
              })}
            </p>
          )}
        </Confirm>
      )}
    </>
  );
}

export function MemberPage({ id }: { readonly id: string }) {
  const { organization } = useActing();
  const members = useMembers(organization.id);
  const back = (
    <Link to="/more/members" className="back">
      {t('members.back')}
    </Link>
  );
  const member = members.data?.find((one) => one.id === id.toLowerCase());
  const missing = !isUuid(id) || (members.isSuccess && member === undefined);
  if (missing || members.isError) {
    return (
      <NotShown
        back={back}
        missing={missing}
        error={members.error}
        notFound={t('members.notFound')}
        integrity={t('members.integrity')}
        onRetry={() => void members.refetch()}
      />
    );
  }
  if (member === undefined) return <Loading />;
  return (
    <section className="stack request">
      {back}
      <MemberShown member={member} now={members.data ?? []} />
    </section>
  );
}
