// The organisation's members (6D4b; BR-01, BR-02): `/more/members`, for any
// of its roles to read. Each member by role, "(you)" for the person signed in,
// their membership ID, whether they are active and since when; an admin sees
// each by "Name (email)" too, as the API names them to admins alone (S212 F3,
// decision 27), their role beside it. Each
// opens their page (member.tsx), where an admin changes a role, deactivates
// them or resets a lost second factor. An admin also invites people,
// confirms or declines who accepted an admin's or approver's invitation
// (invite.tsx), and reaches the registered contacts and the factor resets.
import { Link } from '@tanstack/react-router';

import { type Member, useMembers } from '../agents.ts';
import { isIntegrityFailed } from '../api.ts';
import { timeText } from '../requests.ts';
import { useActing } from '../session.tsx';
import { t } from '../text.ts';
import { memberText, namedText } from './agent.tsx';
import { Loading, Retry } from './failed.tsx';
import { Invite, WaitingInvitation } from './invite.tsx';
import { Tag } from './tag.tsx';

function Row({ member, me }: { readonly member: Member; readonly me: string }) {
  return (
    <li className="row">
      <span className="row-main">
        <span>
          <Link to="/more/members/$id" params={{ id: member.id }}>
            {memberText(member, me)}
          </Link>
          {member.status === 'DEACTIVATED' && <Tag warn>{t('members.status.DEACTIVATED')}</Tag>}
        </span>
        {namedText(member) !== undefined && <span className="muted">{t(`choose.role.${member.role}`)}</span>}
        <span className="mono fine">{member.id}</span>
        <span className="muted">{t('members.since', { time: timeText(member.joinedAt) })}</span>
      </span>
    </li>
  );
}

function MemberList() {
  const { organization, session } = useActing();
  const members = useMembers(organization.id);
  if (members.isPending) return <Loading />;
  if (members.isError) {
    return isIntegrityFailed(members.error) ? (
      <p className="notice" role="alert">
        {t('members.integrity')}
      </p>
    ) : (
      <Retry onRetry={() => void members.refetch()} />
    );
  }
  const me = session.userId.toLowerCase();
  return (
    <ul className="rows">
      {members.data.map((member) => (
        <Row key={member.id} member={member} me={me} />
      ))}
    </ul>
  );
}

export function Members() {
  const { organization } = useActing();
  const admin = organization.role === 'admin';
  return (
    <section className="stack">
      <Link to="/more" className="back to-more">
        {t('members.backToMore')}
      </Link>
      <h1>{t('members.title')}</h1>
      <p className="muted">{t(admin ? 'members.introNamed' : 'members.intro')}</p>
      <MemberList />
      {admin && (
        <>
          <nav className="stack" aria-label={t('members.trust')}>
            <h2>{t('members.trust')}</h2>
            <Link to="/more/contacts">{t('contacts.title')}</Link>
            <Link to="/more/factor-resets">{t('resets.title')}</Link>
          </nav>
          <Invite />
          <WaitingInvitation />
        </>
      )}
    </section>
  );
}
