// Resets of members' lost second factors (6D4b; ADR-003 §4, ADR-012 §8,
// SEC-OPS-04), an admin's alone: `/more/factor-resets`, and each member's own
// on their page. Each reset as the API gives it: whose, who asked, where it
// stands and until when. One still open (a draft, waiting for a registered
// contact, or cooling off) can be cancelled by any admin, at once and with no
// passkey (stopping is never gated), confirmed in the console's words (the API
// states none for it), the dialog pinned to the reset as it showed it. A reset
// is asked from the member's page; it is sent to the contacts on the way back
// from the passkey (stepped-up.tsx). A draft whose step-up was lost can't be
// sent: it is cancelled, and asked again.
import { Link } from '@tanstack/react-router';
import { useState } from 'react';

import { type Member, useMembers } from '../agents.ts';
import { api } from '../api.ts';
import { Confirm } from '../confirm.tsx';
import { isCancellable, type Reset, resetRefusal, useResets } from '../people.ts';
import { timeText } from '../requests.ts';
import { useActing } from '../session.tsx';
import { t } from '../text.ts';
import { Said, useChange } from './change.tsx';
import { Loading, Retry } from './failed.tsx';
import { MemberName, Moved, movedSince } from './people-parts.tsx';
import { useEndStepped } from './stepped-up.tsx';

/** Where a reset stands, and until when where it matters. */
function standing(reset: Reset): string {
  if (reset.status === 'COOLING_OFF' && reset.coolingOffUntil !== null) {
    return t('resets.status.coolingOffUntil', { time: timeText(reset.coolingOffUntil) });
  }
  if (reset.status === 'DRAFT' || reset.status === 'AWAITING_CONTACT') {
    return t(`resets.status.${reset.status}`, { time: timeText(reset.expiresAt) });
  }
  return t(`resets.status.${reset.status}`);
}

const stateOf = (reset: Reset): string => [reset.status, reset.coolingOffUntil].join('/');

function Row({
  reset,
  members,
  me,
  busy,
  onCancel,
}: {
  readonly reset: Reset;
  readonly members: readonly Member[];
  readonly me: string;
  readonly busy: boolean;
  readonly onCancel: (reset: Reset) => void;
}) {
  const find = (id: string) => members.find((member) => member.id === id);
  return (
    <li className="row">
      <span className="row-main">
        <span>
          <MemberName member={find(reset.person)} id={reset.person} me={me} />
        </span>
        <span className="muted">{standing(reset)}</span>
        <span className="fine">
          {t('resets.askedBy')} <MemberName member={find(reset.requestedBy)} id={reset.requestedBy} me={me} />
        </span>
      </span>
      {isCancellable(reset) && (
        <span className="actions">
          <button
            type="button"
            className="secondary"
            disabled={busy}
            aria-label={t('resets.cancelNamed', { id: reset.id })}
            onClick={() => {
              onCancel(reset);
            }}
          >
            {t('resets.cancel')}
          </button>
        </span>
      )}
    </li>
  );
}

/** The resets, all or one member's (`person`), each open one cancellable: shown to an admin only. */
export function ResetList({ person }: { readonly person?: string }) {
  const { organization, session } = useActing();
  const resets = useResets(organization.id);
  const members = useMembers(organization.id);
  const { busy, said, run } = useChange(resetRefusal);
  const [seen, setSeen] = useState<Reset | null>(null);
  const endStepped = useEndStepped();
  const me = session.userId.toLowerCase();
  if (resets.isPending) return <Loading />;
  if (resets.isError) return <Retry error={resets.error} onRetry={() => void resets.refetch()} />;
  const shown = resets.data.filter((reset) => person === undefined || reset.person === person);
  const close = () => {
    setSeen(null);
  };
  const now = seen === null ? undefined : resets.data.find((reset) => reset.id === seen.id);
  const moved = seen !== null && movedSince(seen, now, stateOf);
  const cancel = (reset: Reset) =>
    run(
      async () => {
        const at = `/v1/factor-resets/${encodeURIComponent(reset.id)}`;
        await api.post(`${at}/cancel`, { organization: organization.id, body: {} });
        // What asking the reset said (its draft's confirm, or "asked") is stale now: the cancel's words replace it.
        endStepped(`${at}/confirm`);
      },
      { after: close, done: t('resets.cancelled') },
    );
  return (
    <>
      {shown.length === 0 ? (
        <p className="muted">{t('resets.none')}</p>
      ) : (
        <ul className="rows">
          {shown.map((reset) => (
            <Row key={reset.id} reset={reset} members={members.data ?? []} me={me} busy={busy} onCancel={setSeen} />
          ))}
        </ul>
      )}
      <Said said={said} />
      {seen !== null && (
        <Confirm
          text={t('resets.cancelText')}
          title={t('resets.cancelTitle')}
          confirmLabel={t('resets.cancelConfirm')}
          busy={busy}
          ready={!moved}
          onCancel={close}
          onConfirm={() => void cancel(seen)}
        >
          <Moved moved={moved} />
          <p>
            <MemberName member={members.data?.find((member) => member.id === seen.person)} id={seen.person} me={me} />
          </p>
          <p className="muted">{standing(seen)}</p>
        </Confirm>
      )}
    </>
  );
}

/** `/more/factor-resets`: every reset of the organisation's members' second factors. */
export function Resets() {
  const { organization } = useActing();
  const back = (
    <Link to="/more/members" className="back">
      {t('members.back')}
    </Link>
  );
  return (
    <section className="stack">
      {back}
      <h1>{t('resets.title')}</h1>
      <p className="muted">{t('resets.intro')}</p>
      {organization.role === 'admin' ? <ResetList /> : <p className="muted">{t('resets.adminsOnly')}</p>}
    </section>
  );
}
