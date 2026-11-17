// Accepting an invitation (6D4b; PRD §7.1, ADR-005 §6): the page the link an
// admin sends opens, `/invitations/accept#token=…`, before any organisation is
// chosen (the person may belong to none yet: a first admin). The token is read
// from the fragment once and the address cleaned of it (arrived-token.ts); it
// goes nowhere but `POST /v1/invitations/accept`, which needs the person
// signed in with the login whose verified email is the invited one. Signed
// out, the page says so: signing in leaves the page, and the token with it,
// so the link is opened again after. Nothing happens on arrival: the person
// presses Accept. A developer or viewer joins at once; an admin or approver
// (or anyone rejoining) waits for an admin of the organisation to confirm
// them, by the invitation's ID, which the page shows to pass on.
import { useQueryClient } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { useState } from 'react';

import { api, isSignedOut, signInAddress } from '../api.ts';
import { useArrivedToken } from '../arrived-token.ts';
import { goTo } from '../navigate.ts';
import { invitationRefusal, type Invitation } from '../people.ts';
import { endSession, type Session } from '../session.tsx';
import { t } from '../text.ts';
import { Panel } from './panel.tsx';

/** The token's form, as the API takes it: 32 random bytes in base64url. */
const TOKEN = /^[\w-]{43}$/;

const PAGE = '/invitations/accept';

type Sent =
  | { readonly kind: 'ready' | 'sending' }
  | { readonly kind: 'accepted'; readonly invitation: Invitation }
  | { readonly kind: 'refused'; readonly said: string };

/** Accepted: joined now, or waiting for an admin's confirmation, with the ID to give them. */
function Accepted({ invitation }: { readonly invitation: Invitation }) {
  const role = t(`choose.role.${invitation.role}`);
  if (invitation.status !== 'AWAITING_CONFIRMATION') {
    return (
      <Panel id="accept" title={t('invitations.accept.joinedTitle')} narrow>
        <p role="status">{t('invitations.accept.joined', { role })}</p>
        <Link to="/approvals">{t('invitations.accept.open')}</Link>
      </Panel>
    );
  }
  return (
    <Panel id="accept" title={t('invitations.accept.waitingTitle')} narrow>
      <p role="status">{t('invitations.accept.waiting', { role })}</p>
      <dl className="facts">
        <dt>{t('invitations.id')}</dt>
        <dd className="mono">{invitation.id}</dd>
      </dl>
    </Panel>
  );
}

export function AcceptInvitation({ session }: { readonly session: Session | null }) {
  const arrived = useArrivedToken(TOKEN);
  const queries = useQueryClient();
  const [sent, setSent] = useState<Sent>({ kind: 'ready' });
  if (sent.kind === 'accepted') return <Accepted invitation={sent.invitation} />;
  if (arrived === 'none' || arrived === 'malformed') {
    return (
      <Panel id="accept" title={t('invitations.accept.title')} narrow>
        <p className="notice" role="alert">
          {t(arrived === 'none' ? 'invitations.accept.noLink' : 'invitations.accept.badLink')}
        </p>
      </Panel>
    );
  }
  if (session === null) {
    return (
      <Panel id="accept" title={t('invitations.accept.title')} narrow>
        <p>{t('invitations.accept.signInFirst')}</p>
        <button
          type="button"
          className="primary"
          onClick={() => {
            // Back here with no token: the link is opened again once signed in.
            goTo(signInAddress(PAGE));
          }}
        >
          {t('signedOut.button')}
        </button>
      </Panel>
    );
  }
  const accept = async () => {
    setSent({ kind: 'sending' });
    try {
      const answer = await api.post<{ readonly invitation: Invitation }>('/v1/invitations/accept', {
        body: { token: arrived.token },
      });
      setSent({ kind: 'accepted', invitation: answer.invitation });
      // A new organisation, if joined now: listed when the console opens.
      await queries.invalidateQueries({ queryKey: ['organizations'] });
    } catch (error) {
      if (isSignedOut(error)) endSession(queries);
      else setSent({ kind: 'refused', said: invitationRefusal(error) });
    }
  };
  return (
    <Panel id="accept" title={t('invitations.accept.title')} narrow>
      <p>{t('invitations.accept.what')}</p>
      <p className="muted">{t('invitations.accept.which')}</p>
      {sent.kind === 'refused' && (
        <p className="notice" role="alert">
          {sent.said}
        </p>
      )}
      <button type="button" className="primary" disabled={sent.kind === 'sending'} onClick={() => void accept()}>
        {t('invitations.accept.button')}
      </button>
    </Panel>
  );
}
