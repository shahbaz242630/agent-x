// Connecting an app (6E3b, ADR-016; MCP-Guide M5; SEC-OAUTH-10): the page an
// MCP client's authorize sends the browser to, `/connect?request=<id>`, drawn
// before any organisation is chosen (the person picks one here). Only the
// browser that opened the request reads it (the API's cookie): anyone else, or
// a request decided or ended, is told it can't be answered. The app is named
// by what it says it is, never as proof; the host it sends the person back to
// is shown in bold, with a warning for an app on this computer and for a
// website Agent X doesn't know. Signed out, the person signs in and comes
// back here, the request kept in the address.
// Allow goes by the shared step-up (connect-choose.tsx); back with
// `?stepped=<challenge>`, the change kept for it is shown to confirm, and the
// confirm's answer sends the browser back to the app with its code, this once.
// A retry of a confirm already made has no address to go to, and says so.
// `/connect?problem=…` is a request the API wouldn't send back to the app (an
// unknown app, an address it didn't register): explained, never followed.
import { useQueryClient } from '@tanstack/react-query';
import { useNavigate, useRouterState } from '@tanstack/react-router';
import { useEffect, useState } from 'react';

import { SCOPES } from '../agents.ts';
import { ApiError, isRefusal, isSignedOut, isUuid, signInAddress } from '../api.ts';
import {
  type ConnectionRequest,
  connectRefusal,
  deviceAnswered,
  isWebAddress,
  requestAt,
  useConnectionRequest,
} from '../connections.ts';
import { goTo } from '../navigate.ts';
import { timeText } from '../requests.ts';
import { endSession, type Session } from '../session.tsx';
import { confirm, forget, isUndecided, type PendingChange, pendingFor, STEP_UP_FAILED, STEPPED } from '../step-up.ts';
import { t, type TextKey } from '../text.ts';
import { Scopes } from './agent.tsx';
import { Choose, type Seed } from './connect-choose.tsx';
import { Failed, Loading } from './failed.tsx';
import { Panel } from './panel.tsx';
import { ConfirmKept, Ended } from './stepped-up.tsx';

export const CONNECT = '/connect';

/** The problems the API names when it won't send the browser back to the app, each in plain words. */
const PROBLEMS: ReadonlyMap<string, TextKey> = new Map([
  ['unknown_client', 'connect.problem.unknown_client'],
  ['unregistered_redirect', 'connect.problem.unregistered_redirect'],
  ['temporarily_unavailable', 'connect.problem.temporarily_unavailable'],
]);

/** The page's own address for a request: where sign-in and the step-up come back to. */
const pageOf = (id: string): string => `${CONNECT}?${new URLSearchParams({ request: id }).toString()}`;

/** A change kept for this request's consent, as the form's starting choices. */
function seedOf(pending: PendingChange | undefined): Seed | undefined {
  if (pending?.organization === undefined) return undefined;
  const { agentId, scopes } = pending.body;
  if (typeof agentId !== 'string' || !Array.isArray(scopes)) return undefined;
  return { organization: pending.organization, agentId, scopes: SCOPES.filter((scope) => scopes.includes(scope)) };
}

/** Where the person goes back to, with its warning; for a device, the warning that the device is theirs. */
function SendsBack({ request }: { readonly request: ConnectionRequest }) {
  if (request.redirectHost === null) return <p className="notice">{t('connect.device')}</p>;
  return (
    <>
      <p>
        {t('connect.sendsBack')} <strong className="mono">{request.redirectHost}</strong>
      </p>
      <p className="notice">
        {request.loopback ? t('connect.loopback') : t('connect.unknownHost', { host: request.redirectHost })}
      </p>
    </>
  );
}

/** Who asks, where the person goes back to, and what is asked for. */
function Asking({ request }: { readonly request: ConnectionRequest }) {
  const { name, verifiedBy } = request.client;
  return (
    <>
      {/* A document's host vouches for its name (CIMD); a name an app registered is only what it says. */}
      {verifiedBy === null ? (
        <p>{t('connect.says', { name })}</p>
      ) : (
        <p>
          {t('connect.verified', { name })} <strong className="mono">{verifiedBy}</strong>
        </p>
      )}
      <SendsBack request={request} />
      <h2>{t('connect.askedTitle')}</h2>
      <Scopes scopes={request.scopesAsked} />
      <p className="fine">{t('connect.endsAt', { time: timeText(request.endsAt) })}</p>
    </>
  );
}

type Sent = 'ready' | 'sending' | 'leaving' | 'retried' | { readonly said: string; readonly decided: boolean };

/** Back from signing in again: the connection kept for it, confirmed or not made. */
function Confirming({
  pending,
  device,
  onClose,
}: {
  readonly pending: PendingChange;
  /** A device's request: once made, back to `/device`, as the device takes its tokens itself. */
  readonly device: boolean;
  readonly onClose: () => void;
}) {
  const queries = useQueryClient();
  const [sent, setSent] = useState<Sent>('ready');
  const send = async () => {
    setSent('sending');
    try {
      const answer = await confirm(pending);
      const redirectTo = typeof answer === 'object' && answer !== null && 'redirectTo' in answer && answer.redirectTo;
      if (isWebAddress(redirectTo)) {
        setSent('leaving');
        goTo(redirectTo);
        return;
      }
      if (device && redirectTo === null) {
        setSent('leaving');
        goTo(deviceAnswered('allowed'));
        return;
      }
      // Made on an earlier try: its code was given then, once.
      if (redirectTo === null) setSent('retried');
      else throw new ApiError(502, 'UNREADABLE');
    } catch (error) {
      // To sign-in, which comes back here, the change still kept (confirm keeps it for a 401).
      if (isSignedOut(error)) {
        endSession(queries);
        return;
      }
      const decided = isRefusal(error) && !isUndecided(error);
      setSent({ said: isUndecided(error) ? t('stepUp.busy') : connectRefusal(error), decided });
      // Refused: the request may have ended, which reading it again shows.
      if (decided) await queries.invalidateQueries({ queryKey: ['oauth-request'] });
    }
  };
  if (sent === 'leaving') return <p role="status">{t('connect.leaving')}</p>;
  if (sent === 'retried') {
    return (
      <p className="notice" role="status">
        {t('connect.retried')}
      </p>
    );
  }
  if (typeof sent === 'object' && sent.decided) {
    return (
      <Ended onClose={onClose}>
        <p>{t('stepUp.notMade', { change: pending.label })}</p>
        <p>{sent.said}</p>
      </Ended>
    );
  }
  return (
    <ConfirmKept
      pending={pending}
      sending={sent === 'sending'}
      said={typeof sent === 'object' ? sent.said : undefined}
      onSend={() => void send()}
      onDrop={onClose}
    />
  );
}

/** A step-up's way back, with the page's own address kept: the change kept for it, a failed sign-in, or neither. */
function useStepBack(id: string, query: URLSearchParams) {
  const navigate = useNavigate();
  const challenge = query.get(STEPPED);
  const failed = query.get(STEP_UP_FAILED);
  const failedFor = failed !== null && isUuid(failed) ? failed : undefined;
  // Read once, on the way back: the form starts from it after a "don't make it" too.
  const [pending] = useState(() => {
    const kept = challenge === null ? undefined : pendingFor(challenge);
    // Only a change of this request's consent is confirmed here.
    return kept?.confirmPath === `${requestAt(id)}/consent/confirm` ? kept : undefined;
  });
  useEffect(() => {
    if (failedFor !== undefined) forget(failedFor);
  }, [failedFor]);
  const close = () => {
    void navigate({ href: pageOf(id), replace: true });
  };
  return { challenge, failedFor, pending, close };
}

/** One request, read: who asks and what for, then the choice or its confirm. */
function Request({
  id,
  session,
  query,
}: {
  readonly id: string;
  readonly session: Session;
  readonly query: URLSearchParams;
}) {
  const read = useConnectionRequest(id);
  const { challenge, failedFor, pending, close } = useStepBack(id, query);
  if (read.isPending) return <Loading />;
  if (read.isError) {
    if (!(read.error instanceof ApiError && read.error.status === 404)) {
      return <Failed onRetry={() => void read.refetch()} />;
    }
    return (
      <Panel id="connect" title={t('connect.endedTitle')} narrow>
        <p className="notice">{t('connect.ended')}</p>
      </Panel>
    );
  }
  let back = null;
  if (failedFor !== undefined)
    back = (
      <p className="notice" role="alert">
        {t('stepUp.signInFailed')}
      </p>
    );
  else if (challenge !== null && pending === undefined)
    back = (
      <p className="notice" role="alert">
        {t('stepUp.lost')}
      </p>
    );
  const confirming = challenge !== null && pending !== undefined;
  return (
    <Panel id="connect" title={t('connect.title')}>
      <Asking request={read.data} />
      {back}
      {confirming ? (
        <Confirming pending={pending} device={read.data.via === 'device'} onClose={close} />
      ) : (
        <Choose request={read.data} session={session} seed={seedOf(pending)} />
      )}
    </Panel>
  );
}

export function Connect({ session }: { readonly session: Session | null }) {
  // The raw query, not the router's parsed one, which reads values as JSON.
  const search = useRouterState({ select: ({ location }) => location.searchStr });
  const query = new URLSearchParams(search);
  const problem = query.get('problem');
  const id = query.get('request') ?? '';
  if (problem !== null) {
    return (
      <Panel id="connect" title={t('connect.problemTitle')} narrow>
        <p className="notice">{t(PROBLEMS.get(problem) ?? 'connect.problem.other')}</p>
      </Panel>
    );
  }
  if (!isUuid(id)) {
    return (
      <Panel id="connect" title={t('connect.title')} narrow>
        <p className="notice">{t('connect.noRequest')}</p>
      </Panel>
    );
  }
  if (session === null) {
    return (
      <Panel id="connect" title={t('connect.title')} narrow>
        <p>{t('connect.signInFirst')}</p>
        <button
          type="button"
          className="primary"
          onClick={() => {
            goTo(signInAddress(pageOf(id)));
          }}
        >
          {t('signedOut.button')}
        </button>
      </Panel>
    );
  }
  return <Request id={id} session={session} query={query} />;
}
