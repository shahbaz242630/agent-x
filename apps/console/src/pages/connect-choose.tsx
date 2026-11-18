// Choosing on `/connect` (6E3b, ADR-016; SEC-OAUTH-08, -10): the organisation
// (among those the person is an admin or developer of), the agent the app acts
// as (an active one; a developer's own alone, as the API allows), and what it
// may do: only what the app asked for and the agent holds, a write scope never
// ticked for the person (decision 8). Allow asks for the connection and goes to
// sign in again (the shared step-up, a passkey for an admin), coming back to
// `/connect` to confirm; Deny tells the app no. Choices come back over the
// step-up from what it kept (`seed`), so a "don't make it" finds them as left.
import { useState } from 'react';

import { type Agent, KEY_CHANGING, REGISTERING, type Scope, useMembers } from '../agents.ts';
import { api, ApiError } from '../api.ts';
import {
  type ConnectionRequest,
  connectRefusal,
  deviceAnswered,
  isWebAddress,
  isWriteScope,
  requestAt,
  tickable,
  useAgentsOf,
} from '../connections.ts';
import { goTo } from '../navigate.ts';
import { type Organization, type Session, useOrganizations } from '../session.tsx';
import { byPasskey } from '../step-up.ts';
import { t } from '../text.ts';
import { Said, useChange } from './change.tsx';
import { Loading, Retry } from './failed.tsx';

/** What was chosen before a step-up, kept with its change: back to the same ticks. */
export interface Seed {
  readonly organization: string;
  readonly agentId: string;
  readonly scopes: readonly Scope[];
}

/** The ticks an agent starts with: what can be ticked, less any write scope (decision 8). */
const startingTicks = (request: ConnectionRequest, agent: Agent): readonly Scope[] =>
  tickable(request.scopesAsked, agent.scopes).filter((scope) => !isWriteScope(scope));

/** The agents the person may connect: active, and their own unless they are an admin (the API's owner rule). */
function useConnectable(organization: Organization, session: Session) {
  const agents = useAgentsOf(organization.id);
  const members = useMembers(organization.id);
  const admin = organization.role === 'admin';
  const me = session.userId.toLowerCase();
  const mine = members.data?.find((member) => member.userId.toLowerCase() === me)?.id;
  const failed = agents.isError || (!admin && members.isError);
  const pending = agents.isPending || (!admin && members.isPending);
  const connectable = (agents.data ?? []).filter(
    (agent) => agent.status === 'ACTIVE' && (admin || agent.owner === mine),
  );
  const retry = () => {
    void agents.refetch();
    void members.refetch();
  };
  return { connectable, failed, pending, retry };
}

/** One labelled choice among a list, none picked until the person picks. */
function Pick({
  id,
  label,
  pick,
  value,
  options,
  onPick,
}: {
  readonly id: string;
  readonly label: string;
  readonly pick: string;
  readonly value: string;
  readonly options: readonly { readonly id: string; readonly text: string }[];
  readonly onPick: (id: string) => void;
}) {
  return (
    <>
      <label className="field" htmlFor={id}>
        {label}
      </label>
      <select
        id={id}
        value={value}
        onChange={(event) => {
          onPick(event.target.value);
        }}
      >
        <option value="">{pick}</option>
        {options.map((option) => (
          <option key={option.id} value={option.id}>
            {option.text}
          </option>
        ))}
      </select>
    </>
  );
}

/** The ticks for the agent picked: what it may do of what was asked, and what was asked that it can't. */
function Ticks({
  request,
  agent,
  ticks,
  onTicks,
}: {
  readonly request: ConnectionRequest;
  readonly agent: Agent;
  readonly ticks: readonly Scope[];
  readonly onTicks: (ticks: readonly Scope[]) => void;
}) {
  const offered = tickable(request.scopesAsked, agent.scopes);
  const notHeld = request.scopesAsked.filter((scope) => !agent.scopes.includes(scope));
  if (offered.length === 0) return <p className="notice">{t('connect.scopesNone')}</p>;
  return (
    <>
      <fieldset className="options">
        <legend>{t('connect.scopesLegend')}</legend>
        {offered.map((scope) => (
          <label key={scope} className="option">
            <input
              type="checkbox"
              checked={ticks.includes(scope)}
              onChange={() => {
                onTicks(ticks.includes(scope) ? ticks.filter((one) => one !== scope) : [...ticks, scope]);
              }}
            />
            <span>{t(`agents.scope.${scope}`)}</span>
          </label>
        ))}
      </fieldset>
      <p className="fine">{t('connect.scopesHint')}</p>
      {notHeld.length > 0 && (
        <p className="muted">
          {t('connect.notHeld', { scopes: notHeld.map((scope) => t(`agents.scope.${scope}`)).join(' · ') })}
        </p>
      )}
    </>
  );
}

/** Tells the app no, and goes back to it with that: leaving the page, as a step-up does. */
async function deny(request: ConnectionRequest, organization: string): Promise<'stepping'> {
  const { redirectTo } = await api.post<{ readonly redirectTo: unknown }>(`${requestAt(request.id)}/deny`, {
    organization,
    body: {},
  });
  // A device's has none: it learns the answer by polling, and the person is told so.
  if (request.via === 'device' && redirectTo === null) {
    goTo(deviceAnswered('denied'));
    return 'stepping';
  }
  // Only ever a web address the app registered; anything else is never followed.
  if (!isWebAddress(redirectTo)) throw new ApiError(502, 'UNREADABLE');
  goTo(redirectTo);
  return 'stepping';
}

/** The agent picker and the ticks, for the organisation chosen. */
function AgentChoice({
  request,
  organization,
  session,
  seed,
  onDeny,
  change,
}: {
  readonly request: ConnectionRequest;
  readonly organization: Organization;
  readonly session: Session;
  readonly seed: Seed | undefined;
  readonly onDeny: () => void;
  readonly change: ReturnType<typeof useChange>;
}) {
  const { connectable, failed, pending, retry } = useConnectable(organization, session);
  const seeded = seed?.organization === organization.id ? seed : undefined;
  const [agentId, setAgentId] = useState(seeded?.agentId ?? '');
  const [ticks, setTicks] = useState<readonly Scope[] | undefined>(seeded?.scopes);
  const [broken, setBroken] = useState(false);
  if (failed) return <Retry onRetry={retry} />;
  if (pending) return <Loading />;
  const agent = connectable.find((one) => one.id === agentId);
  // Kept ticks too are only what can be ticked now: a scope the agent lost over the step-up has no box, so is never sent.
  const offered = agent === undefined ? [] : tickable(request.scopesAsked, agent.scopes);
  const ticked =
    agent === undefined ? [] : (ticks ?? startingTicks(request, agent)).filter((scope) => offered.includes(scope));
  // Sent in the API's own order, and only what can be ticked for this agent.
  const scopes = offered.filter((scope) => ticked.includes(scope));
  const allow = () => {
    if (agent === undefined) return;
    if (scopes.length === 0) {
      setBroken(true);
      return;
    }
    const label = t('connect.label', { client: request.client.name, agent: agent.name });
    void change.run(() =>
      byPasskey(`${requestAt(request.id)}/consent`, label, { agentId: agent.id, scopes }, organization.id),
    );
  };
  return (
    <>
      {connectable.length === 0 ? (
        <p className="notice">{t('connect.agentNone')}</p>
      ) : (
        <Pick
          id="connect-agent"
          label={t('connect.agentChoose')}
          pick={t('connect.agentPick')}
          value={agent?.id ?? ''}
          options={connectable.map((one) => ({ id: one.id, text: `${one.name} · ${one.id}` }))}
          onPick={(id) => {
            setAgentId(id);
            setTicks(undefined);
            setBroken(false);
          }}
        />
      )}
      {REGISTERING.includes(organization.role) && (
        <p className="fine">
          <a href={`/agents?org=${encodeURIComponent(organization.id)}`} target="_blank" rel="noopener noreferrer">
            {t('agents.register')}
          </a>{' '}
          {t('connect.registerHint')}
        </p>
      )}
      {agent !== undefined && (
        <Ticks
          request={request}
          agent={agent}
          ticks={ticked}
          onTicks={(next) => {
            setTicks(next);
            setBroken(false);
          }}
        />
      )}
      {broken && (
        <p className="notice" role="alert">
          {t('connect.scopesBroken')}
        </p>
      )}
      <p className="fine">{t('connect.allowHint')}</p>
      <div className="actions">
        <button type="button" className="secondary" disabled={change.busy} onClick={onDeny}>
          {t('connect.deny')}
        </button>
        <button
          type="button"
          className="primary"
          disabled={change.busy || agent === undefined || tickable(request.scopesAsked, agent.scopes).length === 0}
          onClick={allow}
        >
          {t('connect.allow')}
        </button>
      </div>
    </>
  );
}

/** The organisation, then the agent and the ticks; Allow and Deny. */
export function Choose({
  request,
  session,
  seed,
}: {
  readonly request: ConnectionRequest;
  readonly session: Session;
  readonly seed: Seed | undefined;
}) {
  const organizations = useOrganizations();
  const change = useChange(connectRefusal);
  const [chosenId, setChosenId] = useState(seed?.organization ?? '');
  if (organizations.isError) return <Retry onRetry={() => void organizations.refetch()} />;
  if (organizations.isPending) return <Loading />;
  const eligible = organizations.data.organizations.filter((one) => KEY_CHANGING.includes(one.role));
  if (eligible.length === 0) return <p className="notice">{t('connect.orgNone')}</p>;
  const chosen = eligible.length === 1 ? eligible[0] : eligible.find((one) => one.id === chosenId);
  // Any organisation the person may connect in can tell the app no: the answer names none.
  const denyIn = chosen ?? eligible[0];
  const onDeny = () => {
    if (denyIn !== undefined) void change.run(() => deny(request, denyIn.id));
  };
  return (
    <section className="stack">
      {eligible.length > 1 && (
        <Pick
          id="connect-org"
          label={t('connect.orgChoose')}
          pick={t('connect.orgPick')}
          value={chosen?.id ?? ''}
          options={eligible.map((one) => ({ id: one.id, text: one.name }))}
          onPick={setChosenId}
        />
      )}
      {chosen === undefined ? (
        <div className="actions">
          <button type="button" className="secondary" disabled={change.busy} onClick={onDeny}>
            {t('connect.deny')}
          </button>
        </div>
      ) : (
        <AgentChoice
          key={chosen.id}
          request={request}
          organization={chosen}
          session={session}
          seed={seed}
          onDeny={onDeny}
          change={change}
        />
      )}
      <Said said={change.said} />
    </section>
  );
}
