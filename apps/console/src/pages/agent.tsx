// One agent's page (6D1): `/agents/<id>`, from its row on the Agents tab.
// Its name and ID (two may share a name, SEC-AG-10), who is responsible for
// it, what it may do, and its keys: each key's ID, status and expiry, never a
// secret (the API keeps only a MAC). A live key can be rotated (a new key,
// the old one kept for the overlap or ended at once, chosen in the API's
// `old_key` words with none picked, decision 22) or revoked (it stops at
// once, said in the console's words: the API states none). An admin can hand
// the agent to another active admin or developer, which revokes every key and
// makes a new one. Each goes by passkey (the shared step-up); a new key is
// shown once on the way back (stepped-up.tsx, key-once.tsx). Buttons show by
// role (rotating: an admin, or the developer who owns it); the API checks again.
import { Link } from '@tanstack/react-router';
import { useState } from 'react';

import {
  type Agent,
  type AgentKey,
  agentAt,
  agentRefusal,
  HANDING_OVER,
  isLive,
  KEY_CHANGING,
  type Member,
  OWNING,
  type Scope,
  useAgent,
  useMembers,
} from '../agents.ts';
import { isMissing } from '../api.ts';
import { MANAGING } from '../mandates.ts';
import { Confirm } from '../confirm.tsx';
import { timeText } from '../requests.ts';
import { useActing } from '../session.tsx';
import { byPasskey } from '../step-up.ts';
import { t } from '../text.ts';
import { Said, useChange } from './change.tsx';
import { Loading, NotShown } from './failed.tsx';

/** A member as the console can name them: the API gives a role and IDs, no name. */
export function memberText(member: Member | undefined, me: string): string {
  if (member === undefined) return t('agents.memberUnknown');
  const role = t(`choose.role.${member.role}`);
  return member.userId.toLowerCase() === me ? `${role} ${t('payments.you')}` : role;
}

/** What an agent may do, each scope in plain words: on its page, and confirming a registration. */
export function Scopes({ scopes }: { readonly scopes: readonly Scope[] }) {
  return (
    <ul className="plain">
      {scopes.map((scope) => (
        <li key={scope}>{t(`agents.scope.${scope}`)}</li>
      ))}
    </ul>
  );
}

function keyState(key: AgentKey, live: boolean): string {
  if (key.status === 'REVOKED') return t('agents.key.revoked');
  const at = timeText(key.expiresAt);
  return live ? t('agents.key.until', { time: at }) : t('agents.key.expired', { time: at });
}

type Open =
  | { readonly kind: 'none' }
  | { readonly kind: 'rotate'; readonly key: AgentKey }
  | { readonly kind: 'revoke'; readonly key: AgentKey }
  | { readonly kind: 'owner'; readonly member: Member };
const NONE: Open = { kind: 'none' };

function KeyRow({
  agentKey,
  canRotate,
  canRevoke,
  busy,
  onOpen,
}: {
  readonly agentKey: AgentKey;
  readonly canRotate: boolean;
  readonly canRevoke: boolean;
  readonly busy: boolean;
  readonly onOpen: (open: Open) => void;
}) {
  const live = isLive(agentKey);
  return (
    <li className="row">
      <span className="row-main">
        <span className="mono">{agentKey.id}</span>
        <span className="muted">{keyState(agentKey, live)}</span>
        <span className="muted">{agentKey.scopes.map((scope) => t(`agents.scope.${scope}`)).join(' · ')}</span>
      </span>
      {live && (canRotate || canRevoke) && (
        <span className="actions">
          {canRotate && (
            <button
              type="button"
              className="secondary"
              disabled={busy}
              aria-label={t('agents.rotateNamed', { key: agentKey.id })}
              onClick={() => {
                onOpen({ kind: 'rotate', key: agentKey });
              }}
            >
              {t('agents.rotate')}
            </button>
          )}
          {canRevoke && (
            <button
              type="button"
              className="secondary"
              disabled={busy}
              aria-label={t('agents.revokeNamed', { key: agentKey.id })}
              onClick={() => {
                onOpen({ kind: 'revoke', key: agentKey });
              }}
            >
              {t('agents.revoke')}
            </button>
          )}
        </span>
      )}
    </li>
  );
}

/** Handing the agent over: chosen among the active admins and developers other than its owner. */
function HandOver({
  agent,
  members,
  me,
  busy,
  onOpen,
}: {
  readonly agent: Agent;
  readonly members: readonly Member[];
  readonly me: string;
  readonly busy: boolean;
  readonly onOpen: (open: Open) => void;
}) {
  const [chosen, setChosen] = useState('');
  const eligible = members.filter(
    (member) => member.status === 'ACTIVE' && OWNING.includes(member.role) && member.id !== agent.owner,
  );
  const picked = eligible.find((member) => member.id === chosen);
  return (
    <section className="stack" aria-labelledby="owner-title">
      <h2 id="owner-title">{t('agents.ownerTitle')}</h2>
      <p className="muted">{t('agents.ownerIntro')}</p>
      {eligible.length === 0 ? (
        <p className="muted">{t('agents.ownerNone')}</p>
      ) : (
        <>
          <label className="field" htmlFor="agent-owner">
            {t('agents.ownerChoose')}
          </label>
          <select
            id="agent-owner"
            value={chosen}
            onChange={(event) => {
              setChosen(event.target.value);
            }}
          >
            <option value="">{t('agents.ownerPick')}</option>
            {eligible.map((member) => (
              <option key={member.id} value={member.id}>
                {`${memberText(member, me)} · ${member.id}`}
              </option>
            ))}
          </select>
          <button
            type="button"
            className="primary"
            disabled={busy || picked === undefined}
            onClick={() => {
              if (picked !== undefined) onOpen({ kind: 'owner', member: picked });
            }}
          >
            {t('agents.ownerButton')}
          </button>
        </>
      )}
    </section>
  );
}

function AgentShown({ agent, keys }: { readonly agent: Agent; readonly keys: readonly AgentKey[] }) {
  const { organization, session } = useActing();
  const members = useMembers(organization.id);
  const { busy, said, run } = useChange(agentRefusal);
  const [open, setOpen] = useState<Open>(NONE);
  const me = session.userId.toLowerCase();
  const listed = members.data ?? [];
  const owner = listed.find((member) => member.id === agent.owner);
  const role = organization.role;
  // Rotating is an admin's, or the developer's who owns it (agent-key-changes.ts mayRotate); revoking any of either.
  const canRevoke = KEY_CHANGING.includes(role);
  const canRotate = role === 'admin' || (canRevoke && owner?.userId.toLowerCase() === me);
  const close = () => {
    setOpen(NONE);
  };
  const at = agentAt(agent.id);
  const keyAt = (key: AgentKey) => `${at}/keys/${encodeURIComponent(key.id)}`;
  // Each is done on its way back from the passkey (stepped-up.tsx), the new key shown there: none said here.
  const send = (label: string, path: string, body: Readonly<Record<string, unknown>>, statementVersion?: number) =>
    run(
      // No version (a revoke, a hand-over: no API words) is left out of the confirm's JSON.
      () => byPasskey(path, label, body, organization.id, { statementVersion }),
      { after: close },
    );
  const names = (key: AgentKey) => ({ key: key.id, name: agent.name });

  return (
    <>
      <span className="kicker">{t(`agents.status.${agent.status}`)}</span>
      <h1>{agent.name}</h1>
      <dl className="facts">
        <dt>{t('agents.id')}</dt>
        <dd className="mono">{agent.id}</dd>
        <dt>{t('agents.owner')}</dt>
        <dd>
          {memberText(owner, me)} <span className="mono">{agent.owner}</span>
        </dd>
        <dt>{t('agents.registered')}</dt>
        <dd>{timeText(agent.createdAt)}</dd>
        <dt>{t('agents.mayDo')}</dt>
        <dd>
          <Scopes scopes={agent.scopes} />
        </dd>
      </dl>
      <section className="stack" aria-labelledby="keys-title">
        <h2 id="keys-title">{t('agents.keys')}</h2>
        <p className="muted">{t('agents.keysIntro')}</p>
        {!canRevoke && <p className="muted">{t('agents.keysViewOnly')}</p>}
        {keys.length === 0 ? (
          <p className="muted">{t('agents.keysNone')}</p>
        ) : (
          <ul className="rows">
            {keys.map((key) => (
              <KeyRow
                key={key.id}
                agentKey={key}
                canRotate={canRotate}
                canRevoke={canRevoke}
                busy={busy}
                onOpen={setOpen}
              />
            ))}
          </ul>
        )}
      </section>
      <section className="stack" aria-labelledby="agent-mandates">
        <h2 id="agent-mandates">{t('mandates.title')}</h2>
        <p className="muted">{t('mandates.agentIntro')}</p>
        <Link to="/more/mandates">{t('mandates.agentList')}</Link>
        {MANAGING.includes(role) && agent.status === 'ACTIVE' && (
          <Link to="/more/mandates/new" search={{ agent: agent.id }}>
            {t('mandates.agentDraft')}
          </Link>
        )}
      </section>
      {HANDING_OVER.includes(role) && members.isSuccess && (
        <HandOver agent={agent} members={listed} me={me} busy={busy} onOpen={setOpen} />
      )}
      <Said said={said} />
      {open.kind === 'rotate' && (
        <Confirm
          statement="old_key"
          title={t('agents.rotateTitle', names(open.key))}
          confirmLabel={t('brakes.passkeyConfirm')}
          busy={busy}
          onCancel={close}
          onConfirm={(oldKey, version) =>
            void send(t('agents.rotateLabel', names(open.key)), `${keyAt(open.key)}/rotate`, { oldKey }, version)
          }
        >
          <p className="mono">{open.key.id}</p>
          <p>{t('agents.rotateNew')}</p>
        </Confirm>
      )}
      {open.kind === 'revoke' && (
        <Confirm
          text={t('agents.revokeText')}
          title={t('agents.revokeTitle', names(open.key))}
          confirmLabel={t('brakes.passkeyConfirm')}
          busy={busy}
          onCancel={close}
          onConfirm={() => void send(t('agents.revokeLabel', names(open.key)), `${keyAt(open.key)}/revoke`, {})}
        >
          <p className="mono">{open.key.id}</p>
        </Confirm>
      )}
      {open.kind === 'owner' && (
        <Confirm
          text={t('agents.ownerText')}
          title={t('agents.ownerConfirmTitle', { name: agent.name })}
          confirmLabel={t('brakes.passkeyConfirm')}
          busy={busy}
          onCancel={close}
          onConfirm={() =>
            void send(t('agents.ownerLabel', { name: agent.name }), `${at}/owner`, { owner: open.member.id })
          }
        >
          <p>
            {memberText(open.member, me)} <span className="mono">{open.member.id}</span>
          </p>
        </Confirm>
      )}
    </>
  );
}

export function AgentPage({ id }: { readonly id: string }) {
  const { organization } = useActing();
  const shown = useAgent(id, organization.id);
  const back = (
    <Link to="/agents" className="back">
      {t('agents.back')}
    </Link>
  );
  const missing = isMissing(id, shown.error);
  if (missing || shown.isError) {
    return (
      <NotShown
        back={back}
        missing={missing}
        error={shown.error}
        notFound={t('agents.notFound')}
        integrity={t('agents.integrity')}
        onRetry={() => void shown.refetch()}
      />
    );
  }
  if (shown.isPending) return <Loading />;
  return (
    <section className="stack request">
      {back}
      <AgentShown agent={shown.data.agent} keys={shown.data.keys} />
    </section>
  );
}
