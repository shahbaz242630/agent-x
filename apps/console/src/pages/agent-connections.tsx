// An agent's connected apps (6E3b, ADR-016), on its page below its keys: each
// app by what it said it is, the host it sent the person back to (or a
// device's), who allowed it and when, what it may do, when it last connected
// and whether it still works. A live one can be revoked by an admin or a
// developer (as a key can), by the shared step-up: it stops at once.
// Suspending the agent stays the instant brake for every connection at once.
import { useState } from 'react';

import { type Agent, agentRefusal, KEY_CHANGING } from '../agents.ts';
import { Confirm } from '../confirm.tsx';
import { type Connection, connectionsAt, useConnections } from '../connections.ts';
import { timeText } from '../requests.ts';
import { useActing } from '../session.tsx';
import { byPasskey } from '../step-up.ts';
import { t } from '../text.ts';
import { Said, useChange } from './change.tsx';
import { Loading, Retry } from './failed.tsx';

function stateOf(connection: Connection): string {
  if (connection.status === 'REVOKED') return t('connections.status.REVOKED');
  return t(`connections.status.${connection.status}`, { time: timeText(connection.expiresAt) });
}

function ConnectionRow({
  connection,
  madeBy,
  canRevoke,
  busy,
  onRevoke,
}: {
  readonly connection: Connection;
  readonly madeBy: string;
  readonly canRevoke: boolean;
  readonly busy: boolean;
  readonly onRevoke: (connection: Connection) => void;
}) {
  const { clientName, redirectHost, lastConnectedAt } = connection;
  return (
    <li className="row">
      <span className="row-main">
        <span>
          {clientName} {redirectHost === null ? null : <strong className="mono">{redirectHost}</strong>}
        </span>
        {redirectHost === null && <span className="muted">{t('connections.device')}</span>}
        <span className="muted">{t('connections.made', { time: timeText(connection.createdAt), who: madeBy })}</span>
        <span className="muted">{connection.scopes.map((scope) => t(`agents.scope.${scope}`)).join(' · ')}</span>
        <span className="muted">
          {lastConnectedAt === null
            ? t('connections.neverConnected')
            : t('connections.lastConnected', { time: timeText(lastConnectedAt) })}
        </span>
        <span className="muted">{stateOf(connection)}</span>
      </span>
      {canRevoke && connection.status === 'ACTIVE' && (
        <span className="actions">
          <button
            type="button"
            className="secondary"
            disabled={busy}
            aria-label={t('connections.revokeNamed', { client: clientName })}
            onClick={() => {
              onRevoke(connection);
            }}
          >
            {t('connections.revoke')}
          </button>
        </span>
      )}
    </li>
  );
}

/** `named` names a member by their membership, as the agent's page names its owner. */
export function Connections({
  agent,
  named,
}: {
  readonly agent: Agent;
  readonly named: (membershipId: string) => string;
}) {
  const { organization } = useActing();
  const listed = useConnections(agent.id, organization.id);
  const { busy, said, run } = useChange(agentRefusal);
  const [revoking, setRevoking] = useState<Connection | undefined>(undefined);
  const canRevoke = KEY_CHANGING.includes(organization.role);
  const close = () => {
    setRevoking(undefined);
  };
  const names = (connection: Connection) => ({ client: connection.clientName, name: agent.name });
  const revoke = (connection: Connection) =>
    run(
      () =>
        byPasskey(
          `${connectionsAt(agent.id)}/${encodeURIComponent(connection.keyId)}/revoke`,
          t('connections.revokeLabel', names(connection)),
          {},
          organization.id,
        ),
      { after: close },
    );
  let shown = <Loading />;
  if (listed.isError) shown = <Retry onRetry={() => void listed.refetch()} />;
  else if (listed.data?.length === 0) shown = <p className="muted">{t('connections.none')}</p>;
  else if (listed.data !== undefined) {
    shown = (
      <ul className="rows">
        {listed.data.map((connection) => (
          <ConnectionRow
            key={connection.keyId}
            connection={connection}
            madeBy={named(connection.madeBy)}
            canRevoke={canRevoke}
            busy={busy}
            onRevoke={setRevoking}
          />
        ))}
      </ul>
    );
  }
  return (
    <section className="stack" aria-labelledby="connections-title">
      <h2 id="connections-title">{t('connections.title')}</h2>
      <p className="muted">{t('connections.intro')}</p>
      {!canRevoke && <p className="muted">{t('connections.viewOnly')}</p>}
      {shown}
      <Said said={said} />
      {revoking !== undefined && (
        <Confirm
          text={t('connections.revokeText')}
          title={t('connections.revokeTitle', names(revoking))}
          confirmLabel={t('brakes.passkeyConfirm')}
          busy={busy}
          onCancel={close}
          onConfirm={() => void revoke(revoking)}
        >
          <p>
            {revoking.clientName}{' '}
            {revoking.redirectHost !== null && <strong className="mono">{revoking.redirectHost}</strong>}
          </p>
        </Confirm>
      )}
    </section>
  );
}
