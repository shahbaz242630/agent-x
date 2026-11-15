// The brakes' screens (6B2): the organisation's agents, suppliers and bank
// accounts, each with its brake. Suspending is one confirm and no passkey,
// and is done at once: the person reads what happens in the API's words
// (GET /v1/statements, `suspend`), chooses what happens to pending requests
// (none chosen for them, decisions 8 and 11) and confirms. An agent's suspend
// is the kill switch, so it never waits on a passkey. Reactivating asks for
// a passkey (the shared step-up, step-up.ts): straight there for an agent or a
// bank account, after choosing what happens to the held requests for a
// supplier (decision 9, the `reactivate` words). The buttons show by role only;
// the API checks again whatever is pressed. Look A "Statement": nothing shouts.
import { useState } from 'react';

import { atOnce, type Braked, brakeRefusal, type Kind, KINDS, REACTIVATING, useBrakeList } from '../brakes.ts';
import { Confirm } from '../confirm.tsx';
import { useActing } from '../session.tsx';
import { ask, changeAt } from '../step-up.ts';
import { t } from '../text.ts';
import { Said, useChange } from './change.tsx';
import { Loading, Retry } from './failed.tsx';

interface Opened {
  readonly kind: 'suspend' | 'reactivate';
  readonly thing: Braked;
}
type Open = { readonly kind: 'none' } | Opened;
const NONE: Open = { kind: 'none' };

function Row({
  thing,
  canSuspend,
  canReactivate,
  busy,
  onOpen,
}: {
  readonly thing: Braked;
  readonly canSuspend: boolean;
  readonly canReactivate: boolean;
  readonly busy: boolean;
  readonly onOpen: (open: Opened) => void;
}) {
  let action: Opened['kind'] | null = null;
  if (thing.ended) action = null;
  else if (thing.suspended) action = canReactivate ? 'reactivate' : null;
  else if (canSuspend) action = 'suspend';
  return (
    <li className="row">
      <span className="row-main">
        <span>
          {thing.name}
          {thing.suspended && <span className="tag warn">{t('brakes.suspended')}</span>}
          {thing.ended && <span className="tag">{t('brakes.ended')}</span>}
        </span>
        <span className="muted mono">{thing.detail}</span>
      </span>
      {action !== null && (
        <button
          type="button"
          className="secondary"
          disabled={busy}
          aria-label={t(`brakes.${action}Named`, { name: thing.name })}
          onClick={() => {
            onOpen({ kind: action, thing });
          }}
        >
          {t(`brakes.${action}`)}
        </button>
      )}
    </li>
  );
}

/** One kind's list, each with its brake. */
export function BrakeList({ kind }: { readonly kind: Kind }) {
  const { organization } = useActing();
  const listed = useBrakeList(kind, organization.id);
  const { busy, said, run } = useChange(brakeRefusal);
  const [open, setOpen] = useState<Open>(NONE);
  const { path, suspending, reactivateChooses } = KINDS[kind];
  const canSuspend = suspending.includes(organization.role);
  const canReactivate = REACTIVATING.includes(organization.role);
  const pages = listed.data?.pages ?? [];
  const shown = pages.flatMap((page) => page.listed);
  const unchecked = pages.reduce((count, page) => count + page.unchecked.length, 0);
  const close = () => {
    setOpen(NONE);
  };
  const at = (thing: Braked) => `${path}/${encodeURIComponent(thing.id)}`;

  const suspend = (thing: Braked, pendingRequests: string, statementVersion?: number) =>
    run(
      () =>
        atOnce(`${at(thing)}/suspend`, { organization: organization.id, body: { pendingRequests, statementVersion } }),
      { done: t('brakes.suspendedDone', { name: thing.name }), after: close },
    );
  const reactivateChange = (thing: Braked, body: Readonly<Record<string, unknown>>) =>
    changeAt(`${at(thing)}/reactivate`, t('brakes.reactivateLabel', { name: thing.name }), body, organization.id);
  const done = (thing: Braked) => ({ done: t('brakes.reactivatedDone', { name: thing.name }), after: close });
  // An agent or a bank account: nothing to choose, so straight to the passkey.
  const reactivate = (thing: Braked) => run(() => ask(reactivateChange(thing, {})), done(thing));
  // A supplier: the choice is asked with, and the version of the words shown is sent with the confirm (CO3).
  const reactivateChoosing = (thing: Braked, pendingRequests: string, statementVersion?: number) =>
    run(() => ask(reactivateChange(thing, { pendingRequests }), { statementVersion }), done(thing));

  return (
    <section className="stack">
      <h1>{t(`brakes.${kind}.title`)}</h1>
      <p className="muted">{t(`brakes.${kind}.intro`)}</p>
      {!canSuspend && <p className="muted">{t(`brakes.${kind}.viewOnly`)}</p>}
      {listed.isPending && <Loading />}
      {listed.isError && <Retry onRetry={() => void listed.refetch()} />}
      {listed.isSuccess && shown.length === 0 && <p className="muted">{t(`brakes.${kind}.none`)}</p>}
      {shown.length > 0 && (
        <ul className="rows">
          {shown.map((thing) => (
            <Row
              key={thing.id}
              thing={thing}
              canSuspend={canSuspend}
              canReactivate={canReactivate}
              busy={busy}
              onOpen={(next) => {
                if (next.kind === 'reactivate' && !reactivateChooses) void reactivate(next.thing);
                else setOpen(next);
              }}
            />
          ))}
        </ul>
      )}
      {unchecked > 0 && (
        <p className="notice" role="status">
          {t('brakes.unchecked', { count: String(unchecked) })}
        </p>
      )}
      {listed.hasNextPage && (
        <button
          type="button"
          className="secondary"
          disabled={listed.isFetchingNextPage}
          onClick={() => void listed.fetchNextPage()}
        >
          {t('approvals.more')}
        </button>
      )}
      <Said said={said} />
      {open.kind !== 'none' && (
        <Confirm
          statement={open.kind}
          title={t(`brakes.${open.kind}Title`, { name: open.thing.name })}
          confirmLabel={t(open.kind === 'suspend' ? 'brakes.suspendConfirm' : 'brakes.passkeyConfirm')}
          busy={busy}
          onCancel={close}
          onConfirm={(choice, version) => {
            void (open.kind === 'suspend'
              ? suspend(open.thing, choice, version)
              : reactivateChoosing(open.thing, choice, version));
          }}
        >
          <p className="amount">{open.thing.name}</p>
        </Confirm>
      )}
    </section>
  );
}
