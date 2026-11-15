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
import { useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';

import { isRefusal, isSignedOut } from '../api.ts';
import { atOnce, type Braked, brakeRefusal, type Kind, KINDS, REACTIVATING, useBrakeList } from '../brakes.ts';
import { Confirm } from '../confirm.tsx';
import { endSession, useActing } from '../session.tsx';
import { ask } from '../step-up.ts';
import { t } from '../text.ts';
import { Loading, Retry } from './failed.tsx';

/**
 * Sends a change and says how it went: left to sign in again, or held open
 * for the person to look at, nothing more; done, its words; refused or
 * failed, in plain words (`refusal`: a brake's, or another screen's own).
 * Everything shown reads again after a decision either way (a refusal says
 * the thing moved on); a 401 goes to sign-in.
 */
export function useChange(refusal: (error: unknown) => string = brakeRefusal) {
  const queries = useQueryClient();
  const [busy, setBusy] = useState(false);
  const [said, setSaid] = useState<string | null>(null);
  const run = async (send: () => Promise<unknown>, done: string, after: () => void) => {
    setBusy(true);
    setSaid(null);
    try {
      const sent = await send();
      if (sent === 'stepping' || sent === 'held') return;
      after();
      setSaid(done);
      await queries.invalidateQueries();
    } catch (error) {
      if (isSignedOut(error)) {
        endSession(queries);
        return;
      }
      after();
      setSaid(refusal(error));
      if (isRefusal(error)) await queries.invalidateQueries();
    } finally {
      setBusy(false);
    }
  };
  return { busy, said, run };
}

/** What a page says after a change: done, refused or failed. */
export function Said({ said }: { readonly said: string | null }) {
  return said === null ? null : (
    <p className="notice" role="status">
      {said}
    </p>
  );
}

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
  const { busy, said, run } = useChange();
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
      t('brakes.suspendedDone', { name: thing.name }),
      close,
    );
  const reactivateChange = (thing: Braked, body: Readonly<Record<string, unknown>>) => ({
    label: t('brakes.reactivateLabel', { name: thing.name }),
    askPath: `${at(thing)}/reactivate`,
    confirmPath: `${at(thing)}/reactivate/confirm`,
    body,
    organization: organization.id,
  });
  const done = (thing: Braked) => t('brakes.reactivatedDone', { name: thing.name });
  // An agent or a bank account: nothing to choose, so straight to the passkey.
  const reactivate = (thing: Braked) => run(() => ask(reactivateChange(thing, {})), done(thing), close);
  // A supplier: the choice is asked with, and the version of the words shown is sent with the confirm (CO3).
  const reactivateChoosing = (thing: Braked, pendingRequests: string, statementVersion?: number) =>
    run(() => ask(reactivateChange(thing, { pendingRequests }), { statementVersion }), done(thing), close);

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
