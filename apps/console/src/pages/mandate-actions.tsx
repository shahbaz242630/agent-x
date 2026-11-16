// What an admin can do with a mandate (6D3a, ADR-003 §8, ADR-014 §8), each
// asked, then confirmed with a passkey (the shared step-up, step-up.ts):
// - Accept the waiting draft: its terms shown in full first. A first version
//   chooses nothing; a new one chooses what happens to the pending requests of
//   the version in force, in the API's `supersede` words with none picked. A
//   carry's ask answers what it will do to each pending request, shown before
//   the passkey; confirming applies exactly that.
// - Suspend (the brake), choosing in the API's `suspend` words, none picked,
//   what happens to the pending requests; resume; revoke, which can't be undone.
// - The over-limit choice on the version in force, in the API's `over_limit`
//   words, none picked.
// The client pins what it shows: each dialog keeps the mandate as it was when
// opened, shows and sends that alone, and if a re-read finds it changed
// meanwhile (a draft replaced or accepted, its status or choice moved) it says
// so and can't be confirmed. The server binds the rest: an acceptance by the
// `versionId` it names; a suspend, resume, revoke or over-limit choice by the
// API's challenge, bound at the ask to the mandate's latest signed event
// (mandate-moves.ts).
// Only an admin is shown them; the API checks again whatever is pressed.
import { useState } from 'react';

import { ApiError } from '../api.ts';
import { Confirm } from '../confirm.tsx';
import {
  type Carried,
  carryIn,
  isEnded,
  MANAGING,
  type MandateDetails,
  mandateAt,
  mandateRefusal,
} from '../mandates.ts';
import { useActing } from '../session.tsx';
import { type Asked, askFirst, byPasskey, changeAt } from '../step-up.ts';
import { t } from '../text.ts';
import { Said, useChange } from './change.tsx';
import { TermsTable } from './mandate-terms.tsx';

type Move = 'suspend' | 'resume' | 'revoke';

/** An action's dialog, with the mandate as it was shown when the dialog opened (`seen`). */
type Opened =
  | { readonly kind: 'accept'; readonly seen: MandateDetails }
  | {
      readonly kind: 'plan';
      readonly seen: MandateDetails;
      readonly asked: Asked;
      readonly plan: readonly Carried[];
      readonly later: number;
      readonly version?: number | undefined;
    }
  | { readonly kind: 'overLimit'; readonly seen: MandateDetails }
  | { readonly kind: Move; readonly seen: MandateDetails };
type Open = { readonly kind: 'none' } | Opened;
const NONE: Open = { kind: 'none' };

/** What a dialog's words depend on: its status, its version in force and choice, and its waiting draft. */
const stateOf = (mandate: MandateDetails): string =>
  [mandate.status, mandate.current?.id, mandate.current?.overLimit, mandate.pending?.id].join('/');

/** Whether the mandate read now is no longer the one a dialog showed. */
const changedSince = (seen: MandateDetails, now: MandateDetails): boolean => stateOf(seen) !== stateOf(now);

/** The moves each status allows: suspend one in force, resume one suspended, revoke any not ended. */
function movesOf(mandate: MandateDetails): readonly Move[] {
  if (isEnded(mandate.status)) return [];
  if (mandate.status === 'ACTIVE') return ['suspend', 'revoke'];
  if (mandate.status === 'SUSPENDED') return ['resume', 'revoke'];
  return ['revoke'];
}

/** What a carry will do to each pending request, as its ask answered: shown before the passkey. */
function Plan({ plan, later }: { readonly plan: readonly Carried[]; readonly later: number }) {
  return (
    <>
      {plan.length === 0 ? (
        <p>{t('mandates.accept.planNone')}</p>
      ) : (
        <ul className="plain stack">
          {plan.map((carried) => (
            <li key={carried.id}>
              <span className="mono">{carried.id}</span>{' '}
              <span className={carried.outcome === 'cancel' ? 'tag warn' : 'tag'}>
                {t(`mandates.accept.outcome.${carried.outcome}`)}
              </span>
              {carried.reasons.map((reason) => (
                <span key={reason.code} className="fine reason">
                  {reason.message}
                </span>
              ))}
            </li>
          ))}
        </ul>
      )}
      {later > 0 && <p className="muted">{t('mandates.accept.planLater', { count: String(later) })}</p>}
    </>
  );
}

/** Said in a dialog whose mandate changed since it opened: it can't be confirmed. */
function Changed({ changed }: { readonly changed: boolean }) {
  return changed ? (
    <p className="notice" role="alert">
      {t('mandates.changedSince')}
    </p>
  ) : null;
}

/** The dialog each opened action shows, from the mandate as it was when opened. */
function Dialog({
  open,
  changed,
  busy,
  onCancel,
  onAccept,
  onMove,
  onOverLimit,
  onPlan,
}: {
  readonly open: Opened;
  readonly changed: boolean;
  readonly busy: boolean;
  readonly onCancel: () => void;
  readonly onAccept: (seen: MandateDetails, choice: string, version?: number) => void;
  readonly onMove: (seen: MandateDetails, move: Move, choice: string, version?: number) => void;
  readonly onOverLimit: (seen: MandateDetails, choice: string, version?: number) => void;
  readonly onPlan: (asked: Asked, version?: number) => void;
}) {
  const { seen } = open;
  const common = { busy, onCancel, ready: !changed, confirmLabel: t('brakes.passkeyConfirm') };
  const notice = <Changed changed={changed} />;
  switch (open.kind) {
    case 'accept': {
      const words = seen.current === null ? { text: t('mandates.accept.firstText') } : { statement: 'supersede' };
      return (
        <Confirm
          {...common}
          {...words}
          title={t('mandates.accept.title')}
          onConfirm={(choice, version) => {
            onAccept(seen, choice, version);
          }}
        >
          {notice}
          <TermsTable current={null} pending={seen.pending} />
        </Confirm>
      );
    }
    case 'plan':
      return (
        <Confirm
          {...common}
          text={t('mandates.accept.planText')}
          title={t('mandates.accept.planTitle')}
          onConfirm={() => {
            onPlan(open.asked, open.version);
          }}
        >
          {notice}
          <Plan plan={open.plan} later={open.later} />
        </Confirm>
      );
    case 'overLimit':
      return (
        <Confirm
          {...common}
          statement="over_limit"
          title={t('mandates.overLimit.title')}
          onConfirm={(choice, version) => {
            onOverLimit(seen, choice, version);
          }}
        >
          {notice}
          <p className="muted">
            {t('mandates.overLimit.now', {
              choice: t(`mandates.overLimit.${seen.current?.overLimit ?? 'not-chosen'}`),
            })}
          </p>
        </Confirm>
      );
    case 'suspend':
      return (
        <Confirm
          {...common}
          statement="suspend"
          title={t('mandates.move.suspend.title')}
          onConfirm={(choice, version) => {
            onMove(seen, 'suspend', choice, version);
          }}
        >
          {notice}
          <p>{t('mandates.move.suspend.what')}</p>
        </Confirm>
      );
    case 'resume':
    case 'revoke':
      return (
        <Confirm
          {...common}
          text={t(`mandates.move.${open.kind}.text`)}
          title={t(`mandates.move.${open.kind}.title`)}
          onConfirm={() => {
            onMove(seen, open.kind, 'confirm');
          }}
        >
          {notice}
        </Confirm>
      );
  }
}

/** A change's label, naming the mandate by its purpose as shown. */
const labelOf = (seen: MandateDetails, key: 'accept' | 'overLimit' | Move) =>
  t(`mandates.label.${key}`, { purpose: (seen.current ?? seen.pending)?.purpose ?? '' });

/** The mandate's actions for an admin: accept the waiting draft, the over-limit choice, and its moves. */
export function MandateActions({ mandate }: { readonly mandate: MandateDetails }) {
  const { organization } = useActing();
  const { busy, said, run } = useChange(mandateRefusal);
  const [open, setOpen] = useState<Open>(NONE);
  if (!MANAGING.includes(organization.role)) return <p className="muted">{t('mandates.viewOnly')}</p>;
  const at = mandateAt(mandate.id);
  const { pending, current } = mandate;
  const close = () => {
    setOpen(NONE);
  };
  const ended = isEnded(mandate.status);
  const acceptable = pending !== null && !ended;

  // The confirm takes no version ID (only the ask does): left out of the confirm's JSON by naming it undefined.
  const stepUp = (asked: Asked, version?: number) =>
    asked.stepUp(undefined, { versionId: undefined, statementVersion: version });
  // Only the draft shown is ever asked for: the API then binds the passkey to its terms.
  const accept = (seen: MandateDetails, choice: string, version?: number) => {
    const shown = seen.pending;
    if (shown === null) return;
    const label = labelOf(seen, 'accept');
    if (seen.current === null) {
      void run(
        () => byPasskey(`${at}/accept`, label, { versionId: shown.id }, organization.id, { versionId: undefined }),
        { after: close },
      );
      return;
    }
    void run(
      async () => {
        const asked = await askFirst(
          changeAt(`${at}/accept`, label, { versionId: shown.id, pendingRequests: choice }, organization.id),
        );
        if ('done' in asked) throw new ApiError(200, 'STEP_UP_NOT_ASKED');
        const { plan, later } = carryIn(asked.answer);
        if (choice !== 'carry' || (plan.length === 0 && later === 0)) return stepUp(asked, version);
        // A carry's plan is shown before the passkey: confirming applies exactly it.
        setOpen({ kind: 'plan', seen, asked, plan, later, version });
        return 'held';
      },
      { after: close },
    );
  };
  const plan = (asked: Asked, version?: number) =>
    void run(() => Promise.resolve(stepUp(asked, version)), { after: close });
  const move = (seen: MandateDetails, kind: Move, choice: string, version?: number) =>
    void run(
      () =>
        byPasskey(
          `${at}/${kind}`,
          labelOf(seen, kind),
          kind === 'suspend' ? { pendingRequests: choice } : {},
          organization.id,
          { statementVersion: version },
        ),
      { after: close },
    );
  const overLimit = (seen: MandateDetails, choice: string, version?: number) =>
    void run(
      () =>
        byPasskey(`${at}/over-limit`, labelOf(seen, 'overLimit'), { overLimit: choice }, organization.id, {
          statementVersion: version,
        }),
      { after: close },
    );
  const opener = (kind: Opened['kind'] & ('accept' | 'overLimit' | Move), words: string, primary = false) => (
    <button
      type="button"
      className={primary ? 'primary' : 'secondary'}
      disabled={busy}
      onClick={() => {
        setOpen({ kind, seen: mandate });
      }}
    >
      {words}
    </button>
  );

  return (
    <section className="stack" aria-labelledby="mandate-actions">
      <h2 id="mandate-actions">{t('mandates.actions')}</h2>
      {acceptable && mandate.status === 'SUSPENDED' && <p className="muted">{t('mandates.accept.resumeFirst')}</p>}
      {acceptable && mandate.status !== 'SUSPENDED' && opener('accept', t('mandates.accept.open'), true)}
      {current !== null && !ended && opener('overLimit', t('mandates.overLimit.open'))}
      {movesOf(mandate).map((kind) => (
        <span key={kind}>{opener(kind, t(`mandates.move.${kind}.open`))}</span>
      ))}
      {ended && <p className="muted">{t('mandates.endedNote')}</p>}
      <Said said={said} />
      {open.kind !== 'none' && (
        <Dialog
          open={open}
          changed={changedSince(open.seen, mandate)}
          busy={busy}
          onCancel={close}
          onAccept={accept}
          onMove={move}
          onOverLimit={overLimit}
          onPlan={plan}
        />
      )}
    </section>
  );
}
