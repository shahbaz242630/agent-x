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
  type MandateVersion,
} from '../mandates.ts';
import { useActing } from '../session.tsx';
import { type Asked, askFirst, byPasskey, changeAt } from '../step-up.ts';
import { t } from '../text.ts';
import { Said, useChange } from './change.tsx';
import { TermsTable } from './mandate-terms.tsx';

type Move = 'suspend' | 'resume' | 'revoke';

type Open =
  | { readonly kind: 'none' }
  | { readonly kind: 'accept' }
  | {
      readonly kind: 'plan';
      readonly asked: Asked;
      readonly plan: readonly Carried[];
      readonly later: number;
      readonly version?: number | undefined;
    }
  | { readonly kind: 'overLimit' }
  | { readonly kind: Move };
const NONE: Open = { kind: 'none' };

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

/** The dialog each opened action shows. */
function Opened({
  open,
  mandate,
  pending,
  busy,
  onCancel,
  onAccept,
  onMove,
  onOverLimit,
  onPlan,
}: {
  readonly open: Exclude<Open, { kind: 'none' }>;
  readonly mandate: MandateDetails;
  readonly pending: MandateVersion | null;
  readonly busy: boolean;
  readonly onCancel: () => void;
  readonly onAccept: (choice: string, version?: number) => void;
  readonly onMove: (move: Move, choice: string, version?: number) => void;
  readonly onOverLimit: (choice: string, version?: number) => void;
  readonly onPlan: (asked: Asked, version?: number) => void;
}) {
  const common = { busy, onCancel, confirmLabel: t('brakes.passkeyConfirm') };
  const shown = mandate.current?.overLimit ?? 'not-chosen';
  switch (open.kind) {
    case 'accept': {
      const words = mandate.current === null ? { text: t('mandates.accept.firstText') } : { statement: 'supersede' };
      return (
        <Confirm {...common} {...words} title={t('mandates.accept.title')} onConfirm={onAccept}>
          <TermsTable current={null} pending={pending} />
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
          <Plan plan={open.plan} later={open.later} />
        </Confirm>
      );
    case 'overLimit':
      return (
        <Confirm {...common} statement="over_limit" title={t('mandates.overLimit.title')} onConfirm={onOverLimit}>
          <p className="muted">{t('mandates.overLimit.now', { choice: t(`mandates.overLimit.${shown}`) })}</p>
        </Confirm>
      );
    case 'suspend':
      return (
        <Confirm
          {...common}
          statement="suspend"
          title={t('mandates.move.suspend.title')}
          onConfirm={(choice, version) => {
            onMove('suspend', choice, version);
          }}
        >
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
            onMove(open.kind, 'confirm');
          }}
        />
      );
  }
}

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
  const label = (key: 'accept' | 'overLimit' | Move) =>
    t(`mandates.label.${key}`, { purpose: (current ?? pending)?.purpose ?? '' });

  // The confirm takes no version ID (only the ask does): left out of the confirm's JSON by naming it undefined.
  const stepUp = (asked: Asked, version?: number) =>
    asked.stepUp(undefined, { versionId: undefined, statementVersion: version });
  const accept = (choice: string, version?: number) => {
    if (pending === null) return;
    if (current === null) {
      void run(
        () =>
          byPasskey(`${at}/accept`, label('accept'), { versionId: pending.id }, organization.id, {
            versionId: undefined,
          }),
        { after: close },
      );
      return;
    }
    void run(
      async () => {
        const asked = await askFirst(
          changeAt(
            `${at}/accept`,
            label('accept'),
            { versionId: pending.id, pendingRequests: choice },
            organization.id,
          ),
        );
        if ('done' in asked) throw new ApiError(200, 'STEP_UP_NOT_ASKED');
        const { plan, later } = carryIn(asked.answer);
        if (choice !== 'carry' || (plan.length === 0 && later === 0)) return stepUp(asked, version);
        // A carry's plan is shown before the passkey: confirming applies exactly it.
        setOpen({ kind: 'plan', asked, plan, later, version });
        return 'held';
      },
      { after: close },
    );
  };
  const plan = (asked: Asked, version?: number) =>
    void run(() => Promise.resolve(stepUp(asked, version)), { after: close });
  const move = (kind: Move, choice: string, version?: number) =>
    void run(
      () =>
        byPasskey(
          `${at}/${kind}`,
          label(kind),
          kind === 'suspend' ? { pendingRequests: choice } : {},
          organization.id,
          { statementVersion: version },
        ),
      { after: close },
    );
  const overLimit = (choice: string, version?: number) =>
    void run(
      () =>
        byPasskey(`${at}/over-limit`, label('overLimit'), { overLimit: choice }, organization.id, {
          statementVersion: version,
        }),
      { after: close },
    );
  const opener = (next: Open, words: string, primary = false) => (
    <button
      type="button"
      className={primary ? 'primary' : 'secondary'}
      disabled={busy}
      onClick={() => {
        setOpen(next);
      }}
    >
      {words}
    </button>
  );

  return (
    <section className="stack" aria-labelledby="mandate-actions">
      <h2 id="mandate-actions">{t('mandates.actions')}</h2>
      {acceptable && mandate.status === 'SUSPENDED' && <p className="muted">{t('mandates.accept.resumeFirst')}</p>}
      {acceptable && mandate.status !== 'SUSPENDED' && opener({ kind: 'accept' }, t('mandates.accept.open'), true)}
      {current !== null && !ended && opener({ kind: 'overLimit' }, t('mandates.overLimit.open'))}
      {movesOf(mandate).map((kind) => (
        <span key={kind}>{opener({ kind }, t(`mandates.move.${kind}.open`))}</span>
      ))}
      {ended && <p className="muted">{t('mandates.endedNote')}</p>}
      <Said said={said} />
      {open.kind !== 'none' && (
        <Opened
          open={open}
          mandate={mandate}
          pending={pending}
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
