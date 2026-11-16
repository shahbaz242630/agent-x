// The integrity hold (6D4a, ADR-012 §2, SEC-DB-10's clearing): `/more/integrity-hold`,
// an admin's alone, as the API lets only an admin read it. Once Agent X finds
// any record of the organisation tampered with, it holds the organisation: no
// payment goes to the bank and agents can't ask for new ones. The page says
// since when and how it showed; the admin records what the investigation
// concluded (a conclusion, none picked, and the incident's reference, a
// ticket's ID), each confirmed; and then may clear it, by passkey, with the
// investigation it rests on, after reading in plain words what clearing
// means. The clear is pinned to the hold as shown: the dialog keeps it as it
// was when opened, reads the hold again, and can't be confirmed if that
// re-read finds it moved on (cleared and set again, say); the API binds the
// rest, its step-up tied to exactly that held state and investigation. The
// banner across the console (HoldBanner, in the shell) says a hold is on,
// for an admin: no one else can read it.
import { Link } from '@tanstack/react-router';
import { useRef, useState } from 'react';

import { useMembers } from '../agents.ts';
import { api, ApiError, isIntegrityFailed } from '../api.ts';
import { Confirm } from '../confirm.tsx';
import {
  type Conclusion,
  CONCLUSIONS,
  foundOnText,
  type Hold,
  HOLD_PATH,
  HOLDING,
  holdRefusal,
  holdState,
  type Investigation,
  investigationsOf,
  isReference,
  keepInvestigation,
  reasonText,
  REFERENCE_MOST,
  useHold,
} from '../hold.ts';
import { timeText } from '../requests.ts';
import { useActing } from '../session.tsx';
import { decides } from '../sources.ts';
import { byPasskey } from '../step-up.ts';
import { t } from '../text.ts';
import { memberText } from './agent.tsx';
import { Said, useChange } from './change.tsx';
import { Choices } from './choices.tsx';
import { Loading, Retry } from './failed.tsx';
import { LineField } from './line-field.tsx';

/** Across the console, for an admin, while the organisation is held. */
export function HoldBanner() {
  const { organization } = useActing();
  const hold = useHold(organization.id, HOLDING.includes(organization.role));
  if (hold.data?.status !== 'HELD') return null;
  return (
    <p className="banner" role="alert">
      {t('hold.banner')} <Link to="/more/integrity-hold">{t('hold.bannerLink')}</Link>
    </p>
  );
}

/** Recording what the investigation concluded: a conclusion, none picked, and the incident's reference, confirmed. */
function Investigate({ hold, onRecorded }: { readonly hold: Hold; readonly onRecorded: () => void }) {
  const { organization, session } = useActing();
  const { busy, said, run } = useChange(holdRefusal);
  const [conclusion, setConclusion] = useState<Conclusion | null>(null);
  const [reference, setReference] = useState('');
  const [checked, setChecked] = useState(false);
  const [open, setOpen] = useState(false);
  // The record's key while it has no answer: Try again records the same one, never a second.
  const recordKey = useRef<string | null>(null);
  const typed = reference.trim();
  const referenceBroken = isReference(typed) ? undefined : t('hold.investigate.referenceBroken');
  const close = () => {
    setOpen(false);
  };
  const record = (chosen: Conclusion) =>
    run(
      async () => {
        const idempotencyKey = recordKey.current ?? crypto.randomUUID();
        recordKey.current = idempotencyKey;
        try {
          const { investigation } = await api.post<{ readonly investigation: Investigation }>(
            `${HOLD_PATH}/investigations`,
            { organization: organization.id, idempotencyKey, body: { conclusion: chosen, reference: typed } },
          );
          recordKey.current = null;
          keepInvestigation(session.userId, organization.id, investigation);
          setConclusion(null);
          setReference('');
          setChecked(false);
          onRecorded();
        } catch (error) {
          if (decides(error)) recordKey.current = null;
          throw error;
        }
      },
      { done: t('hold.investigate.done'), after: close },
    );
  return (
    <section className="stack" aria-labelledby="investigate-title">
      <h2 id="investigate-title">{t('hold.investigate.title')}</h2>
      <p className="muted">{t('hold.investigate.body')}</p>
      <Choices
        legend={t('hold.investigate.conclusion')}
        options={CONCLUSIONS.map((each) => [each, t(`hold.conclusion.${each}`)] as const)}
        chosen={conclusion}
        onChoose={setConclusion}
        broken={checked && conclusion === null ? t('hold.investigate.chooseOne') : undefined}
        disabled={busy}
      />
      <LineField
        label={t('hold.investigate.reference')}
        hint={t('hold.investigate.referenceHint')}
        most={REFERENCE_MOST}
        value={reference}
        onChange={setReference}
        broken={checked ? referenceBroken : undefined}
        autoComplete="off"
        spellCheck={false}
        disabled={busy}
      />
      <button
        type="button"
        className="secondary"
        disabled={busy}
        onClick={() => {
          setChecked(true);
          if (conclusion !== null && referenceBroken === undefined) setOpen(true);
        }}
      >
        {t('hold.investigate.button')}
      </button>
      <Said said={said} />
      {open && conclusion !== null && (
        <Confirm
          text={t('hold.investigate.statement', {
            conclusion: t(`hold.conclusion.${conclusion}`),
            reference: typed,
            version: String(hold.version),
          })}
          title={t('hold.investigate.confirmTitle')}
          confirmLabel={t('hold.investigate.confirm')}
          busy={busy}
          onCancel={close}
          onConfirm={() => void record(conclusion)}
        />
      )}
    </section>
  );
}

/** The investigations of this hold recorded in this window, newest first. */
function Investigations({ recorded }: { readonly recorded: readonly Investigation[] }) {
  const { organization, session } = useActing();
  const members = useMembers(organization.id);
  const me = session.userId.toLowerCase();
  const who = (userId: string) =>
    memberText(
      members.data?.find((member) => member.userId.toLowerCase() === userId.toLowerCase()),
      me,
    );
  return (
    <section className="stack" aria-labelledby="investigations-title">
      <h2 id="investigations-title">{t('hold.investigations.title')}</h2>
      <p className="muted">{t('hold.investigations.body')}</p>
      {recorded.length === 0 ? (
        <p className="muted">{t('hold.investigations.none')}</p>
      ) : (
        <ul className="rows">
          {recorded.map((investigation) => (
            <li key={investigation.id} className="row">
              <span className="row-main">
                <span>{t(`hold.conclusion.${investigation.conclusion}`)}</span>
                <span className="muted">
                  <span className="mono">{investigation.reference}</span> · {who(investigation.recordedBy)} ·{' '}
                  {timeText(investigation.recordedAt)}
                </span>
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

/** What the clearing dialog was opened on: the hold as shown, and the investigation chosen. */
interface Pinned {
  readonly hold: Hold;
  readonly investigation: Investigation;
}

/** Clearing the hold: an investigation chosen, none picked, what it means read, then a passkey. */
function Clear({
  hold,
  recorded,
  reread,
}: {
  readonly hold: Hold;
  readonly recorded: readonly Investigation[];
  /** Reads the hold again, for the dialog to check it against what it was opened on. */
  readonly reread: () => Promise<Hold | undefined>;
}) {
  const { organization } = useActing();
  const { busy, said, run } = useChange(holdRefusal);
  const [chosen, setChosen] = useState<string | null>(null);
  const [pinned, setPinned] = useState<Pinned | null>(null);
  // The re-read made as the dialog opened: none yet, the hold it found, or none found (a failed read).
  const [again, setAgain] = useState<'reading' | Hold | null>('reading');
  const picked = recorded.find((investigation) => investigation.id === chosen);
  const close = () => {
    setPinned(null);
  };
  const openOn = (investigation: Investigation) => {
    setPinned({ hold, investigation });
    setAgain('reading');
    void reread().then(
      (read) => {
        setAgain(read ?? null);
      },
      () => {
        setAgain(null);
      },
    );
  };
  const clear = (investigation: Investigation) =>
    run(
      () =>
        byPasskey(
          `${HOLD_PATH}/clear`,
          t('hold.clear.label', { reference: investigation.reference }),
          { investigationId: investigation.id },
          organization.id,
        ),
      { after: close },
    );
  const moved =
    pinned !== null && again !== 'reading' && (again === null || holdState(again) !== holdState(pinned.hold));
  return (
    <section className="stack" aria-labelledby="clear-title">
      <h2 id="clear-title">{t('hold.clear.title')}</h2>
      <p className="muted">{t('hold.clear.body')}</p>
      {recorded.length === 0 ? (
        <p className="muted">{t('hold.clear.needsInvestigation')}</p>
      ) : (
        <>
          <Choices
            legend={t('hold.clear.which')}
            options={recorded.map(
              (investigation) =>
                [
                  investigation.id,
                  t('hold.clear.option', {
                    conclusion: t(`hold.conclusion.${investigation.conclusion}`),
                    reference: investigation.reference,
                    time: timeText(investigation.recordedAt),
                  }),
                ] as const,
            )}
            chosen={chosen}
            onChoose={setChosen}
            disabled={busy}
          />
          <button
            type="button"
            className="secondary"
            disabled={busy || picked === undefined}
            onClick={() => {
              if (picked !== undefined) openOn(picked);
            }}
          >
            {t('hold.clear.button')}
          </button>
        </>
      )}
      <Said said={said} />
      {pinned !== null && (
        <Confirm
          text={t('hold.clear.statement')}
          title={t('hold.clear.confirmTitle')}
          confirmLabel={t('brakes.passkeyConfirm')}
          busy={busy}
          ready={again !== 'reading' && !moved}
          onCancel={close}
          onConfirm={() => void clear(pinned.investigation)}
        >
          <dl className="facts">
            <dt>{t('hold.since')}</dt>
            <dd>{timeText(pinned.hold.since)}</dd>
            <dt>{t('hold.reason')}</dt>
            <dd>{reasonText(pinned.hold.reason)}</dd>
            <dt>{t('hold.investigation')}</dt>
            <dd>
              {t(`hold.conclusion.${pinned.investigation.conclusion}`)}{' '}
              <span className="mono">{pinned.investigation.reference}</span>
            </dd>
          </dl>
          {again === 'reading' && <p role="status">{t('hold.clear.rereading')}</p>}
          {moved && (
            <p className="notice" role="alert">
              {t(again === null ? 'hold.clear.unread' : 'hold.clear.moved')}
            </p>
          )}
        </Confirm>
      )}
    </section>
  );
}

function Held({ hold, reread }: { readonly hold: Hold; readonly reread: () => Promise<Hold | undefined> }) {
  const { organization, session } = useActing();
  // Read again from this tab's storage after each record (hold.ts).
  const [, setRecords] = useState(0);
  const recorded = investigationsOf(session.userId, organization.id, hold.version);
  return (
    <>
      <span className="kicker">{t('hold.status.HELD')}</span>
      <h1>{t('hold.title')}</h1>
      <p>{t('hold.heldBody')}</p>
      <dl className="facts">
        <dt>{t('hold.since')}</dt>
        <dd>{timeText(hold.since)}</dd>
        <dt>{t('hold.reason')}</dt>
        <dd>{reasonText(hold.reason)}</dd>
        <dt>{t('hold.foundOn')}</dt>
        <dd>{foundOnText(hold.foundOn)}</dd>
        <dt>{t('hold.version')}</dt>
        <dd>{String(hold.version)}</dd>
      </dl>
      <Investigate
        hold={hold}
        onRecorded={() => {
          setRecords((count) => count + 1);
        }}
      />
      <Investigations recorded={recorded} />
      <Clear hold={hold} recorded={recorded} reread={reread} />
    </>
  );
}

/** Why the hold can't be shown: the admin's role gone, its records failing their check, or a failure to retry. */
function Unread({ error, onRetry }: { readonly error: unknown; readonly onRetry: () => void }) {
  if (isIntegrityFailed(error)) return <p className="notice">{t('hold.integrity')}</p>;
  if (error instanceof ApiError && error.status === 403) return <p className="notice">{t('hold.viewOnly')}</p>;
  return <Retry onRetry={onRetry} />;
}

export function HoldPage() {
  const { organization } = useActing();
  const admin = HOLDING.includes(organization.role);
  const shown = useHold(organization.id, admin);
  // A failed re-read keeps the data read before: none here, so a clear is never confirmed on it.
  const reread = async () => {
    const read = await shown.refetch();
    return read.isError ? undefined : read.data;
  };
  let body;
  if (!admin) body = <p className="muted">{t('hold.viewOnly')}</p>;
  else if (shown.data === undefined && shown.isError)
    body = <Unread error={shown.error} onRetry={() => void shown.refetch()} />;
  else if (shown.data === undefined) body = <Loading />;
  else if (shown.data.status === 'HELD') body = <Held hold={shown.data} reread={reread} />;
  else {
    body = (
      <>
        <span className="kicker">{t('hold.status.CLEAR')}</span>
        <h1>{t('hold.title')}</h1>
        <p>{t('hold.clearBody', { time: timeText(shown.data.since) })}</p>
      </>
    );
  }
  return (
    <section className="stack request">
      <Link to="/more" className="back">
        {t('hold.back')}
      </Link>
      {(!admin || shown.data === undefined) && <h1>{t('hold.title')}</h1>}
      {body}
    </section>
  );
}
