// The shared confirm (6A2, Rule Book §1.9): before any change with a
// consequence, the person reads it in the API's own words (GET
// /v1/statements, the words the change's signed event names by version) and
// confirms. The words are read afresh each time it opens, and shown only once
// read, so a tab open across a release never confirms the old ones. Where the
// change offers a choice, each is shown with its words and
// none is picked for them (decisions 8, 11): Confirm waits for one. Words that
// can't be loaded are said, and nothing can be confirmed without them.
// A change the API states no words for (a reject: one outcome, no signed
// statement) is confirmed with the console's own words instead (6B1).
// Confirming hands back the version of the API's words shown (CO3), which
// the change sends back: the API refuses words it no longer confirms with.
// It is the browser's own modal (a <dialog> opened with showModal, CO12b,
// modern-web-guidance "dialog"): the page behind is inert, Tab stays inside,
// and Escape asks to close, which cancels unless the change is being sent.
// Focus starts on Cancel (on the pop-up itself while every control is
// disabled), and goes back to what was pressed to open it: React removes the
// pop-up rather than closing it, so the browser's own return isn't relied on.
import { queryOptions, useQuery } from '@tanstack/react-query';
import { type ReactNode, useEffect, useId, useRef, useState } from 'react';

import { api } from './api.ts';
import { t } from './text.ts';

interface Words {
  readonly choice: string;
  readonly text: string;
}

export interface Statement {
  readonly id: string;
  readonly version: number;
  readonly words: readonly Words[];
}

/** The API's words for changes (GET /v1/statements): never served from cache, read afresh on each showing. */
export const statementsQuery = (enabled: boolean) =>
  queryOptions({
    queryKey: ['statements'],
    enabled,
    queryFn: () => api.get<{ readonly statements: readonly Statement[] }>('/v1/statements'),
    staleTime: 0,
    refetchOnMount: 'always',
  });

/** The words of one change, as the API confirms changes with them now: read again on each opening. */
function useStatement(id: string | undefined) {
  return useQuery({
    ...statementsQuery(id !== undefined),
    select: ({ statements }) => statements.find((statement) => statement.id === id),
  });
}

/** Where the words come from: the API's set by its id, or the console's own for a change the API states none for (a reject). */
type WordsFrom =
  { readonly statement: string; readonly text?: never } | { readonly text: string; readonly statement?: never };

export type ConfirmProps = WordsFrom & {
  readonly title: string;
  /** What the change is, for this one thing (its supplier, amount…), above the consequence. */
  readonly children?: ReactNode;
  readonly confirmLabel: string;
  /**
   * Called with the choice confirmed (`confirm` for a change with none) and
   * the version of the API's words shown, to send back; none for the console's own.
   */
  readonly onConfirm: (choice: string, statementVersion?: number) => void;
  readonly onCancel: () => void;
  /** While the change is being sent: nothing can be pressed twice. */
  readonly busy?: boolean;
  /** False while what the change needs isn't given yet (a reject's reason): Confirm waits. */
  readonly ready?: boolean;
};

export function Confirm({
  statement,
  text,
  title,
  children,
  confirmLabel,
  onConfirm,
  onCancel,
  busy = false,
  ready = true,
}: ConfirmProps) {
  const words = useStatement(statement);
  const [chosen, setChosen] = useState<string | null>(null);
  const titleId = useId();
  const cancel = useRef<HTMLButtonElement>(null);
  const dialog = useRef<HTMLDialogElement>(null);
  // What was pressed to open it, taken once at the first render: StrictMode's second effect run would find Cancel.
  const [opener] = useState(() => document.activeElement);
  useEffect(() => {
    if (dialog.current?.open === false) dialog.current.showModal();
    cancel.current?.focus();
    return () => {
      if (opener instanceof HTMLElement && opener.isConnected) opener.focus();
    };
  }, [opener]);
  // While the change is being sent every control is disabled, and a disabled one loses focus: the pop-up holds it.
  useEffect(() => {
    if (busy && !dialog.current?.contains(document.activeElement)) dialog.current?.focus();
  }, [busy]);
  // Words only once read afresh, and none after a failed read (whatever was read before).
  const served = statement !== undefined;
  const fetching = served && words.isFetching;
  const unloaded = served && !words.isFetching && (words.isError || words.data === undefined);
  let choices: readonly Words[] = [];
  let version: number | undefined;
  if (text !== undefined) choices = [{ choice: 'confirm', text }];
  else if (!words.isFetching && !words.isError) {
    choices = words.data?.words ?? [];
    version = words.data?.version;
  }
  const single = choices.length === 1 ? choices[0] : undefined;
  const picked = single?.choice ?? chosen;
  return (
    <dialog
      ref={dialog}
      tabIndex={-1}
      className="dialog"
      aria-labelledby={titleId}
      // Escape (or the back gesture) asks to close: never closed by the browser, cancelled here unless sending. Every
      // caller removes the pop-up on onCancel, before a close the browser queues could reach onClose: one cancel.
      onCancel={(event) => {
        event.preventDefault();
        if (!busy) onCancel();
      }}
      // A browser may close it anyway on a second Escape with no click between: shown again while sending, else a cancel.
      onClose={() => {
        if (busy) dialog.current?.showModal();
        else onCancel();
      }}
    >
      <h2 id={titleId}>{title}</h2>
      {children}
      {fetching && <p role="status">{t('loading')}</p>}
      {unloaded && (
        <p className="notice" role="alert">
          {t('confirm.unloaded')}
        </p>
      )}
      {single !== undefined && <p className="statement">{single.text}</p>}
      {choices.length > 1 && (
        <fieldset className="options">
          <legend>{t('confirm.choose')}</legend>
          {choices.map(({ choice, text }) => (
            <label key={choice} className="option">
              <input
                type="radio"
                name={titleId}
                value={choice}
                checked={chosen === choice}
                onChange={() => {
                  setChosen(choice);
                }}
              />
              <span>{text}</span>
            </label>
          ))}
        </fieldset>
      )}
      <div className="actions">
        <button ref={cancel} type="button" className="secondary" disabled={busy} onClick={onCancel}>
          {t('confirm.cancel')}
        </button>
        <button
          type="button"
          className="primary"
          disabled={busy || !ready || picked === null}
          onClick={() => {
            if (picked !== null) onConfirm(picked, version);
          }}
        >
          {confirmLabel}
        </button>
      </div>
    </dialog>
  );
}
