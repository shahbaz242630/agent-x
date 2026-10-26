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
import { useQuery } from '@tanstack/react-query';
import { type ReactNode, useEffect, useId, useRef, useState } from 'react';

import { api } from './api.ts';
import { t } from './text.ts';

interface Words {
  readonly choice: string;
  readonly text: string;
}

interface Statement {
  readonly id: string;
  readonly version: number;
  readonly words: readonly Words[];
}

/** The words of one change, as the API confirms changes with them now: read again on each opening. */
function useStatement(id: string | undefined) {
  return useQuery({
    queryKey: ['statements'],
    enabled: id !== undefined,
    queryFn: () => api.get<{ readonly statements: readonly Statement[] }>('/v1/statements'),
    staleTime: 0,
    refetchOnMount: 'always',
    select: ({ statements }) => statements.find((statement) => statement.id === id),
  });
}

export interface ConfirmProps {
  /** The statement set, as GET /v1/statements names it; or `text` instead, for a change the API states no words for. */
  readonly statement?: string;
  /** The console's own words for a change with one outcome and no statement (a reject). */
  readonly text?: string;
  readonly title: string;
  /** What the change is, for this one thing (its supplier, amount…), above the consequence. */
  readonly children?: ReactNode;
  readonly confirmLabel: string;
  /** Called with the choice confirmed (`confirm` for a change with none). */
  readonly onConfirm: (choice: string) => void;
  readonly onCancel: () => void;
  /** While the change is being sent: nothing can be pressed twice. */
  readonly busy?: boolean;
  /** False while what the change needs isn't given yet (a reject's reason): Confirm waits. */
  readonly ready?: boolean;
}

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
  useEffect(() => {
    cancel.current?.focus();
  }, []);
  // Words only once read afresh, and none after a failed read (whatever was read before).
  const fetching = statement !== undefined && words.isFetching;
  const unloaded = statement !== undefined && !words.isFetching && (words.isError || words.data === undefined);
  const read = !words.isFetching && !words.isError;
  const served = read ? (words.data?.words ?? []) : [];
  const choices = text === undefined ? served : [{ choice: 'confirm', text }];
  const single = choices.length === 1 ? choices[0] : undefined;
  const picked = single?.choice ?? chosen;
  return (
    <div className="veil">
      <section
        className="dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        onKeyDown={(event) => {
          if (event.key === 'Escape' && !busy) onCancel();
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
              if (picked !== null) onConfirm(picked);
            }}
          >
            {confirmLabel}
          </button>
        </div>
      </section>
    </div>
  );
}
