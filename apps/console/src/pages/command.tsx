// The command bar (CO11, borrowed from the Command Deck direction): Ctrl+K
// (⌘K on a Mac), or the search button in the top bar, opens a list of every
// place the person may go, narrowed as they type; arrows move, Enter goes.
// It only navigates, through the router, so whatever guards leaving a page
// (a new key not yet saved) still asks first. It is the browser's own modal
// (<dialog> with showModal, as the shared confirm): Escape closes it.
import { useNavigate } from '@tanstack/react-router';
import { type KeyboardEvent, useEffect, useId, useMemo, useRef, useState } from 'react';

import { useActing } from '../session.tsx';
import { t } from '../text.ts';
import { Icon } from './icons.tsx';
import { type Place, placesFor } from './places.ts';

interface Found {
  readonly place: Place;
  readonly group: string;
  readonly name: string;
}

/** Ctrl+K or ⌘K, wherever focus is: the one shortcut the console takes. */
const isOpenKey = (event: globalThis.KeyboardEvent): boolean =>
  (event.ctrlKey || event.metaKey) && !event.altKey && !event.shiftKey && event.key.toLowerCase() === 'k';

function useFound(query: string): readonly Found[] {
  const { organization } = useActing();
  const all = useMemo(
    () =>
      placesFor(organization.role).flatMap((group) =>
        group.places.map((place) => ({ place, group: t(group.label), name: t(place.label) })),
      ),
    [organization.role],
  );
  const words = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
  return all.filter(({ name, group }) => {
    const text = `${name} ${group}`.toLowerCase();
    return words.every((word) => text.includes(word));
  });
}

function Palette({ onClose }: { readonly onClose: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const navigate = useNavigate();
  const [query, setQuery] = useState('');
  const [at, setAt] = useState(0);
  const found = useFound(query);
  const id = useId();
  const chosen = Math.min(at, Math.max(found.length - 1, 0));

  useEffect(() => {
    const opened = dialog.current;
    if (opened?.open === false) opened.showModal();
    return () => {
      opened?.close();
    };
  }, []);

  const go = (place: Place) => {
    onClose();
    void navigate({ to: place.to });
  };

  const onKey = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      if (found.length === 0) return;
      const step = event.key === 'ArrowDown' ? 1 : -1;
      setAt((chosen + step + found.length) % found.length);
    } else if (event.key === 'Enter') {
      event.preventDefault();
      const place = found[chosen]?.place;
      if (place !== undefined) go(place);
    }
  };

  return (
    <dialog
      ref={dialog}
      className="dialog palette"
      aria-label={t('command.title')}
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
      onClick={(event) => {
        // A click on the backdrop lands on the dialog itself: it closes, as Escape does.
        if (event.target === dialog.current) onClose();
      }}
    >
      <div className="palette-search">
        <Icon name="search" />
        <input
          type="text"
          role="combobox"
          aria-expanded="true"
          aria-controls={`${id}-list`}
          aria-activedescendant={found.length > 0 ? `${id}-${String(chosen)}` : undefined}
          aria-label={t('command.search')}
          placeholder={t('command.placeholder')}
          autoComplete="off"
          spellCheck={false}
          // The person asked for it by a key or a click: typing goes straight in.
          autoFocus
          value={query}
          onChange={(event) => {
            setQuery(event.target.value);
            setAt(0);
          }}
          onKeyDown={onKey}
        />
        <kbd>Esc</kbd>
      </div>
      <ul id={`${id}-list`} role="listbox" aria-label={t('command.places')} className="palette-list">
        {found.map((item, index) => (
          <li
            key={item.place.to}
            id={`${id}-${String(index)}`}
            role="option"
            aria-selected={index === chosen}
            className={index === chosen ? 'on' : undefined}
            onMouseMove={() => {
              setAt(index);
            }}
            onClick={() => {
              go(item.place);
            }}
          >
            <Icon name={item.place.icon} />
            <span>{item.name}</span>
            <span className="muted">{item.group}</span>
          </li>
        ))}
      </ul>
      {found.length === 0 && <p className="muted palette-none">{t('command.none')}</p>}
    </dialog>
  );
}

/** The top bar's search button, and Ctrl+K anywhere in the signed-in console. */
export function CommandBar() {
  const [open, setOpen] = useState(false);
  const opener = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    const onKey = (event: globalThis.KeyboardEvent) => {
      if (!isOpenKey(event)) return;
      event.preventDefault();
      setOpen((was) => !was);
    };
    window.addEventListener('keydown', onKey);
    return () => {
      window.removeEventListener('keydown', onKey);
    };
  }, []);

  const close = () => {
    setOpen(false);
    opener.current?.focus();
  };

  return (
    <>
      <button
        ref={opener}
        type="button"
        className="search"
        aria-haspopup="dialog"
        aria-keyshortcuts="Control+K Meta+K"
        onClick={() => {
          setOpen(true);
        }}
      >
        <Icon name="search" size={15} />
        <span>{t('command.open')}</span>
        <kbd>Ctrl K</kbd>
      </button>
      {open && <Palette onClose={close} />}
    </>
  );
}
