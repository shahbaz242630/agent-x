// An agent's new key, shown once (6D1; ADR-011 §1: only the key's MAC is
// kept, so no one can show it again). It arrives in a confirm's answer
// (registering, rotating, handing over) and is held only in the state of the
// view that confirmed: never sessionStorage or localStorage, the address, the
// query cache, a log or an error report. Masked until "Show"; copied by the
// Clipboard API, said copied only once the write is done (and said when it
// fails); gone with "Done, I've saved it", which closes the view, or with
// leaving the page, which asks first while it is still on screen.
import { useEffect, useState } from 'react';

import { t } from '../text.ts';

/** What stands for the key while it is hidden: never its length or any of it. */
const MASK = '•'.repeat(24);

/**
 * The key a confirm answered with: none for a change that gives no key; null
 * for one that gives a key but answered without it (a retry of the same
 * confirm: only the first answer carries it).
 */
export function keyIn(answer: unknown): { readonly key: string | null } | undefined {
  if (typeof answer !== 'object' || answer === null || !('key' in answer)) return undefined;
  return { key: typeof answer.key === 'string' ? answer.key : null };
}

type Copied = 'not yet' | 'copied' | 'failed';

export function KeyOnce({ secret, onDone }: { readonly secret: string | null; readonly onDone: () => void }) {
  const [shown, setShown] = useState(false);
  const [copied, setCopied] = useState<Copied>('not yet');
  useEffect(() => {
    if (secret === null) return undefined;
    // Leaving or reloading the page loses the key for good: the browser asks first.
    const stay = (event: BeforeUnloadEvent) => {
      event.preventDefault();
    };
    window.addEventListener('beforeunload', stay);
    return () => {
      window.removeEventListener('beforeunload', stay);
    };
  }, [secret]);
  if (secret === null) {
    return (
      <>
        <p className="notice">{t('keyOnce.retried')}</p>
        <button type="button" className="secondary" onClick={onDone}>
          {t('stepUp.close')}
        </button>
      </>
    );
  }
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(secret);
      setCopied('copied');
    } catch {
      // No clipboard here, or the browser refused it: said, so no one pastes an old one.
      setCopied('failed');
    }
  };
  return (
    <section className="key-once" aria-labelledby="key-once-title">
      <h2 id="key-once-title">{t('keyOnce.title')}</h2>
      <p className="notice">{t('keyOnce.warning')}</p>
      <code className="secret mono" aria-label={shown ? t('keyOnce.shownLabel') : t('keyOnce.hiddenLabel')}>
        {shown ? secret : MASK}
      </code>
      <div className="actions">
        <button
          type="button"
          className="secondary"
          aria-pressed={shown}
          onClick={() => {
            setShown(!shown);
          }}
        >
          {t(shown ? 'keyOnce.hide' : 'keyOnce.show')}
        </button>
        <button type="button" className="secondary" onClick={() => void copy()}>
          {t('keyOnce.copy')}
        </button>
        <button type="button" className="primary" onClick={onDone}>
          {t('keyOnce.done')}
        </button>
      </div>
      {copied !== 'not yet' && (
        <p className={copied === 'failed' ? 'notice' : 'fine'} role="status">
          {t(copied === 'copied' ? 'keyOnce.copied' : 'keyOnce.copyFailed')}
        </p>
      )}
    </section>
  );
}
