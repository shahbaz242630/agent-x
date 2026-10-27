import { t, type TextKey } from '../text.ts';

/** A section whose screens come in a later slice: what it will hold. */
export function Soon({ what }: { readonly what: TextKey }) {
  return (
    <section className="soon">
      <p>{t(what)}</p>
      <p className="muted">{t('soon.note')}</p>
    </section>
  );
}
