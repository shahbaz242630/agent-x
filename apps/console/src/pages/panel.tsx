import type { ReactNode } from 'react';

import { t } from '../text.ts';

/** A page before the shell (sign-in, choosing, a failure): one centred panel, its heading naming it. */
export function Panel({
  id,
  title,
  narrow = false,
  branded = true,
  role,
  children,
}: {
  readonly id: string;
  readonly title: string;
  readonly narrow?: boolean;
  readonly branded?: boolean;
  readonly role?: 'alert';
  readonly children: ReactNode;
}) {
  return (
    <main className="center">
      <section className={narrow ? 'panel narrow' : 'panel'} role={role} aria-labelledby={id}>
        {branded && <span className="brand">{t('brand')}</span>}
        <h1 id={id}>{title}</h1>
        {children}
      </section>
    </main>
  );
}

/** Said wherever organisations are listed, when any of the person's can't be opened. */
export function Unreadable({ count }: { readonly count: number }) {
  return count > 0 ? <p className="notice">{t('choose.unreadable')}</p> : null;
}
