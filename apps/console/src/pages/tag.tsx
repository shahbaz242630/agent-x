// A status badge beside a name ("Suspended", "In force"). A real space comes
// before it so a screen reader reads "Buyer bot, Suspended" as two words,
// never "Buyer botSUSPENDED" (CO11a F6): a CSS margin alone sets no gap in
// the text (the margin is 4px so the space and it together look as before).
import type { ReactNode } from 'react';

export function Tag({ warn = false, children }: { readonly warn?: boolean; readonly children: ReactNode }) {
  return (
    <>
      {' '}
      <span className={warn ? 'tag warn' : 'tag'}>{children}</span>
    </>
  );
}
