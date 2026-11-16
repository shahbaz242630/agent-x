// What a screen keeps in this tab's sessionStorage for the person signed in
// (6D4a): a bank link started and waiting at the bank (sources.ts), and the
// hold's investigations recorded here (hold.ts). Nothing secret, but it is
// the person's own work, so it goes when their session does: signing out, or
// a session that ends while the page is open (endSession). A step-up's kept
// changes (step-up.ts) go on signing out alone (forgetAll): one may meet a
// 401 on its round trip, and must survive it.

/** Where a started bank link is kept, by person and organisation. */
export const SOURCE_LINK_KEY = 'agentx.source-link.';
/** Where the hold's investigations recorded in this tab are kept, by person and organisation. */
export const HOLD_INVESTIGATIONS_KEY = 'agentx.hold-investigations.';

/** Forgets every sessionStorage entry under these prefixes. Storage blocked: nothing was kept. */
export function dropStartingWith(prefixes: readonly string[]): void {
  try {
    const keys = Array.from({ length: sessionStorage.length }, (_, at) => sessionStorage.key(at));
    for (const key of keys) {
      if (key !== null && prefixes.some((prefix) => key.startsWith(prefix))) sessionStorage.removeItem(key);
    }
  } catch {
    // Storage blocked: nothing kept to forget.
  }
}

/** Forgets everything kept here for anyone: the session is gone. */
export function dropKept(): void {
  dropStartingWith([SOURCE_LINK_KEY, HOLD_INVESTIGATIONS_KEY]);
}
