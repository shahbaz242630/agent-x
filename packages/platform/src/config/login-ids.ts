// SA2b: our login service user IDs, read alone, with no package: the API's config (settings.ts loginIdList) and the
// deploy tool's paste check (deploy/azure/deploy.ts, run in CI with no packages installed) both read them here, so
// what the deploy writes is exactly what the API accepts.

/** The most login service user IDs one of SA2's lists may name: a handful are ours, so more is a pasting slip. */
const MOST_LOGIN_IDS = 20;

/** The word for no list: the vault holds it until the partner writes ours, so the secret is always there to mount. */
export const NO_LOGIN_IDS = 'none';

/** A list read: its IDs (sorted, once each), none for `none`, or what is wrong with it, never repeating a value. */
export type LoginIdsRead =
  { readonly ok: true; readonly ids: readonly string[] | undefined } | { readonly ok: false; readonly problem: string };

/** Login service user IDs, as Zitadel makes them (digits), comma-separated with no spaces, or `none`. */
export function readLoginIds(raw: string): LoginIdsRead {
  if (raw === NO_LOGIN_IDS) return { ok: true, ids: undefined };
  const entries = raw.split(',');
  const bad = entries.flatMap((entry, index) => (/^\d{1,30}$/.test(entry) ? [] : [index + 1]));
  if (bad.length > 0) {
    return {
      ok: false,
      problem: `entry ${bad.join(', ')} is not a login service user ID. Write each as its digits, comma-separated with no spaces, or none`,
    };
  }
  if (entries.length > MOST_LOGIN_IDS) {
    return { ok: false, problem: `names ${String(entries.length)} IDs; at most ${String(MOST_LOGIN_IDS)}` };
  }
  return { ok: true, ids: [...new Set(entries)].sort() };
}
