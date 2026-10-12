// The paging both expiry jobs share (mandates, Phase 2 B4; spend requests,
// D7): each organisation the directory lists in turn, its candidates found by
// their rows a page at a time, each page after the last, so candidates
// refused on every run (tampered with) can't fill a page and keep the rest
// from their end, and no more than a run's share expired.

/**
 * Runs `inEach` for each organisation `list` names, until one returns false
 * (the signal stopped it). A list that can't be read skips the whole run,
 * `failed` logging it: an error the integrity-runs alert counts (Phase 2 E2c).
 */
export async function eachOrganisation(
  list: () => Promise<readonly string[]>,
  failed: (error: unknown) => void,
  inEach: (orgId: string) => Promise<boolean>,
): Promise<void> {
  let orgs: readonly string[];
  try {
    orgs = await list();
  } catch (error) {
    failed(error);
    return;
  }
  for (const orgId of orgs) {
    if (!(await inEach(orgId))) return;
  }
}

/**
 * Expires one organisation's candidates, up to `most`: each page as long as
 * what is left of the share, each candidate by `expire` (whether it expired
 * it); false if the signal stopped it. A page that can't be read ends the
 * organisation's run (`unreadable`).
 */
export async function expireInPages({
  most,
  signal,
  page,
  expire,
  unreadable,
}: {
  readonly most: number;
  readonly signal: AbortSignal | undefined;
  readonly page: (left: number, after: string | undefined) => Promise<readonly string[]>;
  readonly expire: (id: string) => Promise<boolean>;
  readonly unreadable: (error: unknown) => void;
}): Promise<boolean> {
  let expired = 0;
  let after: string | undefined;
  // Until the candidates run out, or the run's share of them is expired.
  while (expired < most) {
    // A page as long as what is left of the share, so a run never expires more.
    const left = most - expired;
    let due: readonly string[];
    try {
      due = await page(left, after);
    } catch (error) {
      unreadable(error);
      return true;
    }
    for (const id of due) {
      if (signal?.aborted === true) return false;
      if (await expire(id)) expired += 1;
    }
    if (due.length < left) return true;
    after = due.at(-1);
  }
  return true;
}
