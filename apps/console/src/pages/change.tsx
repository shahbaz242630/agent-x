// Sending a change from a screen (6B1, 6B2, 6C1) and saying how it went, the
// same on every screen: left to sign in again, or held open for the person to
// look at, nothing more; done, its words if it has any; refused or failed, in
// the screen's plain words. Everything shown reads again after a decision
// either way (a refusal says the thing moved on); a 401 goes to sign-in.
import { useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';

import { isRefusal, isSignedOut } from '../api.ts';
import { endSession } from '../session.tsx';

interface Sending {
  /** What to say once done; nothing for a change whose page shows it done. */
  readonly done?: string;
  /** Called once decided either way (the pop-up closes). */
  readonly after?: () => void;
  /** This step's own words for a refusal, where they differ from the screen's. */
  readonly refusal?: (error: unknown) => string;
}

/** A screen's changes: `refusal` its words for a refusal or failure. */
export function useChange(refusal: (error: unknown) => string) {
  const queries = useQueryClient();
  const [busy, setBusy] = useState(false);
  const [said, setSaid] = useState<string | null>(null);
  const run = async (send: () => Promise<unknown>, { done, after, refusal: own = refusal }: Sending = {}) => {
    setBusy(true);
    setSaid(null);
    try {
      const sent = await send();
      if (sent === 'stepping' || sent === 'held') return;
      after?.();
      if (done !== undefined) setSaid(done);
      await queries.invalidateQueries();
    } catch (error) {
      if (isSignedOut(error)) {
        endSession(queries);
        return;
      }
      after?.();
      setSaid(own(error));
      if (isRefusal(error)) await queries.invalidateQueries();
    } finally {
      setBusy(false);
    }
  };
  return { busy, said, run };
}

/** What a page says after a change: done, refused or failed. */
export function Said({ said }: { readonly said: string | null }) {
  return said === null ? null : (
    <p className="notice" role="status">
      {said}
    </p>
  );
}
