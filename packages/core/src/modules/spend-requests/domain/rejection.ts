// Why a person rejected a spend request (Phase 3 B4a; partner decision 6): a
// short reason, required, kept in the reject's signed event and shown to the
// team; the agent never sees it.
import { keptNote } from '../../../shared-kernel/index.ts';

/** The most characters a reject's reason may have. */
export const REJECT_REASON_MOST = 200;

/** The reason as it is kept (composed, NFC), with the problems that keep it from being one. */
export const rejectReason = (reason: string): { readonly note: string; readonly problems: readonly string[] } =>
  keptNote(reason, REJECT_REASON_MOST, 'the reason');
