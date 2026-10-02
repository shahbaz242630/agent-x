// Opening a field kept sealed with field-encryption: an address or a reset's
// secret, bound to its own row's IDs by the associated data.
import type { KeyProvider, Message, Sealed } from '@agentx/platform/keys';

/** The sealed field's text; what `onFail` makes of the cause is thrown for one that won't open. */
export function openField(
  keys: KeyProvider,
  sealed: Sealed,
  associatedData: Message,
  onFail: (cause: unknown) => Error,
): string {
  try {
    return keys.decrypt('field-encryption', sealed, associatedData).toString('utf8');
  } catch (error) {
    throw onFail(error);
  }
}
