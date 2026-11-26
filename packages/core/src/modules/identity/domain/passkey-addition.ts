// A passkey added inside Agent X (SA6; ADR-012 §8, SEC-OPS-04, B6-3d). A key
// added at the login service directly restricts the person for 7 days
// (idp-copier.ts), which is right against a phished session enrolling its own
// key, and locks a one-person organisation out for a week when they get a new
// phone. So a person may add one here instead, after signing in again with a
// passkey they already hold (a password, or an app's code, won't do):
//
// 1. the console opens a step-up for `passkey.add`; its return keeps the
//    person's own access token to the login service, sealed, server-side;
// 2. the console is given a one-time ticket (TICKET_SECONDS), for the add-a-key
//    page on a host of its own beside the login service's;
// 3. the page redeems it: the API asks the login service to register a
//    passkey as the person, records the new passkey's ID on the platform chain
//    as the person's own addition, and only then hands the page what to make
//    the key with;
// 4. the page sends the key back, and the API confirms it as the person.
//
// The copier exempts the new key from the restriction only when that exact
// passkey, for that person and login, was recorded before the key was
// confirmed, no more than OWN_KEY_WINDOW_MS before, and no other copy used the
// record already (ownKeyExempts). Any other key counts as it always has. A key
// added still ends every session of the person, as every second factor added
// does.

/** The step-up's action for adding a passkey, in the same form as a write's operation. */
export const PASSKEY_ADD_ACTION = 'passkey.add';

/** The platform chain's record of a passkey the person is adding inside Agent X, before the key exists. */
export const OWN_PASSKEY_REGISTERED = 'identity.own_passkey_registered';

/** How long after the step-up comes back the console may ask for the page's ticket. */
export const STEPPED_UP_SECONDS = 300;

/** How long the page's one-time ticket lasts before it is redeemed. */
export const TICKET_SECONDS = 120;

/** How long the page has, once the ticket is redeemed, to send the key made back. */
export const REGISTERING_SECONDS = 300;

/** How long after the record the login service's confirmation of the key may come and still be the person's own. */
export const OWN_KEY_WINDOW_MS = 15 * 60_000;

/**
 * How far the login service's clock may be behind ours: its confirmation always comes after our record in truth, as
 * the record is made before the page has anything to make the key with.
 */
export const OWN_KEY_CLOCK_TOLERANCE_MS = 5_000;

/** What the copier knows of the person's own addition of the key a copied event confirmed. */
export interface OwnKeyRecord {
  /** When the addition of exactly this passkey, for this person and login, was recorded; undefined: never. */
  readonly recordedAt: Date | undefined;
  /** Whether another copied event was exempted by the same record already. */
  readonly usedBefore: boolean;
}

/**
 * Whether a key confirmed at `confirmedAt` is the person's own addition, so counts toward no restriction: recorded,
 * not used before, and confirmed from just before the record (the clocks' tolerance) to OWN_KEY_WINDOW_MS after it.
 */
export function ownKeyExempts(record: OwnKeyRecord, confirmedAt: Date): boolean {
  const { recordedAt, usedBefore } = record;
  if (recordedAt === undefined || usedBefore) return false;
  const after = confirmedAt.getTime() - recordedAt.getTime();
  return after >= -OWN_KEY_CLOCK_TOLERANCE_MS && after <= OWN_KEY_WINDOW_MS;
}
