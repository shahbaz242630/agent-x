// A supplier's bank details passed through with no answer (6D2): the try is
// held until it is asked again with the same key, so a fresh one never
// registers the details twice (the API carries an open pass-through on for no
// new key). Held in this tab's memory alone, by person, organisation and
// supplier, so it outlives the form (Back, a failed re-read, reopening it) and
// a session that ends (the same person signing in again finds it locked),
// while no one else signing in on the tab ever sees it. Never in storage, the
// address or the query cache: it holds an IBAN. Only an answer, a refusal that
// ends it, or the person's confirmed Stop trying drop one; signing out or
// leaving the page (pagehide, as 6D1's key) drops them all. The guard is this
// tab's alone: another tab, or a reload, doesn't know of it.

/** The pass-through's body, as sent: the details and the choice made with them. */
interface PassedBody {
  readonly name: string;
  readonly iban: string;
  readonly pendingRequests: string;
  readonly statementVersion?: number | undefined;
}

/** A try with no answer: sent again whole with the same key, the API asks the partner by it. */
export interface HeldTry {
  readonly key: string;
  readonly body: PassedBody;
  /** How the details came, as the person said before sending: shown again with them. */
  readonly told: 'yes' | 'no';
}

/** Whose try: the person signed in, the organisation they act in, and the supplier. */
export interface Whose {
  readonly user: string;
  readonly organization: string;
  readonly supplier: string;
}

const held = new Map<string, HeldTry>();
const at = ({ user, organization, supplier }: Whose) => [user.toLowerCase(), organization, supplier].join('/');

export const heldTry = (whose: Whose): HeldTry | undefined => held.get(at(whose));

/** Holds a try, or drops it with null. */
export function holdTry(whose: Whose, tried: HeldTry | null): void {
  if (tried === null) held.delete(at(whose));
  else held.set(at(whose), tried);
}

/** Drops every try held: the person signed out, or the page is left. */
export function dropAllTries(): void {
  held.clear();
}

globalThis.addEventListener('pagehide', dropAllTries);
