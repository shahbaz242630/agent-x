// A supplier's bank details passed through with no answer (6D2): the try is
// held until it is asked again with the same key, so a fresh one never
// registers the details twice (the API carries an open pass-through on for no
// new key). Held in this tab's memory alone, by organisation and supplier, so
// it outlives the form (Back, a failed re-read, reopening it), and never in
// storage, the address or the query cache: it holds an IBAN. Only an answer,
// a refusal that decides it, or the person's confirmed Stop trying drop one;
// ending the session or leaving the page (pagehide, as 6D1's key) drops them all.

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

const held = new Map<string, HeldTry>();
const at = (organization: string, supplier: string) => `${organization}/${supplier}`;

export const heldTry = (organization: string, supplier: string): HeldTry | undefined =>
  held.get(at(organization, supplier));

/** Holds a try, or drops it with null. */
export function holdTry(organization: string, supplier: string, tried: HeldTry | null): void {
  if (tried === null) held.delete(at(organization, supplier));
  else held.set(at(organization, supplier), tried);
}

/** Drops every try held: the session ended or the page is left. */
export function dropAllTries(): void {
  held.clear();
}

globalThis.addEventListener('pagehide', dropAllTries);
