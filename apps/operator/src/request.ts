// The request the operator's job reads from its file (B1c-2a), in the one
// place both sides take it from: the command that reads it (main.ts) and
// deploy/azure/operator.ts, which writes it onto the job before a run
// (B1c-2b). A JSON list of the command's words and the new organisation's ID,
// at most REQUEST_LIMIT_BYTES of UTF-8. Nothing here logs anything: a name
// never is.

/** The most a request file may hold: a command and one name, with room to spare. */
export const REQUEST_LIMIT_BYTES = 4096;

/** What a request file holds, as a JSON list: the same words, and the new organisation's ID. */
export const REQUEST_USAGE = 'create-organization --name <name> --id <new ID>';

/** A UUIDv7 in lower case, as the product makes every ID (ADR-007). */
export const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/** Why a run holding the job's `[]` is refused, which deploy/azure/operator.ts looks for in the run's log. */
export const NO_REQUEST_PROBLEM = 'no request was written for this run: the job holds none until a person writes one';

/** The request to create an organisation with this name and ID, as its file holds it. */
export const createOrganizationRequest = (name: string, id: string): string =>
  JSON.stringify(['create-organization', '--name', name, '--id', id]);
