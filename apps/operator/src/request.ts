// The request the operator's job reads from its file (B1c-2a), in the one
// place both sides take it from: the command that reads it (main.ts) and
// deploy/azure/operator.ts, which writes it onto the job before a run
// (B1c-2b). A JSON list of the command's words and the new organisation's ID,
// or of the first admin's invitation (B4-6b), at most REQUEST_LIMIT_BYTES of
// UTF-8. Nothing here logs anything: a name or an address never is.

/** The most a request file may hold: a command and one name, with room to spare. */
export const REQUEST_LIMIT_BYTES = 4096;

/** What a request file holds, as a JSON list: the same words, and the new organisation's ID. */
export const REQUEST_USAGE = 'create-organization --name <name> --id <new ID>';

/** A UUIDv7 in lower case, as the product makes every ID (ADR-007). */
export const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/** Why a run holding the job's `[]` is refused, which deploy/azure/operator.ts looks for in the run's log. */
export const NO_REQUEST_PROBLEM = 'no request was written for this run: the job holds none until a person writes one';

/** What a request file holds to invite an organisation's first admin (B4-6b): only ever a file, as the token's hash is made where its link is shown. */
export const FIRST_ADMIN_USAGE =
  'invite-first-admin --org <organisation ID> --email <address> --id <new invitation ID> --token-hash <64 hex>';

/** The SHA-256 of an invitation's token, in lower-case hex. */
export const TOKEN_HASH_HEX = /^[0-9a-f]{64}$/;

/** The request to create an organisation with this name and ID, as its file holds it. */
export const createOrganizationRequest = (name: string, id: string): string =>
  JSON.stringify(['create-organization', '--name', name, '--id', id]);

/** The request to invite the organisation's first admin, as its file holds it: the token's hash, never the token. */
export const firstAdminRequest = (orgId: string, email: string, id: string, tokenHashHex: string): string =>
  JSON.stringify(['invite-first-admin', '--org', orgId, '--email', email, '--id', id, '--token-hash', tokenHashHex]);
