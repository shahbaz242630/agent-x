// The request the operator's job reads from its file (B1c-2a), in the one
// place both sides take it from: the command that reads it (main.ts) and
// deploy/azure/operator.ts, which writes it onto the job before a run
// (B1c-2b). A JSON list of the command's words and the new organisation's ID,
// or of the first admin's invitation (B4-6b), an export for a case (E10c,
// L7), or a pause or resume of every hand-off (Phase 4 B1), at most
// REQUEST_LIMIT_BYTES of UTF-8. Nothing here logs anything: a name or an address never is, and
// nothing here imports anything, so the deploy tool reads it as it is.

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

/** The restore drill's check (S78), which a request file holds as its one word: it reads, and names no ID, as it makes nothing. */
export const RESTORE_CHECK = 'restore-check';

/** The request for the restore drill's check, as its file holds it. */
export const restoreCheckRequest = (): string => JSON.stringify([RESTORE_CHECK]);

/** What a request file holds to export an organisation's audit log for a case (Phase 3 E10c, ADR-005 §6): only ever a file. */
export const AUDIT_EXPORT_USAGE =
  'audit-export --org <organisation ID> --from <time> --to <time> --reason <case reference> --id <new export ID>';

/** What a request file holds to export an organisation's activity log for a case (Phase 3 L7): as an audit export's. */
export const ACTIVITY_EXPORT_USAGE =
  'activity-export --org <organisation ID> --from <time> --to <time> --reason <case reference> --id <new export ID>';

/**
 * A case reference, as a dispute's or a regulator's file names one: 3 to 64
 * letters, digits and `. _ / -`, starting with a letter or digit. No spaces,
 * so it stays a reference and never becomes a note about the case: it is
 * sealed on both chains and shown to the organisation's admins.
 */
const CASE_REFERENCE = /^[A-Za-z0-9][A-Za-z0-9._/-]{2,63}$/;

/** Why a case reference is refused, which never repeats it. */
const CASE_REFERENCE_PROBLEM =
  'the case reference must be 3 to 64 letters, digits and . _ / -, starting with a letter or digit';

/** A time as a request file names one: UTC, to the second or the millisecond (2026-10-01T00:00:00Z). */
const REQUEST_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;

/** Why an audit export can't run where no store is set for its file, which deploy/azure/operator.ts looks for in the run's log. */
export const NO_STORE_PROBLEM =
  'no store for an audit export is set: AGENTX_EVIDENCE_CONTAINER_URL deployed, or AGENTX_EVIDENCE_DIR in development and test';

/**
 * A request file's time, or undefined for one that isn't REQUEST_TIME or isn't
 * a real moment: no date at all (month 13, hour 25), or one a date rolls over
 * (30 February). Without its Z, the text starts the moment's own ISO form,
 * to the second or the millisecond.
 */
function requestTime(text: string | undefined): Date | undefined {
  if (text === undefined || !REQUEST_TIME.test(text)) return undefined;
  const at = new Date(text);
  return !Number.isNaN(at.getTime()) && at.toISOString().startsWith(text.slice(0, -1)) ? at : undefined;
}

/** An audit export's words, as a request file or the deploy tool's command line gives them. */
export interface AuditExportWords {
  readonly orgId: string | undefined;
  readonly from: string | undefined;
  readonly to: string | undefined;
  readonly caseRef: string | undefined;
  readonly id: string;
}

/** The audit export asked for, its times read. */
export interface AuditExportAsked {
  readonly orgId: string;
  readonly from: Date;
  readonly to: Date;
  readonly caseRef: string;
  readonly id: string;
}

/** A day, in milliseconds. */
const DAY = 86_400_000;

/**
 * The audit export these words ask for, or the problems, by the rules both
 * sides hold it to: the operator's command reading its file (main.ts), and
 * deploy/azure/operator.ts before it writes one. The range is an admin's
 * download's: at most `mostDays` days (core's MOST_EXPORT_DAYS, which the
 * caller passes, since nothing here imports anything). The case reference is
 * repeated in no problem.
 */
export function auditExportOf(
  { orgId, from: fromText, to: toText, caseRef, id }: AuditExportWords,
  mostDays: number,
): AuditExportAsked | { readonly problems: readonly string[] } {
  const from = requestTime(fromText);
  const to = requestTime(toText);
  const span = (to?.getTime() ?? Number.NaN) - (from?.getTime() ?? Number.NaN);
  const problems = [
    ...(UUID_V7.test(String(orgId)) ? [] : ["the organisation's ID must be a UUIDv7, in lower case"]),
    ...(UUID_V7.test(id) ? [] : ["the export's ID must be a UUIDv7, in lower case"]),
    ...(from === undefined || to === undefined
      ? ['--from and --to must each be a UTC time, such as 2026-10-01T00:00:00Z']
      : []),
    ...(span <= 0 || span > mostDays * DAY
      ? [`the range starts before it ends, ${String(mostDays)} days at most`]
      : []),
    ...(CASE_REFERENCE.test(String(caseRef)) ? [] : [CASE_REFERENCE_PROBLEM]),
  ];
  if (problems.length > 0 || from === undefined || to === undefined) return { problems };
  return { orgId: String(orgId), from, to, caseRef: String(caseRef), id };
}

/** The request to export an organisation's audit log for a case, as its file holds it. */
export const auditExportRequest = (orgId: string, from: string, to: string, caseRef: string, id: string): string =>
  JSON.stringify(['audit-export', '--org', orgId, '--from', from, '--to', to, '--reason', caseRef, '--id', id]);

/** The request to export an organisation's activity log for a case, as its file holds it (Phase 3 L7). */
export const activityExportRequest = (orgId: string, from: string, to: string, caseRef: string, id: string): string =>
  JSON.stringify(['activity-export', '--org', orgId, '--from', from, '--to', to, '--reason', caseRef, '--id', id]);

/** The two commands that pause and resume every hand-off to the bank (Phase 4 B1, SEC-OPS-03): only ever a file. */
export type HandoffCommand = 'handoff-pause' | 'handoff-resume';

/** What a request file holds to pause or resume every hand-off: the reason, and the ID of the platform event it records. */
export const handoffUsage = (command: HandoffCommand): string => `${command} --reason <reference> --id <new ID>`;

/** A pause or resume asked for: its reason (a case reference) and the ID its platform event takes. */
export interface HandoffAsked {
  readonly reason: string;
  readonly id: string;
}

/**
 * The pause or resume these words ask for, or the problems, by the rules both
 * sides hold it to: the operator's command reading its file (main.ts), and
 * deploy/azure/operator.ts before it writes one. The reason is a case
 * reference (an incident's or a regulator's), sealed on the platform chain
 * and every organisation's, shown to their admins; it is repeated in no problem.
 */
export function handoffAskedOf({
  reason,
  id,
}: {
  readonly reason: string | undefined;
  readonly id: string;
}): HandoffAsked | { readonly problems: readonly string[] } {
  const problems = [
    // None given is refused, never read as the text `undefined`, which has the shape of a reference.
    ...(reason !== undefined && CASE_REFERENCE.test(reason) ? [] : [CASE_REFERENCE_PROBLEM]),
    ...(UUID_V7.test(id) ? [] : ["the pause's ID must be a UUIDv7, in lower case"]),
  ];
  return problems.length > 0 || reason === undefined ? { problems } : { reason, id };
}

/** The request to pause or resume every hand-off, as its file holds it. */
export const handoffRequest = (command: HandoffCommand, reason: string, id: string): string =>
  JSON.stringify([command, '--reason', reason, '--id', id]);
