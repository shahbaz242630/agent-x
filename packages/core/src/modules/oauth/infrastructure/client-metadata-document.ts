// A client named by its own metadata document (6E3c; MCP 2025-11-25's Client
// ID Metadata Documents, draft-ietf-oauth-client-id-metadata-document;
// SEC-OAUTH-09): its client ID is an https address, and what it publishes
// there says what it is and where it may be sent back to. Only an address on
// the allowlist is ever fetched (decision 2, the API's fetcher); what comes
// back is checked here before anything is kept, as a registration is:
// public clients alone, the document naming itself by the very address it was
// fetched from, every redirect address one a client could register.
import { visibleName } from '../../../shared-kernel/index.ts';
import { redirectProblems } from '../domain/redirects.ts';
import { GRANT_TYPES, type GrantType } from './client-metadata.ts';

/** The most characters of a client ID that is an address (0093's client_id columns). */
const MOST_CHARACTERS = 2048;

/** The most redirect addresses a document may list (0095): a published client's web, desktop and loopback ones. */
const MOST_REDIRECTS = 10;

/** The most characters of a client's name, as an agent's. */
const MOST_NAME = 100;

/** A client's metadata document, checked: what is kept. */
export interface ClientMetadataDocument {
  readonly clientId: string;
  readonly name: string;
  readonly redirectUris: readonly string[];
  readonly grantTypes: readonly GrantType[];
}

export type DocumentChecked =
  | { readonly outcome: 'valid'; readonly document: ClientMetadataDocument }
  | { readonly outcome: 'invalid'; readonly reason: string };

/**
 * Whether a client ID is a metadata document's address, as the draft allows one (§3): https, with a path, no user or
 * password, no fragment, no `.` or `..` segment, at most 2048 characters. Anything else is never fetched.
 */
export function isMetadataClientId(clientId: string): boolean {
  if (clientId.length > MOST_CHARACTERS || !clientId.startsWith('https://') || !URL.canParse(clientId)) return false;
  const url = new URL(clientId);
  // Written as the parser prints its origin (no capitals, no default port), so the path is the text after it, as sent:
  // the parser would tidy a `.` or `..` segment away.
  if (!clientId.startsWith(`${url.origin}/`) || url.username !== '' || url.password !== '') return false;
  const [path = ''] = clientId.slice(url.origin.length).split('?', 1);
  const segments = path.split('/');
  return !clientId.includes('#') && path !== '/' && !segments.includes('.') && !segments.includes('..');
}

const invalid = (reason: string): DocumentChecked => ({ outcome: 'invalid', reason });

const isRecord = (value: unknown): value is Readonly<Record<string, unknown>> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const isTextList = (value: unknown): value is readonly string[] =>
  Array.isArray(value) && value.every((one) => typeof one === 'string');

/** The grant types the document names that we know, or the code flow's alone where it names none of them. */
function grantsOf(value: unknown): readonly GrantType[] {
  const known = isTextList(value) ? GRANT_TYPES.filter((grant) => value.some((one) => one === grant)) : [];
  return known.length > 0 ? known : ['authorization_code'];
}

/** The name the document gives, if it is a visible one, or the client ID's host. */
function nameOf(given: unknown, clientId: string): string {
  const checked = typeof given === 'string' ? visibleName(given, MOST_NAME) : undefined;
  return checked?.problems.length === 0 ? checked.name : new URL(clientId).host;
}

/**
 * The document fetched from `clientId`, checked (§4): its own `client_id` is that address exactly; 1 to 10 redirect
 * addresses, each one a client could register (https, or a loopback's); a public client (`none`, no secret); response
 * type `code` if named.
 */
export function checkClientMetadataDocument(clientId: string, document: unknown): DocumentChecked {
  if (!isRecord(document)) return invalid('not_an_object');
  if (document.client_id !== clientId) return invalid('client_id_mismatch');
  const redirects = document.redirect_uris;
  if (!isTextList(redirects) || redirects.length === 0 || redirects.length > MOST_REDIRECTS) {
    return invalid('redirect_uris');
  }
  if (new Set(redirects).size !== redirects.length || redirects.some((one) => redirectProblems(one).length > 0)) {
    return invalid('redirect_uris');
  }
  const method = document.token_endpoint_auth_method ?? 'none';
  if (method !== 'none' || 'client_secret' in document) return invalid('not_public');
  const responses = document.response_types ?? ['code'];
  if (!isTextList(responses) || !responses.includes('code')) return invalid('response_types');
  if (document.grant_types !== undefined && !isTextList(document.grant_types)) return invalid('grant_types');
  return {
    outcome: 'valid',
    document: {
      clientId,
      name: nameOf(document.client_name, clientId),
      redirectUris: [...redirects],
      grantTypes: grantsOf(document.grant_types),
    },
  };
}
