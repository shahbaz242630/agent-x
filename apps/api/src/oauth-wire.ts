// What every OAuth route shares (6E3a, ADR-016): the addresses, the one
// capabilities object every metadata document is written from, the flag that
// keeps it all off, the browser's flow cookie, the RFC error body, and the
// token and revocation endpoints' form parser.
//
// The contract's second wire exception (contract.ts): OAuth's own endpoints
// answer as RFC 6749 §5.2 and RFC 7591 §3.2.2 say, `{error,
// error_description}` at 400 and 401, never the one error body, as every OAuth
// client reads those. A route says so with `config.oauthWire`, and may then
// declare those two statuses with OAUTH_ERROR_BODY alone; what it sends is
// written here and marked as the contract's own, as an error body is. Anything
// the framework refuses first (a body too large, a rate limit) is still the
// one error body.
//
// Off (AGENTX_MCP_OAUTH, the default), every route with `config.oauth` is a
// 404 before its caller is even asked for (server.ts), and nothing anywhere
// advertises it: the MCP endpoint's 401 names no metadata.
import { SCOPES } from '@agentx/core/modules/agents';
import { PKCE_METHOD, SCOPES_SUPPORTED } from '@agentx/core/modules/oauth';
import type { FastifyReply, FastifyRequest } from 'fastify';

import { BUSY_RETRY_SECONDS, JSON_TYPE } from './errors.ts';
import { MCP_PATH } from './mcp-protocols.ts';
import { OAUTH_ERROR_BODY, type OauthError } from './oauth-errors.ts';
import { markWritten } from './written-answers.ts';

declare module 'fastify' {
  interface FastifyContextConfig {
    /** One of the OAuth server's routes (6E3a): a 404 while AGENTX_MCP_OAUTH is off. */
    readonly oauth?: true;
    /** Answers OAuth's own error bodies at 400 and 401 (the contract's second wire exception, oauth-wire.ts). */
    readonly oauthWire?: true;
    /** Called by OAuth clients from anywhere: a write from another origin is theirs to make (no cookie is read). */
    readonly oauthClient?: true;
  }
  interface FastifyRequest {
    /** A form body sent with a field twice (RFC 6749 §3.1): refused by its route as `invalid_request`. */
    formRepeated: boolean;
  }
}

/** Where each OAuth endpoint is. */
export const OAUTH_PATHS = {
  authorize: '/v1/oauth/authorize',
  // The token endpoint, where a code or refresh is exchanged.
  exchange: '/v1/oauth/token',
  revoke: '/v1/oauth/revoke',
  register: '/v1/oauth/register',
  resourceMetadata: '/.well-known/oauth-protected-resource',
  serverMetadata: '/.well-known/oauth-authorization-server',
  openIdConfiguration: '/.well-known/openid-configuration',
} as const;

/** Where the console asks the person, and where a request the client can't be told of goes (6E3b's screen). */
export const CONNECT_PATH = '/connect';

/**
 * Everything the metadata documents say, from the one object (decision 1: the RFC 8414 document and OIDC discovery's
 * are the same, and nothing claims OIDC). The issuer is the public origin exactly, no trailing slash (MCP-Guide §8).
 */
export interface Capabilities {
  readonly issuer: string;
  /** The MCP endpoint, the one resource a connection's tokens are for (RFC 8707). */
  readonly resource: string;
  readonly resourceMetadataUrl: string;
  readonly authorizationEndpoint: string;
  readonly tokenEndpoint: string;
  readonly revocationEndpoint: string;
  readonly registrationEndpoint: string;
  readonly scopes: readonly string[];
  readonly grantTypes: readonly string[];
}

/** The origin with no slash at its end: the issuer is compared as text, exactly (RFC 8414 §3.3). */
function withoutTrailingSlash(origin: string): string {
  let end = origin.length;
  while (end > 0 && origin.charAt(end - 1) === '/') end -= 1;
  return origin.slice(0, end);
}

export function capabilitiesOf(publicOrigin: string): Capabilities {
  const issuer = withoutTrailingSlash(publicOrigin);
  return {
    issuer,
    resource: `${issuer}${MCP_PATH}`,
    resourceMetadataUrl: `${issuer}${OAUTH_PATHS.resourceMetadata}${MCP_PATH}`,
    authorizationEndpoint: `${issuer}${OAUTH_PATHS.authorize}`,
    tokenEndpoint: `${issuer}${OAUTH_PATHS.exchange}`,
    revocationEndpoint: `${issuer}${OAUTH_PATHS.revoke}`,
    registrationEndpoint: `${issuer}${OAUTH_PATHS.register}`,
    scopes: SCOPES_SUPPORTED,
    grantTypes: ['authorization_code', 'refresh_token'],
  };
}

/** The protected resource's metadata (RFC 9728), as the document holds it. */
export const resourceMetadataOf = (capabilities: Capabilities) => ({
  resource: capabilities.resource,
  authorization_servers: [capabilities.issuer],
  scopes_supported: [...SCOPES],
  bearer_methods_supported: ['header'],
  resource_name: 'Agent X',
  resource_documentation: `${capabilities.issuer}/docs/api`,
});

/** The authorization server's metadata (RFC 8414), the same document at OIDC discovery's address too. */
export const serverMetadataOf = (capabilities: Capabilities) => ({
  issuer: capabilities.issuer,
  authorization_endpoint: capabilities.authorizationEndpoint,
  token_endpoint: capabilities.tokenEndpoint,
  revocation_endpoint: capabilities.revocationEndpoint,
  registration_endpoint: capabilities.registrationEndpoint,
  scopes_supported: [...capabilities.scopes],
  response_types_supported: ['code'],
  response_modes_supported: ['query'],
  grant_types_supported: [...capabilities.grantTypes],
  code_challenge_methods_supported: [PKCE_METHOD],
  token_endpoint_auth_methods_supported: ['none'],
  revocation_endpoint_auth_methods_supported: ['none'],
  authorization_response_iss_parameter_supported: true,
});

/** The OAuth error answers a route with `config.oauthWire` declares, beside the one error body for the rest. */
export const OAUTH_ERROR_RESPONSES = { 400: OAUTH_ERROR_BODY, 401: OAUTH_ERROR_BODY, 503: OAUTH_ERROR_BODY } as const;

/** What no token answer, nor any refusal of a token endpoint, may be kept as (RFC 6749 §5.1). */
const NO_STORE = { 'cache-control': 'no-store', pragma: 'no-cache' } as const;

/** Sends OAuth's own error body, written as the contract's (the second wire exception). */
export function sendOauthError(
  reply: FastifyReply,
  status: 400 | 401 | 503,
  error: OauthError,
  description: string,
): FastifyReply {
  const text = JSON.stringify({ error, error_description: description });
  markWritten(reply, text);
  // Busy: send the same again after this many seconds (RFC 7009 §2.2.1), as every busy answer says.
  if (status === 503) void reply.header('retry-after', String(BUSY_RETRY_SECONDS));
  return reply.code(status).headers(NO_STORE).type(JSON_TYPE).send(text);
}

/** A token endpoint's answer: never kept by a cache (RFC 6749 §5.1). */
export const noStore = (reply: FastifyReply): FastifyReply => reply.headers(NO_STORE);

/** The browser's flow cookie (a `__Host-` cookie, as the console's are): it alone reads or decides its flows. */
export const CONNECT_COOKIE = '__Host-agentx-connect';

/** How long the flow cookie lasts: a day, so one browser's flows share it. */
const CONNECT_COOKIE_SECONDS = 86_400;

/** The cookie as set: Secure, HttpOnly, Lax (it rides the client's redirect back to the console). */
export const connectCookie = (value: string): string =>
  `${CONNECT_COOKIE}=${value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${String(CONNECT_COOKIE_SECONDS)}`;

/** The most a token or revocation form may be (plan §3): every field a client sends, with room to spare. */
export const FORM_BODY_LIMIT = 4096;

/** The one type of body OAuth's token and revocation endpoints take (RFC 6749 §3.2). */
export const FORM_TYPE = 'application/x-www-form-urlencoded';

/**
 * Reads an OAuth form body (server.ts adds it as its scope's one parser): each field once, as text. A field sent twice
 * marks the request (`formRepeated`), and its route refuses it as RFC 6749 §3.1 says.
 */
export function formFields(request: FastifyRequest, body: string | Buffer): Record<string, string> {
  const fields: Record<string, string> = {};
  for (const [name, value] of new URLSearchParams(typeof body === 'string' ? body : body.toString('utf8'))) {
    if (Object.hasOwn(fields, name)) request.formRepeated = true;
    fields[name] = value;
  }
  return fields;
}

/** Where a client's browser goes back to: its own address, with these parameters added to its query. */
export function backToClient(redirectUri: string, parameters: Readonly<Record<string, string | null>>): string {
  const url = new URL(redirectUri);
  for (const [name, value] of Object.entries(parameters)) {
    if (value !== null) url.searchParams.append(name, value);
  }
  return url.toString();
}
