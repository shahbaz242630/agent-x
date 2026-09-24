/**
 * Every package product code may depend on at run time, with the reason it
 * was accepted (Rule Book §5: a new dependency needs a reason). A check fails
 * if any package or app declares a production dependency missing from this
 * list, or if an entry is no longer used. So a new dependency, a telemetry SDK
 * included, is always a reviewed change to this file. Workspace packages
 * (`workspace:*`) and development tools are not listed.
 */
export const ALLOWED_DEPENDENCIES: Readonly<Record<string, string>> = {
  '@fastify/proxy-addr':
    "SEC-AV-07: Fastify's own proxy-trust rule, also applied to the rate limit's key for requests Fastify builds without it",
  '@fastify/rate-limit': "ADR-011 §4: the API's rate limit per client address; Fastify's own plugin",
  '@fastify/swagger':
    "ADR-001, SEC-WEB-06: writes the API's OpenAPI document from its routes; Fastify's own plugin. It serves nothing: the document is not a route",
  fastify: "ADR-001: the API's HTTP server",
  'fastify-type-provider-zod':
    'ADR-001, SEC-WEB-06: every route checks its input and answers through its zod schemas, and they become the OpenAPI document',
  jose: "ADR-003 §5: checks the login service's ID tokens (JWS signatures against its published keys, and the JWT claims); no dependencies of its own, and used only by the identity module's OIDC client, which fetches the keys itself through the outbound allowlist",
  kysely: 'ADR-001: typed SQL with bound parameters, and the transactions withTenant opens',
  pg: 'ADR-001: the Postgres driver, used only by @agentx/platform/db and the test database harness',
  pino: 'ADR-001, ADR-013: the logger, which writes redacted JSON lines to stdout',
  uuid: 'ADR-001, ADR-007: UUIDv7 IDs generated in the app',
  zod: 'ADR-001, Rule Book §5: input validation at the edges, and the start-up config check',
};
