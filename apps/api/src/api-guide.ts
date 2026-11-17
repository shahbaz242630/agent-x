// BR-19 (6E1c): what an integrator reads in the OpenAPI document before any
// one operation: how the API is versioned, how people and agents sign in, the
// organisation's header, idempotency, the one error body, rate limits and
// correlation IDs. Written over the document the routes made (contract.ts),
// from what each operation already shows, so it can't say otherwise:
// - its `security`, from its x-access and x-agent-scopes;
// - its one tag, from its address;
// - its 429 answer, which the rate limit gives every route (rate-limit.ts).
// Nothing here changes what a route checks or answers. The guide for agent
// builders is docs/api/README.md, held to this document by docs-api.test.ts.
import { KEY_DAYS, KEY_PREFIX } from '@agentx/core/modules/agents';
import { FAKE_SIGNATURE_HEADER } from '@agentx/core/modules/providers';
import type { ReasonCode } from '@agentx/core/shared-kernel';
import { IDEMPOTENCY_RETENTION_DAYS } from '@agentx/platform/db';
import { z } from 'zod';

import { ORGANIZATION_HEADER } from './access.ts';
import { CORRELATION_HEADER } from './correlation.ts';
import { RATE_LIMIT_HEADERS } from './rate-limit.ts';
import { SESSION_COOKIE } from './sign-in.ts';
import { IDEMPOTENCY_KEY_HEADER, IDEMPOTENCY_KEY_RULE } from './write-operations.ts';

/** The guide for agent builders, in the public repository. */
export const GUIDE_URL = 'https://github.com/shahbaz242630/agent-x/blob/main/docs/api/README.md';

/** The security scheme of a signed-in person's session cookie. */
export const SESSION_SCHEME = 'session';

/** The security scheme of an agent's key. */
export const AGENT_KEY_SCHEME = 'agentKey';

/** The security scheme of the partner's signature over a message's raw body. */
export const PARTNER_SIGNATURE_SCHEME = 'partnerSignature';

/** An agent's key as it is written, its parts named. */
const KEY_FORM = `${KEY_PREFIX}<keyId>_<secret>`;

/** A reason code, as the description shows it: a code renamed or removed stops this compiling. */
const code = (name: ReasonCode): string => `\`${name}\``;

/** Where the document shows the 429 every route may answer, once. */
const RATE_LIMITED_RESPONSE = 'RateLimited';

/** What each header the rate limit sets means: one for every header it sets, which the type holds it to. */
const RATE_LIMIT_HEADER_TEXT: Readonly<Record<(typeof RATE_LIMIT_HEADERS)[number], string>> = {
  'x-ratelimit-limit': 'The most requests the limit that refused this one allows in a minute.',
  'x-ratelimit-remaining': 'How many of them are left in this minute: none, on a 429.',
  'x-ratelimit-reset': 'Seconds until the minute ends and the count starts again.',
  'retry-after': 'Seconds to wait before sending the request again (RFC 9110 §10.2.3).',
};

/**
 * Each tag, what it holds, and the addresses it holds: an address is the
 * prefix itself or anything below it. No prefix sits below another, so an
 * operation has one tag at most; contract.test.ts holds every operation the
 * API serves to exactly one, so a new area of the API is named before it
 * ships. (An address none holds isn't refused here: the tests' own routes
 * have none.)
 */
export const TAGS: readonly {
  readonly name: string;
  readonly description: string;
  readonly prefixes: readonly string[];
}[] = [
  {
    name: 'Agent API',
    description:
      "What an AI agent calls with its key: who it is, its mandate, the bank accounts and suppliers it may name, and its own spend requests. It creates a spend request under 'Spend requests'.",
    prefixes: ['/v1/agent'],
  },
  {
    name: 'Spend requests',
    description:
      "Spend requests and their decisions. An agent creates one (POST /v1/spend-requests); the organisation's people read, approve, reject and cancel them.",
    prefixes: ['/v1/spend-requests', '/v1/approvals'],
  },
  {
    name: 'Agents',
    description: "The organisation's AI agents, registered by its people: their keys, scopes, owners and suspensions.",
    prefixes: ['/v1/agents'],
  },
  {
    name: 'Mandates and policy',
    description: "Each agent's mandate, and the organisation's and each mandate's spending rules.",
    prefixes: ['/v1/mandates', '/v1/policies'],
  },
  {
    name: 'Suppliers',
    description: 'The suppliers an organisation pays, their bank details, and how each was verified.',
    prefixes: ['/v1/suppliers'],
  },
  {
    name: 'Bank accounts',
    description: "The organisation's bank accounts, linked through the licensed partner with the bank's consent.",
    prefixes: ['/v1/funding-sources'],
  },
  {
    name: 'Payments',
    description:
      'Payments the licensed partner initiated from approved spend requests, as it reports them, and the exceptions to follow up with the bank.',
    prefixes: ['/v1/payments'],
  },
  {
    name: 'Organisation',
    description: 'The organisation as a whole: freezing it, its integrity hold, and its registered contacts.',
    prefixes: ['/v1/organization', '/v1/integrity-hold', '/v1/registered-contacts'],
  },
  {
    name: 'Members',
    description: 'The people in an organisation: roles, invitations, deactivations and second-factor resets.',
    prefixes: ['/v1/members', '/v1/invitations', '/v1/factor-resets'],
  },
  {
    name: 'Logs',
    description: "The organisation's audit log and access log, to read and export.",
    prefixes: ['/v1/audit-log', '/v1/access-log'],
  },
  {
    name: 'Sign-in',
    description:
      "A person's sign-in to the console, their session and organisations, and the words each choice is confirmed with.",
    prefixes: ['/v1/auth', '/v1/statements'],
  },
  {
    name: 'Partner',
    description:
      "The licensed partner's messages about its payments, and the stand-in partner used for testing (staging only).",
    prefixes: ['/v1/partner', '/v1/fake-bank'],
  },
  {
    name: 'Service',
    description: "The service's own health, and the console's error reports.",
    prefixes: ['/health', '/internal', '/v1/client-errors'],
  },
];

/** The tags whose prefixes hold an address. */
export const tagsOf = (path: string): string[] =>
  TAGS.filter(({ prefixes }) => prefixes.some((prefix) => path === prefix || path.startsWith(`${prefix}/`))).map(
    ({ name }) => name,
  );

/** The document's description: one section, under a heading of its own, for each thing an integrator reads first. */
const DESCRIPTION = `Agent X turns an AI agent's request to pay a supplier into a policy-approved payment intent. The licensed partner validates consent and authentication, then initiates and executes the payment. The guide for agent builders: ${GUIDE_URL}.

## Versioning

Every address of the API's own starts with \`/v1\`, its major version (the service's health and internal addresses aside). Within v1, changes are additive only: new addresses, new optional request fields, new answer fields and new reason codes. Ignore answer fields you don't know, and treat a reason code you don't know by its HTTP status. A breaking change comes only under \`/v2\`, with notice.

## Authentication

Each operation's \`security\` shows who may call it, as does its \`x-access\`:

- **People** sign in through the console. Their session is the \`${SESSION_COOKIE}\` cookie (scheme \`${SESSION_SCHEME}\`).
- **AI agents** send their key as \`Authorization: Bearer ${KEY_FORM}\` (scheme \`${AGENT_KEY_SCHEME}\`). A key expires ${String(KEY_DAYS)} days after it is made. An operation names the scopes the key must hold; an agent may call only operations naming agents.
- **The licensed partner** signs each message it sends over its raw body (scheme \`${PARTNER_SIGNATURE_SCHEME}\`).

A missing or refused credential is 401 ${code('UNAUTHENTICATED')}; a caller the operation doesn't name is 403 ${code('FORBIDDEN')}; a key without every scope the operation needs is 403 ${code('INSUFFICIENT_SCOPE')}. An admin's or approver's powers need a session signed in with a passkey (403 ${code('PASSKEY_REQUIRED')}), and for a while after a second factor is removed a person keeps only what a developer or viewer may do (403 ${code('SECOND_FACTOR_REMOVED')}).

## Organisation header

A person's call on an operation naming roles names the organisation it acts in, by its ID, in the \`AgentX-Organization\` header (\`${ORGANIZATION_HEADER}\`); without one, or with something other than an ID, it is 400 ${code('ORGANIZATION_INVALID')}. An agent never sends it: its key's organisation is the one.

## Idempotency

A write that changes something requires an \`Idempotency-Key\` header (\`${IDEMPOTENCY_KEY_HEADER}\`), shown as a required header on its operation: ${IDEMPOTENCY_KEY_RULE}, new for each change, the same to retry it. The same key with the same request does nothing twice: it answers with the first request's status and the resource as it now stands. With another request it is 409 ${code('IDEMPOTENCY_KEY_REUSED')}; while the first is still being done it is 409 ${code('IDEMPOTENCY_KEY_BUSY')} with Retry-After. A key is kept for at least ${String(IDEMPOTENCY_RETENTION_DAYS)} days: don't reuse one, even after that. The operation's \`operationId\` names what the key is for.

## Errors

Every refusal and failure has the one \`Error\` body: \`{ "error": { "code", "message", "correlationId" } }\`. Act on \`code\`, never on \`message\`, which is the code's public description and may be reworded. The codes and their meanings are the \`code\` schema in this document.

## Rate limits

Requests are counted per minute: per client address, per signed-in person, per agent and per organisation. Over a limit the answer is 429 ${code('RATE_LIMITED')}, with \`Retry-After\` in seconds and the \`X-RateLimit-*\` headers. Wait that long, then send the same request again, with the same Idempotency-Key. A 503 that says the organisation or platform is busy carries Retry-After too.

## Correlation IDs

Every answer carries an \`X-Correlation-Id\` header (\`${CORRELATION_HEADER}\`), and every error body its \`correlationId\`. Send your own UUID in the header to have it used. Quote it when you contact support.`;

/** The parts of an operation the document's own reads. */
const OPERATION = z.looseObject({
  'x-access': z.array(z.string()),
  'x-agent-scopes': z.array(z.string()).optional(),
  'x-partner-signed': z.literal(true).optional(),
  responses: z.record(z.string(), z.unknown()),
});

type Requirement = Readonly<Record<string, readonly string[]>>;

/**
 * Who may call an operation, as OpenAPI security. A route names agents alone
 * or no agents (access.ts), so one scheme does: the partner's signature on its
 * own route, nothing on any other public one, an agent's key with its scopes,
 * or a person's session. An operator's sign-in has no scheme here yet: an
 * operation for operators stops the document, rather than show it open.
 */
export function securityOf(
  access: readonly string[],
  agentScopes: readonly string[] | undefined,
  partnerSigned: boolean,
): Requirement[] {
  if (partnerSigned) return [{ [PARTNER_SIGNATURE_SCHEME]: [] }];
  if (access.includes('public')) return [];
  if (access.includes('operator')) {
    throw new Error("an operator's operation can't be documented: the document has no scheme for operators' sign-in");
  }
  return access.includes('agent') ? [{ [AGENT_KEY_SCHEME]: agentScopes ?? [] }] : [{ [SESSION_SCHEME]: [] }];
}

/**
 * An operation with its security, tag and 429 answer. One without its access
 * is left as it is: a later hook rebuilt its route's schema, which the
 * contract reports by name (contract.ts), so nothing is shown open to anyone.
 */
function guided(path: string, value: unknown): unknown {
  const parsed = OPERATION.safeParse(value);
  if (!parsed.success) return value;
  const operation = parsed.data;
  // Spread from the operation itself, not zod's copy: its x-agent-scopes stays the frozen list the route was added with.
  const original = value as typeof operation;
  return {
    ...original,
    tags: tagsOf(path),
    security: securityOf(operation['x-access'], operation['x-agent-scopes'], operation['x-partner-signed'] === true),
    responses: { ...original.responses, 429: { $ref: `#/components/responses/${RATE_LIMITED_RESPONSE}` } },
  };
}

interface Document {
  readonly info?: object | undefined;
  readonly components?: object | undefined;
  readonly paths?: Readonly<Record<string, object | undefined>> | undefined;
}

/** The document with what an integrator reads first (see the top of this file). */
export function withGuide<D extends Document>(document: D) {
  const paths = Object.fromEntries(
    Object.entries(document.paths ?? {}).map(([path, item]) => [
      path,
      Object.fromEntries(Object.entries(item ?? {}).map(([method, value]) => [method, guided(path, value)])),
    ]),
  );
  return {
    ...document,
    info: { ...document.info, description: DESCRIPTION },
    externalDocs: { description: 'The guide for agent builders', url: GUIDE_URL },
    tags: TAGS.map(({ name, description }) => ({ name, description })),
    components: {
      ...document.components,
      securitySchemes: {
        [SESSION_SCHEME]: {
          type: 'apiKey',
          in: 'cookie',
          name: SESSION_COOKIE,
          description: "A person's session, set when they sign in through the console.",
        },
        [AGENT_KEY_SCHEME]: {
          type: 'http',
          scheme: 'bearer',
          description: `An AI agent's key, \`${KEY_FORM}\`, shown once in the console when the agent is registered or its key is rotated.`,
        },
        // The stand-in partner's header, the one partner built so far: a real partner's adapter names its own.
        [PARTNER_SIGNATURE_SCHEME]: {
          type: 'apiKey',
          in: 'header',
          name: FAKE_SIGNATURE_HEADER,
          description:
            "The licensed partner's signature over the message's raw body, with the time it was signed. A message whose signature doesn't hold is refused. Until a real partner is connected, this is the stand-in partner's header; the real partner's adapter names its own.",
        },
      },
      headers: Object.fromEntries(
        RATE_LIMIT_HEADERS.map((name) => [
          name,
          { description: RATE_LIMIT_HEADER_TEXT[name], schema: { type: 'integer' } },
        ]),
      ),
      responses: {
        [RATE_LIMITED_RESPONSE]: {
          description:
            'Over a rate limit (RATE_LIMITED). Wait the Retry-After seconds, then send the same request again.',
          headers: Object.fromEntries(
            RATE_LIMIT_HEADERS.map((name) => [name, { $ref: `#/components/headers/${name}` }]),
          ),
          content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } },
        },
      },
    },
    paths,
  };
}
