// 6E2 (BR-20; AG3 SEC-MCP-02): each MCP tool's REST twin, as the API
// registered it. An MCP tool never says for itself who may call it, which
// scopes it needs, what it takes, how it is keyed or what it answers: it reads
// each from its twin's route, as the contract left it (contract.ts), so the
// two can't drift. The recorder is added right after the contract, so it sees
// every route the contract checked, and Fastify runs it as each route is
// added, so the book is whole before the MCP route, added last, reads it.
//
// A twin must be an agent's own route that checks nothing a tool would leave
// out: a route config beyond its access, its scopes and its operation (a
// statement's words, a partner's signature) is a check its tool doesn't make,
// and stops the API starting (mcp.ts).
import { type Scope, SCOPES } from '@agentx/core/modules/agents';
import type { FastifyContextConfig, FastifyInstance, RouteOptions } from 'fastify';
import { z } from 'zod';

/** An agent's REST route, as an MCP tool checks and answers by it. */
export interface Twin {
  readonly method: string;
  readonly url: string;
  /** The scopes a key needs: the route's own frozen list (access.ts). */
  readonly scopes: readonly Scope[];
  /** The write's operation, its idempotency keys' namespace (write-operations.ts); none for a read. */
  readonly operation: string | undefined;
  /** Its one success status, and the schema its answer is written through there (SEC-AG-05). */
  readonly status: number;
  readonly answer: z.ZodType;
  /** Its input schemas, each the one its route checks with; none where it takes none. */
  readonly params: z.ZodType | undefined;
  readonly querystring: z.ZodType | undefined;
  readonly body: z.ZodType | undefined;
  /** The most its body may be, in bytes; none for a read. */
  readonly bodyLimit: number | undefined;
}

/** A twin by its method and address, or why it can't be one. */
export type FindTwin = (method: string, url: string) => Twin | { readonly problems: readonly string[] };

/** The route config a twin may carry: anything else is a check its route makes and its tool wouldn't. */
const TWIN_CONFIG: ReadonlySet<string> = new Set(['access', 'agentScopes', 'operation']);

const SUCCESS = /^2\d\d$/;

const zodOrUndefined = (schema: unknown): z.ZodType | undefined => (schema instanceof z.ZodType ? schema : undefined);

/** The route as a twin, or why it can't be one. */
export function twinOf(route: RouteOptions): Twin | { readonly problems: readonly string[] } {
  const config: FastifyContextConfig = route.config ?? {};
  const { access } = config;
  const problems: string[] = [];
  if (!Array.isArray(access) || access.length !== 1 || access[0] !== 'agent') {
    problems.push("it isn't an agent's own route");
  }
  const extra = Object.keys(config).filter((name) => !TWIN_CONFIG.has(name));
  if (extra.length > 0) problems.push(`its route checks what its tool wouldn't (config.${extra.join(', config.')})`);
  const responses: object = route.schema?.response ?? {};
  const successes = Object.keys(responses).filter((status) => SUCCESS.test(status));
  const [status] = successes;
  const answer = status === undefined ? undefined : zodOrUndefined(Reflect.get(responses, status));
  if (successes.length !== 1 || status === undefined || answer === undefined) {
    problems.push('it has no one success answer with a schema');
  }
  if (problems.length > 0 || status === undefined || answer === undefined) return { problems };
  return {
    method: typeof route.method === 'string' ? route.method : route.method.join(','),
    url: route.url,
    // The contract has checked them (access.ts); read again here for their type.
    scopes: z.array(z.enum(SCOPES)).parse(config.agentScopes ?? []),
    operation: config.operation,
    status: Number(status),
    answer,
    params: zodOrUndefined(route.schema?.params),
    querystring: zodOrUndefined(route.schema?.querystring),
    body: zodOrUndefined(route.schema?.body),
    bodyLimit: route.bodyLimit,
  };
}

/**
 * Records every route as it is added, after the contract's own hook has made it what it serves. Call it right after
 * the contract registers. The finder answers at once, from the route as it now stands.
 */
export function recordTwins(app: FastifyInstance): FindTwin {
  const routes = new Map<string, RouteOptions>();
  app.addHook('onRoute', (route) => {
    const methods = typeof route.method === 'string' ? [route.method] : route.method;
    for (const method of methods) routes.set(`${method} ${route.url}`, route);
  });
  return (method, url) => {
    const route = routes.get(`${method} ${url}`);
    return route === undefined ? { problems: ['the API serves no such route'] } : twinOf(route);
  };
}
