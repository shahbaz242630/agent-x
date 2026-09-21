// SEC-WEB-06 (threat WEB-6, ADR-012 §10): the API's contract is its OpenAPI
// document, generated from each route's own zod schemas, and the API serves
// nothing the document doesn't hold.
// - Each route checks and answers through its zod schemas: input outside them
//   is refused as BAD_REQUEST, and an answer is cut down to the fields its
//   schema names, so a field a route didn't declare never leaves.
// - Each route answers a refusal or a failure with the one error body
//   (errors.ts), which the document names once, with every reason code.
// - Once the server is ready, the routes it serves are compared with the
//   document. A route missing from it, hidden or for any other reason, stops
//   the API starting; so does a route the document can't describe.
// The document is kept in the repository as apps/api/openapi.json, and
// contract.test.ts fails when the two differ.
import swagger, { formatParamUrl } from '@fastify/swagger';
import type { FastifyInstance, RouteOptions } from 'fastify';
import {
  createJsonSchemaTransform,
  createJsonSchemaTransformObject,
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { z } from 'zod';

import { API_SCHEMAS } from './api-schemas.ts';
import { ERROR_BODY } from './errors.ts';

/** The methods an OpenAPI path can hold. A route served with any other can't be documented. */
const OPENAPI_METHODS = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace'] as const;

const COMPONENT_PREFIX = '#/components/schemas/';

/**
 * A schema the document can't describe (a Date, the output of a transform)
 * stops it being written, rather than being documented as "anything".
 */
const ZOD_TO_JSON = { unrepresentable: 'throw' } as const;

/** Every route's refusals and failures, in the one error body. */
const ERROR_RESPONSES = {
  '4xx': {
    description: 'Refused. The reason code says why.',
    content: { 'application/json': { schema: ERROR_BODY } },
  },
  '5xx': {
    description: 'Failed on our side. Quote the correlation ID if you contact support.',
    content: { 'application/json': { schema: ERROR_BODY } },
  },
};

/** The response keys that would give a route an error body of its own. */
const isErrorRange = (status: string): boolean => /^[45]xx$/i.test(status) || status === 'default';

/** The API's routes and its OpenAPI document differ, or a route can't be documented. */
export class ContractBroken extends Error {
  readonly problems: readonly string[];

  constructor(problems: readonly string[]) {
    super(`The API breaks its OpenAPI contract: ${problems.join('; ')}`);
    this.name = 'ContractBroken';
    this.problems = problems;
  }
}

const methodsOf = (route: RouteOptions): readonly string[] =>
  typeof route.method === 'string' ? [route.method] : route.method;

/** A route's responses by status, or none. */
function responsesOf(route: RouteOptions): object {
  const responses: unknown = route.schema?.response;
  return typeof responses === 'object' && responses !== null ? responses : {};
}

/** The schemas a response entry holds: itself, or one for each content type. */
function responseSchemas(response: unknown): unknown[] {
  if (typeof response === 'object' && response !== null && 'content' in response) {
    const { content } = response;
    if (typeof content === 'object' && content !== null) {
      return Object.values(content).map((entry: unknown) =>
        typeof entry === 'object' && entry !== null && 'schema' in entry ? entry.schema : undefined,
      );
    }
  }
  return [response];
}

/** Why the document couldn't describe a route truthfully, if it couldn't. */
function routeProblems(route: RouteOptions): string[] {
  const problems: string[] = [];
  const schema = route.schema ?? {};
  for (const part of ['body', 'querystring', 'params', 'headers'] as const) {
    if (schema[part] !== undefined && !(schema[part] instanceof z.ZodType)) {
      problems.push(`its ${part} schema is not a zod schema`);
    }
  }
  for (const [status, response] of Object.entries(responsesOf(route))) {
    if (isErrorRange(status)) {
      problems.push(`it sets its own ${status} response, but every error has the one error body`);
    } else if (!responseSchemas(response).every((entry) => entry instanceof z.ZodType)) {
      problems.push(`its ${status} response schema is not a zod schema`);
    }
  }
  // A route of its own transform could show the document another schema than the one it runs.
  if (route.config !== undefined && 'swaggerTransform' in route.config) {
    problems.push('it changes how the document shows it (swaggerTransform)');
  }
  return problems.map((problem) => `${methodsOf(route).join(',')} ${route.url}: ${problem}`);
}

/** Routes served but not documented, and documented but not served, each as "METHOD /path". */
export function routeTableProblems(
  served: readonly string[],
  document: { readonly paths?: Readonly<Record<string, object | undefined>> | undefined },
): string[] {
  const documented = Object.entries(document.paths ?? {}).flatMap(([path, item]) =>
    OPENAPI_METHODS.filter((method) => item !== undefined && method in item).map(
      (method) => `${method.toUpperCase()} ${path}`,
    ),
  );
  const inDocument = new Set(documented);
  const onServer = new Set(served);
  return [
    ...[...onServer].filter((route) => !inDocument.has(route)).map((route) => `${route} is served but not documented`),
    ...documented.filter((route) => !onServer.has(route)).map((route) => `${route} is documented but not served`),
  ];
}

interface WithSchemas {
  readonly paths?: unknown;
  readonly components?: { readonly schemas?: Readonly<Record<string, unknown>> | undefined } | undefined;
}

/**
 * The document without the named schemas nothing refers to. The zod provider
 * writes an input and an output form of every named schema, and most are used
 * only one way: the error body is only ever an answer.
 */
export function withoutUnusedSchemas<D extends WithSchemas>(
  document: D,
): D & { readonly components: { readonly schemas: Readonly<Record<string, unknown>> } } {
  const schemas = document.components?.schemas ?? {};
  const used = new Set<string>();
  const visit = (value: unknown): void => {
    if (typeof value !== 'object' || value === null) return;
    for (const [key, child] of Object.entries(value)) {
      if (key === '$ref' && typeof child === 'string' && child.startsWith(COMPONENT_PREFIX)) {
        const name = child.slice(COMPONENT_PREFIX.length);
        if (!used.has(name)) {
          used.add(name);
          visit(schemas[name]);
        }
      } else {
        visit(child);
      }
    }
  };
  visit(document.paths);
  return {
    ...document,
    components: {
      ...document.components,
      schemas: Object.fromEntries(Object.entries(schemas).filter(([name]) => used.has(name))),
    },
  };
}

/**
 * Makes zod the way every route checks and answers, and registers the OpenAPI
 * document. Call it before any route is added: a route added earlier would
 * escape both.
 */
export async function registerContract(app: FastifyInstance): Promise<void> {
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);

  const served: string[] = [];
  app.addHook('onRoute', (route) => {
    const problems = routeProblems(route);
    if (problems.length > 0) throw new ContractBroken(problems);
    route.schema = { ...route.schema, response: { ...responsesOf(route), ...ERROR_RESPONSES } };
    served.push(...methodsOf(route).map((method) => `${method} ${formatParamUrl(route.url)}`));
  });

  const transformObject = createJsonSchemaTransformObject({
    schemaRegistry: API_SCHEMAS,
    zodToJsonConfig: ZOD_TO_JSON,
  });
  await app.register(swagger, {
    openapi: {
      openapi: '3.1.0',
      // The API's major version, as in its /v1 addresses (PRD §7.1).
      info: { title: 'Agent X API', version: '1' },
    },
    // Fastify answers HEAD on every GET route, so the document lists those too.
    exposeHeadRoutes: true,
    transform: createJsonSchemaTransform({ schemaRegistry: API_SCHEMAS, skipList: [], zodToJsonConfig: ZOD_TO_JSON }),
    transformObject: (document) => withoutUnusedSchemas(transformObject(document)),
  });

  // After the document's own ready hook, which collects what it needs first.
  // Fastify takes anything thrown here, writing the document included, as the error.
  app.addHook('onReady', (done) => {
    const problems = routeTableProblems(served, app.swagger());
    done(problems.length > 0 ? new ContractBroken(problems) : undefined);
  });
}
