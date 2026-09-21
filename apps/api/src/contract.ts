// SEC-WEB-06 (threat WEB-6, ADR-012 §10): the API's contract is its OpenAPI
// document, generated from each route's own zod schemas, and the API serves
// nothing the document doesn't hold.
// - Each route checks its input through its zod schemas: input outside them
//   is refused as BAD_REQUEST before the route runs. An object answer with a
//   schema for its status is written through it, cut down to the fields it
//   names; a string or a Buffer is sent as it is.
// - Each route answers a refusal or a failure with the one error body
//   (errors.ts), which the document names once, with every reason code.
// - Each route names who may call it (access.ts), which the document shows as
//   x-access on each of its operations.
// - Each route declares its answers for success, as objects that name every
//   field they carry, at every depth, and each route that takes a body sets its
//   own limit for it, which the document shows as x-body-limit.
// - A route the document couldn't describe truthfully is refused as it is
//   added, and every route is checked again once every plugin's hooks have
//   run. Then the routes served are compared with the document: a route
//   missing from it (hidden, or for any other reason), or served twice,
//   stops the API starting.
// The document is kept in the repository as apps/api/openapi.json, and
// contract.test.ts fails when the two differ.
import swagger, { formatParamUrl } from '@fastify/swagger';
import type { FastifyInstance, FastifySchema, RouteOptions } from 'fastify';
import {
  createJsonSchemaTransform,
  createJsonSchemaTransformObject,
  serializerCompiler,
  validatorCompiler,
} from 'fastify-type-provider-zod';
import { z } from 'zod';

import { accessProblems } from './access.ts';
import { API_SCHEMAS } from './api-schemas.ts';
import { ERROR_BODY } from './errors.ts';

/** The methods an OpenAPI path can hold. A route served with any other can't be documented. */
const OPENAPI_METHODS = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace'] as const;

const COMPONENT_PREFIX = '#/components/schemas/';

/** Where each operation shows who may call it; the swagger plugin copies `x-` keys of a route's schema into it. */
const ACCESS_KEY = 'x-access';

/** Where each operation that takes a body shows the most it reads. */
const BODY_LIMIT_KEY = 'x-body-limit';

/** The most any request body may be: the server's own limit, and the most a route may set for itself. */
export const BODY_LIMIT_BYTES = 64 * 1024;

/** Methods whose requests Fastify reads no body for. */
const BODILESS_METHODS: ReadonlySet<string> = new Set(['GET', 'HEAD']);

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

/** Recognised by identity, so a route can't pass off error responses of its own as these. */
const OUR_ERROR_RESPONSES: ReadonlySet<unknown> = new Set(Object.values(ERROR_RESPONSES));

/** The response keys that would give a route an error body of its own. */
const isErrorRange = (status: string): boolean => /^[45]xx$/i.test(status) || status === 'default';

/**
 * The statuses the error path answers with (errors.ts: every 4xx, and 500). A
 * route may name one to say when it is sent, but only with the one error body:
 * the error path never writes through a route's schemas.
 */
const isErrorPathStatus = (status: string): boolean => /^(?:4[0-9][0-9]|500)$/.test(status);

/** A success answer's status, or range of statuses: anything below 400. */
const isSuccessStatus = (status: string): boolean => /^[1-3](?:[0-9][0-9]|xx)$/i.test(status);

/**
 * Route options that would check input, or write answers or errors, other
 * than through the contract. A plugin's own compilers are checked too.
 */
const BYPASSES = ['attachValidation', 'validatorCompiler', 'serializerCompiler', 'errorHandler'] as const;

/** A route as its onRoute hook sees it. */
type AddedRoute = RouteOptions & { readonly routePath: string; readonly prefix: string };

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

const takesBody = (route: RouteOptions): boolean => methodsOf(route).some((method) => !BODILESS_METHODS.has(method));

const isBodyLimit = (limit: unknown): boolean =>
  typeof limit === 'number' && Number.isInteger(limit) && limit >= 1 && limit <= BODY_LIMIT_BYTES;

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
function routeProblems(route: AddedRoute, instance: FastifyInstance): string[] {
  const problems: string[] = [];
  const schema = route.schema ?? {};
  for (const part of ['body', 'querystring', 'params', 'headers'] as const) {
    if (schema[part] !== undefined && !(schema[part] instanceof z.ZodType)) {
      problems.push(`its ${part} schema is not a zod schema`);
    }
  }
  for (const [status, response] of Object.entries(responsesOf(route))) {
    const schemas = responseSchemas(response);
    if (isErrorRange(status)) {
      if (!OUR_ERROR_RESPONSES.has(response)) {
        problems.push(`it sets its own ${status} response, but every error has the one error body`);
      }
    } else if (!schemas.every((entry) => entry instanceof z.ZodType)) {
      problems.push(`its ${status} response schema is not a zod schema`);
    } else if (isErrorPathStatus(status) && !schemas.every((entry) => entry === ERROR_BODY)) {
      problems.push(`its ${status} answer is not the one error body, which is what the API sends for ${status}`);
    }
  }
  // Allowlisted answers: a success answer names its fields, so nothing it doesn't name leaves.
  const successes = Object.entries(responsesOf(route)).filter(([status]) => isSuccessStatus(status));
  if (successes.length === 0) problems.push('it declares no answer for success (a response below 400)');
  for (const [status, response] of successes) {
    if (!responseSchemas(response).every((entry) => entry instanceof z.ZodObject)) {
      problems.push(`its ${status} answer is not an object with named fields`);
    }
  }
  if (takesBody(route) && !isBodyLimit(route.bodyLimit)) {
    problems.push(`it takes a body but sets no limit of its own for it (bodyLimit, 1 to ${BODY_LIMIT_BYTES} bytes)`);
  }
  if (BODY_LIMIT_KEY in schema && schema[BODY_LIMIT_KEY] !== (takesBody(route) ? route.bodyLimit : undefined)) {
    problems.push('the body limit its document shows is not its own (x-body-limit)');
  }
  problems.push(...accessProblems(route.config?.access, route.url));
  // The document shows the access the contract wrote from the route's own; a route
  // can't write another, and a later hook that swapped the route's own would part the two.
  if (ACCESS_KEY in schema && schema[ACCESS_KEY] !== route.config?.access) {
    problems.push('the access its document shows is not its own (x-access)');
  }
  // A route of its own transform could show the document another schema than the one it runs.
  if (route.config !== undefined && 'swaggerTransform' in route.config) {
    problems.push('it changes how the document shows it (swaggerTransform)');
  }
  for (const option of BYPASSES) {
    if (route[option] !== undefined && route[option] !== false) {
      problems.push(`it sets ${option}, so it would check or answer other than through its schemas`);
    }
  }
  if (instance.validatorCompiler !== validatorCompiler || instance.serializerCompiler !== serializerCompiler) {
    problems.push('its plugin checks or writes through compilers other than zod');
  }
  // A twin of a documented route, served only for some hosts or versions, would never show.
  if (route.constraints !== undefined) {
    problems.push("it is served only for some hosts or versions (constraints), which the document can't show");
  }
  // Fastify serves such a route at both /prefix and /prefix/, and tells the hooks of the first alone.
  // A route at '' is served once, but its hooks can't tell it from one at '/', so it must say so too.
  if (route.prefix !== '' && route.routePath === '' && (route.prefixTrailingSlash ?? 'both') === 'both') {
    problems.push("it sits at its prefix's root: set prefixTrailingSlash to 'no-slash' or 'slash'");
  }
  return problems.map((problem) => `${methodsOf(route).join(',')} ${route.url}: ${problem}`);
}

/**
 * Routes served but not documented, documented but not served, and served by
 * more than one route (a twin the document shows as one), each as "METHOD /path".
 */
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
  const twins = new Set(served.filter((route, index) => served.indexOf(route) !== index));
  return [
    ...[...onServer].filter((route) => !inDocument.has(route)).map((route) => `${route} is served but not documented`),
    ...documented.filter((route) => !onServer.has(route)).map((route) => `${route} is documented but not served`),
    ...[...twins].map((route) => `${route} is served by more than one route`),
  ];
}

const isRecord = (value: unknown): value is Readonly<Record<string, unknown>> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/** The keywords by which a JSON Schema says anything about a value: one with none of them takes anything. */
const CONSTRAINING = [
  'type',
  'const',
  'enum',
  '$ref',
  'anyOf',
  'oneOf',
  'allOf',
  'not',
  'properties',
  'items',
  'prefixItems',
  'additionalProperties',
];

/**
 * Where a schema lets through what it doesn't describe, each as a path into
 * it: a value that could be anything, or an object with fields beyond those it
 * names. A map (no named fields, every value of one schema) names its values,
 * so it passes when they do.
 */
function looseParts(
  schema: unknown,
  at: string,
  components: Readonly<Record<string, unknown>>,
  seen: Set<string>,
): string[] {
  if (!isRecord(schema) || !CONSTRAINING.some((key) => key in schema)) return [at];
  const walk = (child: unknown, where: string): string[] => looseParts(child, where, components, seen);
  if (typeof schema.$ref === 'string') {
    if (!schema.$ref.startsWith(COMPONENT_PREFIX)) return [at];
    const name = schema.$ref.slice(COMPONENT_PREFIX.length);
    if (seen.has(name)) return [];
    seen.add(name);
    return walk(components[name], schema.$ref);
  }
  const parts: string[] = [];
  if (isRecord(schema.properties)) {
    if (schema.additionalProperties !== false) parts.push(`${at}.additionalProperties`);
    for (const [name, property] of Object.entries(schema.properties)) {
      parts.push(...walk(property, `${at}.properties.${name}`));
    }
  } else if (schema.type === 'object' || 'additionalProperties' in schema) {
    parts.push(...walk(schema.additionalProperties, `${at}.additionalProperties`));
  }
  if ('items' in schema && schema.items !== false) parts.push(...walk(schema.items, `${at}.items`));
  for (const key of ['prefixItems', 'anyOf', 'oneOf', 'allOf']) {
    const list = schema[key];
    if (Array.isArray(list))
      list.forEach((entry, index) => parts.push(...walk(entry, `${at}.${key}[${String(index)}]`)));
  }
  return parts;
}

/**
 * Every success answer in the document that lets through what it doesn't
 * name, at any depth: a field that could be anything, or an object open to
 * fields it doesn't list. A route's own check sees only the top of its answer.
 */
export function looseAnswers(document: unknown): string[] {
  if (!isRecord(document) || !isRecord(document.paths)) return [];
  const components =
    isRecord(document.components) && isRecord(document.components.schemas) ? document.components.schemas : {};
  const problems: string[] = [];
  for (const [path, item] of Object.entries(document.paths)) {
    for (const method of OPENAPI_METHODS) {
      const operation = isRecord(item) ? item[method] : undefined;
      const responses = isRecord(operation) ? operation.responses : undefined;
      for (const [status, response] of Object.entries(isRecord(responses) ? responses : {})) {
        const content = isRecord(response) ? response.content : undefined;
        if (!isSuccessStatus(status) || !isRecord(content)) continue;
        for (const media of Object.values(content)) {
          const loose = looseParts(isRecord(media) ? media.schema : undefined, 'answer', components, new Set());
          if (loose.length > 0) {
            problems.push(
              `${method.toUpperCase()} ${path}: its ${status} answer lets through what it doesn't name (${loose.join(', ')})`,
            );
          }
        }
      }
    }
  }
  return problems;
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

  const added: { readonly route: AddedRoute; readonly instance: FastifyInstance }[] = [];
  app.addHook('onRoute', function (route) {
    const problems = routeProblems(route, this);
    if (problems.length > 0) throw new ContractBroken(problems);
    // A frozen copy, which the document and the access hook share: neither a change
    // to the document nor to a list the route was given can change who may call it.
    const access = Object.freeze([...(route.config?.access ?? [])]);
    route.config = { ...route.config, access };
    const schema: FastifySchema & Record<typeof ACCESS_KEY, unknown> & Partial<Record<typeof BODY_LIMIT_KEY, number>> =
      {
        ...route.schema,
        [ACCESS_KEY]: access,
        ...(takesBody(route) && route.bodyLimit !== undefined && { [BODY_LIMIT_KEY]: route.bodyLimit }),
        response: { ...responsesOf(route), ...ERROR_RESPONSES },
      };
    route.schema = schema;
    added.push({ route, instance: this });
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
  // Every route again, as it now stands: a plugin's own onRoute hook runs after
  // this one and could have changed it, or its plugin's compilers. Fastify
  // takes anything thrown here, writing the document included, as the error.
  app.addHook('onReady', (done) => {
    const served = added.flatMap(({ route }) =>
      methodsOf(route).map((method) => `${method} ${formatParamUrl(route.url)}`),
    );
    const document = app.swagger();
    const problems = [
      ...added.flatMap(({ route, instance }) => routeProblems(route, instance)),
      ...routeTableProblems(served, document),
      ...looseAnswers(document),
    ];
    done(problems.length > 0 ? new ContractBroken(problems) : undefined);
  });
}
