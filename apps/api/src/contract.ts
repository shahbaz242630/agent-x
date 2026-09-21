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
// - Each route declares its answers for success, as zod objects that name all
//   they carry, at every depth, and each route that takes a body sets its own
//   limit for it, which the document shows as x-body-limit.
// - An object answer goes out only through the schema its route declares for
//   its status, as JSON; one without is a failure on our side, never sent.
// - An answer leaves only as the contract wrote it, byte for byte
//   (written-answers.ts): a string, bytes or a stream a route sent itself, or
//   anything a hook put in its place, is a failure on our side; an empty
//   answer leaves only at a status its route declares.
// - A route the document couldn't describe truthfully is refused as it is
//   added, and every route is checked again once every plugin's hooks have
//   run. Then the routes served are compared with the document: a route
//   missing from it (hidden, or for any other reason), or served twice,
//   stops the API starting.
// The document is kept in the repository as apps/api/openapi.json, and
// contract.test.ts fails when the two differ.
import swagger, { formatParamUrl } from '@fastify/swagger';
import type {
  FastifyInstance,
  FastifyRequest,
  FastifySchema,
  onSendHookHandler,
  preSerializationHookHandler,
  RouteOptions,
} from 'fastify';
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
import { aboutToWrite, recordingWrites, writtenText } from './written-answers.ts';

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
const BODILESS_METHODS: ReadonlySet<string> = new Set(['GET', 'HEAD', 'TRACE']);

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

/** Answer parts that carry a value of their own and nothing beyond it. */
const NAMED_LEAVES: ReadonlySet<string> = new Set([
  'string',
  'number',
  'boolean',
  'null',
  'literal',
  'enum',
  'template_literal',
]);

/**
 * Where an answer's zod schema lets through what it doesn't name, each as a
 * path into it. The schema is walked, not the document: the serializer runs
 * zod, and the document can show a part tighter than zod sends it (a union's
 * "anything" member left out, a codec's other side, an intersection's map).
 * Only these pass: objects closed to fields they don't name, lists, tuples,
 * unions, optional, nullable or read-only parts, lazy parts, maps whose keys
 * are a fixed list, and the named leaves.
 */
function unnamedParts(schema: z.core.$ZodType, at: string, seen: Set<z.core.$ZodType>): string[] {
  if (seen.has(schema)) return [];
  seen.add(schema);
  const walk = (child: z.core.$ZodType, where: string): string[] => unnamedParts(child, where, seen);
  if (schema instanceof z.ZodObject) {
    const { catchall } = schema._zod.def;
    const open =
      catchall === undefined || catchall instanceof z.ZodNever ? [] : [`${at} (open to fields it doesn't name)`];
    const shape: Readonly<Record<string, z.core.$ZodType>> = schema._zod.def.shape;
    return [...open, ...Object.entries(shape).flatMap(([name, field]) => walk(field, `${at}.${name}`))];
  }
  if (schema instanceof z.ZodArray) return walk(schema.element, `${at}[]`);
  if (schema instanceof z.ZodTuple) {
    const { items, rest } = schema._zod.def;
    return [
      ...items.flatMap((item, index) => walk(item, `${at}[${String(index)}]`)),
      ...(rest === null ? [] : walk(rest, `${at}[rest]`)),
    ];
  }
  if (schema instanceof z.ZodUnion) return schema.options.flatMap((option) => walk(option, at));
  if (schema instanceof z.ZodOptional || schema instanceof z.ZodNullable || schema instanceof z.ZodReadonly) {
    return walk(schema._zod.def.innerType, at);
  }
  // The inner schema zod caches and parses with, not a fresh call of its getter, which could differ.
  if (schema instanceof z.ZodLazy) return walk(schema._zod.innerType, at);
  if (schema instanceof z.ZodRecord) {
    const { keyType, valueType } = schema._zod.def;
    const loose = 'mode' in schema._zod.def && schema._zod.def.mode === 'loose';
    const fixedKeys = (keyType instanceof z.ZodEnum || keyType instanceof z.ZodLiteral) && !loose;
    return [...(fixedKeys ? [] : [`${at} (a map whose keys aren't a fixed list)`]), ...walk(valueType, `${at}.*`)];
  }
  return NAMED_LEAVES.has(schema._zod.def.type) ? [] : [`${at} (${schema._zod.def.type})`];
}

/**
 * An object answer with no schema for its status, or not sent as JSON: Fastify
 * would write it whole, or a serializer of the reply's own would, so it is a
 * failure on our side instead.
 */
class AnswerUndeclared extends Error {
  constructor(route: string, status: number) {
    super(`${route} answered ${String(status)} with an object it declares no schema for, or not as JSON`);
    this.name = 'AnswerUndeclared';
  }
}

const keysOf = (value: unknown): string[] => (typeof value === 'object' && value !== null ? Object.keys(value) : []);

/**
 * Whether the request's route declares an answer for the status, as Fastify
 * looks it up: the status, then its range. `own` counts only the route's own
 * answers, not the error body it answers every 4xx and 5xx with.
 */
function isDeclared(request: FastifyRequest, statusCode: number, own = false): boolean {
  const declared = new Set(
    keysOf(request.routeOptions.schema?.response)
      .filter((key) => !own || (!isErrorRange(key) && !isErrorPathStatus(key)))
      .map((key) => key.toLowerCase()),
  );
  const status = String(statusCode);
  return declared.has(status) || declared.has(`${status.charAt(0)}xx`);
}

/** The zod serializer, recording what it writes for the reply it writes it for (written-answers.ts). */
const recordingSerializerCompiler: typeof serializerCompiler = (route) => recordingWrites(serializerCompiler(route));

/**
 * An object answer goes out only through the schema its route declares for its
 * status (as Fastify looks it up: the status, then its range), as JSON. The
 * contract adds it as each route's last preSerialization hook, so no hook after
 * it can change the status or the type. Fastify sets the JSON type before these
 * hooks run, so an answer without it has a serializer of the reply's own.
 * Error answers are text already; objects Fastify sends as bytes or a stream
 * never reach it.
 */
const answerGuard: preSerializationHookHandler = (request, reply, payload, done) => {
  const type = reply.getHeader('content-type');
  const json = typeof type === 'string' && /^application\/json\s*(?:;|$)/i.test(type);
  if (json && isDeclared(request, reply.statusCode)) {
    aboutToWrite(reply, payload);
    done(null, payload);
    return;
  }
  done(new AnswerUndeclared(`${request.method} ${request.routeOptions.url ?? request.url}`, reply.statusCode));
};

/** An answer the contract didn't write: a string, bytes or a stream a route sent itself. */
class AnswerUnwritten extends Error {
  constructor(route: string, status: number) {
    super(`${route} answered ${String(status)} with a body the contract didn't write`);
    this.name = 'AnswerUnwritten';
  }
}

/** Closes a stream a refused answer would have sent, so it holds nothing open (a file, say). */
function closeRefused(payload: unknown): void {
  if (
    typeof payload === 'object' &&
    payload !== null &&
    'destroy' in payload &&
    typeof payload.destroy === 'function'
  ) {
    (payload.destroy as () => void).call(payload);
  }
}

/**
 * An answer leaves only as the contract wrote it, byte for byte
 * (written-answers.ts), or empty at a status its route declares. The contract
 * adds it as each route's last onSend hook, after Fastify's own that empties a
 * HEAD answer, and at the root for the not-found path; it compares the payload
 * as it now stands, so whatever an earlier hook put in its place is refused.
 */
const answerLeaves: onSendHookHandler = (request, reply, payload, done) => {
  const recorded = writtenText(reply);
  // Empty, an answer carries nothing: at a status its route declares an answer of its own for (a
  // redirect, say), or once the contract wrote it and Fastify's own HEAD hook emptied it. Not at a
  // 4xx or 5xx, which the document says carries the error body.
  const empty = payload === undefined || payload === null || payload === '';
  const exact = recorded !== undefined && payload === recorded;
  if (exact || (empty && (recorded !== undefined || isDeclared(request, reply.statusCode, true)))) {
    done(null, payload);
    return;
  }
  closeRefused(payload);
  // A refusal or failure a hook rewrote goes out as the contract wrote it: refusing it
  // again would leave Fastify's own last answer, which shows the error's message.
  if (recorded !== undefined && reply.statusCode >= 400) {
    done(null, recorded);
    return;
  }
  done(new AnswerUnwritten(`${request.method} ${request.routeOptions.url ?? request.url}`, reply.statusCode));
};

/**
 * The contract's checks for the not-found path, which is no route: Fastify runs
 * a not-found handler's own hooks after every root hook, as it does a route's
 * (four-oh-four.js takes every lifecycle hook, though its types list only two).
 */
export const NOT_FOUND_CHECKS: object = Object.freeze({
  preSerialization: Object.freeze([answerGuard]),
  onSend: Object.freeze([answerLeaves]),
});

/**
 * Only the contract puts a hook between an answer being written and it
 * leaving. An onSend hook on the server or a plugin could rewrite an answer
 * after the check, or throw and leave Fastify's own last answer, which shows
 * the error's message; a not-found handler without the contract's checks would
 * answer unchecked. Refused as they are added, from here on, by every plugin
 * (each inherits the server's methods), third-party ones included.
 */
function guardWhatLeaves(app: FastifyInstance): void {
  // Kept to call on whichever instance calls the guard, with that instance as this.
  // eslint-disable-next-line @typescript-eslint/unbound-method -- applied with the calling instance below
  const addHook = app.addHook;
  // eslint-disable-next-line @typescript-eslint/unbound-method -- applied with the calling instance below
  const setNotFoundHandler = app.setNotFoundHandler;
  const guardedAddHook = function (this: FastifyInstance, ...args: unknown[]): unknown {
    if (args[0] === 'onSend') {
      throw new ContractBroken([
        "an onSend hook on the server or a plugin could rewrite an answer after the contract's check",
      ]);
    }
    return Reflect.apply(addHook, this, args);
  };
  const guardedSetNotFoundHandler = function (this: FastifyInstance, ...args: unknown[]): unknown {
    // Without a handler of its own, Fastify would answer with its own.
    if (args[0] !== NOT_FOUND_CHECKS || typeof args[1] !== 'function') {
      throw new ContractBroken(["a not-found handler must carry the contract's checks (NOT_FOUND_CHECKS)"]);
    }
    return Reflect.apply(setNotFoundHandler, this, args);
  };
  app.addHook = guardedAddHook as unknown as FastifyInstance['addHook'];
  app.setNotFoundHandler = guardedSetNotFoundHandler as unknown as FastifyInstance['setNotFoundHandler'];
}

/** Fastify's own onSend hook on a HEAD route, which empties the answer. */
const isHeadEmptier = (hook: unknown): boolean => typeof hook === 'function' && hook.name === 'headRouteOnSendHandler';

/** A route's own hooks of one kind, as a list. */
const hooksOf = <T>(hooks: T | readonly T[] | undefined): readonly T[] =>
  hooks === undefined ? [] : Array.isArray(hooks) ? hooks : [hooks as T];

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

/**
 * Why the document couldn't describe a route truthfully, if it couldn't. Once
 * `written`, what the contract wrote into its schema must still be there: a
 * later hook that rebuilt the schema would drop it from the document.
 */
function routeProblems(route: AddedRoute, instance: FastifyInstance, written: boolean): string[] {
  const problems: string[] = [];
  const schema = route.schema ?? {};
  const keys = new Map<string, unknown>(Object.entries(schema));
  const declared = new Map<string, unknown>(Object.entries(responsesOf(route)));
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
    } else if (schemas.length === 0) {
      problems.push(`its ${status} response names no content type`);
    } else if (!schemas.every((entry) => entry instanceof z.ZodType)) {
      problems.push(`its ${status} response schema is not a zod schema`);
    } else if (isErrorPathStatus(status) && !schemas.every((entry) => entry === ERROR_BODY)) {
      problems.push(`its ${status} answer is not the one error body, which is what the API sends for ${status}`);
    }
  }
  if (written && ![...OUR_ERROR_RESPONSES].every((ours) => [...declared.values()].includes(ours))) {
    problems.push("its error answers are not the contract's");
  }
  if (written && hooksOf(route.preSerialization).at(-1) !== answerGuard) {
    problems.push("a preSerialization hook runs after the contract's check of its answers");
  }
  const sendHooks = hooksOf(route.onSend);
  if (written && sendHooks.at(-1) !== answerLeaves) {
    problems.push("an onSend hook runs after the contract's check of what leaves");
  }
  const ownSendHooks = written ? sendHooks.slice(0, -1) : sendHooks;
  // A route of HEAD alone may have Fastify's own; any other rewrite is refused as the answer leaves anyway.
  const headsOnly = route.method === 'HEAD' && ownSendHooks.length === 1;
  if (!ownSendHooks.every((hook) => headsOnly && isHeadEmptier(hook))) {
    problems.push('it rewrites its answers after they are written (onSend)');
  }
  // Allowlisted answers: every answer a route declares, but the one error body, names all it
  // carries, so nothing it doesn't name leaves: a success, or a 5xx of its own (health's 503).
  const answers = [...declared].filter(([status]) => !isErrorRange(status) && !isErrorPathStatus(status));
  if (!answers.some(([status]) => isSuccessStatus(status))) {
    problems.push('it declares no answer for success (a response below 400)');
  }
  for (const [status, response] of answers) {
    if (!(response instanceof z.ZodObject)) {
      problems.push(`its ${status} answer is not an object with named fields, declared as its schema itself`);
      continue;
    }
    const unnamed = unnamedParts(response, 'answer', new Set());
    if (unnamed.length > 0)
      problems.push(`its ${status} answer lets through what it doesn't name: ${unnamed.join(', ')}`);
  }
  if (takesBody(route) && !isBodyLimit(route.bodyLimit)) {
    problems.push(`it takes a body but sets no limit of its own for it (bodyLimit, 1 to ${BODY_LIMIT_BYTES} bytes)`);
  }
  if (
    (written || keys.has(BODY_LIMIT_KEY)) &&
    keys.get(BODY_LIMIT_KEY) !== (takesBody(route) ? route.bodyLimit : undefined)
  ) {
    problems.push('the body limit its document shows is not its own (x-body-limit)');
  }
  problems.push(...accessProblems(route.config?.access, route.url));
  // The document shows the access the contract wrote from the route's own; a route
  // can't write another, and a later hook that swapped the route's own would part the two.
  if ((written || keys.has(ACCESS_KEY)) && keys.get(ACCESS_KEY) !== route.config?.access) {
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
  if (instance.validatorCompiler !== validatorCompiler || instance.serializerCompiler !== recordingSerializerCompiler) {
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
  app.setSerializerCompiler(recordingSerializerCompiler);
  guardWhatLeaves(app);

  const added: { readonly route: AddedRoute; readonly instance: FastifyInstance }[] = [];
  app.addHook('onRoute', function (route) {
    const problems = routeProblems(route, this, false);
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
    route.preSerialization = [...hooksOf(route.preSerialization), answerGuard];
    route.onSend = [...hooksOf(route.onSend), answerLeaves];
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
    const problems = [
      ...added.flatMap(({ route, instance }) => routeProblems(route, instance, true)),
      ...routeTableProblems(served, app.swagger()),
    ];
    done(problems.length > 0 ? new ContractBroken(problems) : undefined);
  });
}
