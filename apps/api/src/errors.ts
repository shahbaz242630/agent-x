// SEC-DATA-04 (threat DATA-2): an error response says what kind of problem it
// was and gives the correlation ID. It never carries anything internal: no
// error message, stack or framework code, and no echo of the request. An
// unexpected error is logged with its detail instead. Addresses that don't
// exist, and features that are off, get the same plain 404.
import { isReasonCode, REASON_CODES, type ReasonCode } from '@agentx/core/shared-kernel';
import type { FastifyReply } from 'fastify';
import { z } from 'zod';

import { API_SCHEMAS } from './api-schemas.ts';

/** Each registered code as a value of its own, with its public description, so OpenAPI documents every one (ADR-011 §8). */
const REASON_CODE = z.union(
  Object.keys(REASON_CODES)
    .filter(isReasonCode)
    .map((code) => z.literal(code).register(API_SCHEMAS, { description: REASON_CODES[code] })),
);

/** The body of every error response, named `Error` in the OpenAPI document. */
export const ERROR_BODY = z
  .object({
    error: z.object({
      code: REASON_CODE,
      /** The code's public description. */
      message: z.string(),
      correlationId: z.uuid(),
    }),
  })
  .register(API_SCHEMAS, {
    id: 'Error',
    description:
      "Every refusal and failure has this body: a reason code, the code's public description, and the request's correlation ID. Nothing else.",
  });

export type ErrorBody = z.output<typeof ERROR_BODY>;

export function errorBody(code: ReasonCode, correlationId: string): ErrorBody {
  return { error: { code, message: REASON_CODES[code], correlationId } };
}

/** The content type of an error answer, as Fastify writes it for JSON. */
export const JSON_TYPE = 'application/json; charset=utf-8';

/**
 * Sends an error answer, its body already written out. Fastify sends a string
 * as it is, so neither a route's schema nor a preSerialization hook can reshape
 * the body, or fail to write it and send Fastify's own fallback body instead.
 * Every error answer from a route, a hook or the not-found handler goes out
 * this way; bytes Node's parser refuses are answered in client-errors.ts.
 */
export function sendErrorBody(
  reply: FastifyReply,
  status: number,
  code: ReasonCode,
  correlationId: string,
): FastifyReply {
  return reply
    .code(status)
    .type(JSON_TYPE)
    .send(JSON.stringify(errorBody(code, correlationId)));
}

/** Refusals the framework, Node or the rate limit raise, by HTTP status. */
const REFUSALS: Readonly<Partial<Record<number, ReasonCode>>> = {
  400: 'BAD_REQUEST',
  404: 'NOT_FOUND',
  408: 'REQUEST_TIMEOUT',
  413: 'PAYLOAD_TOO_LARGE',
  415: 'UNSUPPORTED_MEDIA_TYPE',
  429: 'RATE_LIMITED',
  431: 'HEADERS_TOO_LARGE',
};

/** The error's own status when it's an error status; anything else is a failure on our side. */
function statusOf(error: unknown): number {
  const status: unknown = error instanceof Error ? (error as { statusCode?: unknown }).statusCode : undefined;
  return typeof status === 'number' && Number.isInteger(status) && status >= 400 ? status : 500;
}

export interface ErrorResponse {
  readonly status: number;
  readonly code: ReasonCode;
}

/**
 * What to send for an error status. A refusal keeps its status and gets its
 * code; any other client error is sent as a plain 400; every status from 500 up
 * is a 500.
 */
export function responseForStatus(status: number): ErrorResponse {
  if (status >= 500) return { status: 500, code: 'INTERNAL_ERROR' };
  const code = REFUSALS[status];
  return code === undefined ? { status: 400, code: 'BAD_REQUEST' } : { status, code };
}

/** What to send for an error, from its own status. */
export function responseFor(error: unknown): ErrorResponse {
  return responseForStatus(statusOf(error));
}
