// SEC-DATA-04 (threat DATA-2): an error response says what kind of problem it
// was and gives the correlation ID. It never carries anything internal: no
// error message, stack or framework code, and no echo of the request. An
// unexpected error is logged with its detail instead. Addresses that don't
// exist, and features that are off, get the same plain 404.
import { REASON_CODES, type ReasonCode } from '@agentx/core/shared-kernel';

/** The body of every error response. */
export interface ErrorBody {
  readonly error: {
    readonly code: ReasonCode;
    /** The code's public description (ADR-011 §8). */
    readonly message: string;
    readonly correlationId: string;
  };
}

export function errorBody(code: ReasonCode, correlationId: string): ErrorBody {
  return { error: { code, message: REASON_CODES[code], correlationId } };
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
