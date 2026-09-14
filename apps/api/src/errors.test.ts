import { REASON_CODES } from '@agentx/core/shared-kernel';
import { describe, expect, it } from 'vitest';

import { errorBody, responseFor } from './errors.ts';

const withStatus = (statusCode: unknown): Error => Object.assign(new Error('internal detail'), { statusCode });

describe('SEC-DATA-04 an error response carries a reason code, never the error', () => {
  it("uses the code's public description as the message", () => {
    expect(errorBody('RATE_LIMITED', 'c-1')).toEqual({
      error: { code: 'RATE_LIMITED', message: REASON_CODES.RATE_LIMITED, correlationId: 'c-1' },
    });
  });

  it.each([
    [400, 'BAD_REQUEST'],
    [404, 'NOT_FOUND'],
    [408, 'REQUEST_TIMEOUT'],
    [413, 'PAYLOAD_TOO_LARGE'],
    [415, 'UNSUPPORTED_MEDIA_TYPE'],
    [429, 'RATE_LIMITED'],
    [431, 'HEADERS_TOO_LARGE'],
  ] as const)('keeps the status of a %d refusal and gives it %s', (status, code) => {
    expect(responseFor(withStatus(status))).toEqual({ status, code });
  });

  it.each([401, 403, 405, 409, 414, 499])('sends any other client error (%d) as a plain 400', (status) => {
    expect(responseFor(withStatus(status))).toEqual({ status: 400, code: 'BAD_REQUEST' });
  });

  it.each([500, 502, 503, 599, 600, 1000])('sends every status from 500 up (%d) as a 500', (status) => {
    expect(responseFor(withStatus(status))).toEqual({ status: 500, code: 'INTERNAL_ERROR' });
  });

  it.each([
    ['no status', undefined],
    ['a status below 400', 302],
    ['a status that is not a whole number', 404.5],
    ['a status written as text', '404'],
  ])('treats an error with %s as a failure on our side', (_what, statusCode) => {
    expect(responseFor(withStatus(statusCode))).toEqual({ status: 500, code: 'INTERNAL_ERROR' });
  });

  it.each([
    ['a string', 'failed'],
    ['a plain object with a status', { statusCode: 404 }],
    ['null', null],
  ])('treats a thrown %s, which is not an Error, as a failure on our side', (_what, thrown) => {
    expect(responseFor(thrown)).toEqual({ status: 500, code: 'INTERNAL_ERROR' });
  });
});
