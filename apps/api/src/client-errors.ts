// SEC-WEB-02, SEC-DATA-04: Node's HTTP parser refuses some requests before any
// route or hook sees them: a malformed request line or header, headers over
// 16 KiB, a request that took too long to arrive. Fastify's own answer carries
// none of our headers and its own body. This one answers like every other
// error, with the security headers, a correlation ID and a reason code, and
// logs the refusal. There's no parsed request, so the line holds only the
// status and Node's error (its type, fixed message and code; never the bytes).
import type { IdGenerator } from '@agentx/core/shared-kernel';
import type { EventName, Logger } from '@agentx/platform/observability';
import type { Socket } from 'node:net';

import { CORRELATION_HEADER } from './correlation.ts';
import { errorBody, responseForStatus } from './errors.ts';
import { SECURITY_HEADERS } from './security-headers.ts';

export const CLIENT_ERROR: EventName = 'http.client_error';

const CRLF = String.fromCharCode(13, 10);

/** Node's error codes with their own status line; anything else is a malformed request. */
const STATUS_LINES: Readonly<Partial<Record<string, string>>> = {
  ERR_HTTP_REQUEST_TIMEOUT: '408 Request Timeout',
  HPE_HEADER_OVERFLOW: '431 Request Header Fields Too Large',
};
const MALFORMED = '400 Bad Request';

export function answerClientError(
  error: Error & { readonly code?: string },
  socket: Socket,
  logger: Logger,
  ids: IdGenerator,
): void {
  // A reset connection, or one already closed, has no one to answer.
  if (error.code === 'ECONNRESET' || socket.destroyed) return;
  const statusLine = STATUS_LINES[error.code ?? ''] ?? MALFORMED;
  const { status, code } = responseForStatus(Number(statusLine.slice(0, 3)));
  const correlationId = ids.next();
  const body = JSON.stringify(errorBody(code, correlationId));
  const headers = {
    ...SECURITY_HEADERS,
    [CORRELATION_HEADER]: correlationId,
    'content-type': 'application/json; charset=utf-8',
    'content-length': String(Buffer.byteLength(body)),
    connection: 'close',
  };
  if (socket.writable) {
    const fields = Object.entries(headers).map(([name, value]) => `${name}: ${value}`);
    socket.write([`HTTP/1.1 ${statusLine}`, ...fields, '', body].join(CRLF));
  }
  socket.destroy(error);
  logger.child({ correlationId }).info(CLIENT_ERROR, { status, err: error });
}
