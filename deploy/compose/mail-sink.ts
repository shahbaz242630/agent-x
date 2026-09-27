// The local stack's stand-in for Azure Communication Services' email API
// (B6-2c): the API sends its notices here, as it sends them to ACS on
// Azure, and this answers as ACS does (202 once taken) and writes one log
// line per email, which the end-to-end suite reads. Nothing is delivered.
//
// It checks each send as ACS would: the path and api-version, the body's
// hash, and the HMAC-SHA256 signature over the method, path and query, the
// date, the host and that hash, made with the access key the suite wrote into
// this service's own folder (read afresh for each send, since the suite
// writes it after the stack starts). Written apart from the notifier
// (packages/core's acs-notifier.ts), so the two can check each other: its
// test signs with the notifier's own function.
//
// Run by compose (compose.yaml's `mail`) in the pinned Node image, as its
// unprivileged user, with no dependency but Node's own modules.
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';

/** ACS's email API: the send, and the version the notifier asks for. */
export const SEND_PATH = '/emails:send';
export const API_VERSION = '2025-09-01';

/** Where compose mounts the suite's copy of the access key. */
export const KEY_FILE = '/mnt/mail/access-key';

/** An email is small: a subject and a few lines. */
const MOST_BODY_BYTES = 64 * 1024;

/** One email taken, as the log line names it. */
export interface Received {
  readonly to: readonly string[];
  readonly subject: string;
  readonly operationId: string;
}

export interface Send {
  readonly method: string;
  /** The path and query, as the request line gives them. */
  readonly target: string;
  readonly headers: Readonly<Record<string, string | undefined>>;
  readonly body: string;
}

/** Equal, in a time that doesn't depend on where they differ. */
function same(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

const field = (value: unknown, name: string): unknown =>
  typeof value === 'object' && value !== null ? (value as Record<string, unknown>)[name] : undefined;

/** The email's recipients and subject, or undefined for a body that isn't an email as ACS takes it. */
function emailOf(body: string): { to: string[]; subject: string } | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return undefined;
  }
  const to = field(field(parsed, 'recipients'), 'to');
  const content = field(parsed, 'content');
  const subject = field(content, 'subject');
  if (typeof field(parsed, 'senderAddress') !== 'string') return undefined;
  if (typeof subject !== 'string' || typeof field(content, 'plainText') !== 'string') return undefined;
  if (!Array.isArray(to) || to.length === 0) return undefined;
  const addresses = to.map((recipient) => field(recipient, 'address'));
  if (!addresses.every((address): address is string => typeof address === 'string')) return undefined;
  return { to: addresses, subject };
}

/** The status ACS would answer a send with, and the email when it is taken. */
export function checkSend(send: Send, accessKey: string | undefined): { status: number; received?: Received } {
  const url = new URL(send.target, 'http://sink');
  if (send.method !== 'POST' || url.pathname !== SEND_PATH) return { status: 404 };
  if (url.searchParams.get('api-version') !== API_VERSION) return { status: 400 };
  const { host, authorization } = send.headers;
  const date = send.headers['x-ms-date'];
  const contentHash = send.headers['x-ms-content-sha256'];
  if (accessKey === undefined || host === undefined || date === undefined || authorization === undefined) {
    return { status: 401 };
  }
  if (contentHash !== createHash('sha256').update(send.body, 'utf8').digest('base64')) return { status: 401 };
  const toSign = `POST\n${url.pathname}${url.search}\n${date};${host};${contentHash}`;
  const signature = createHmac('sha256', Buffer.from(accessKey, 'base64')).update(toSign, 'utf8').digest('base64');
  if (!same(authorization, `HMAC-SHA256 SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature=${signature}`)) {
    return { status: 401 };
  }
  const email = emailOf(send.body);
  if (email === undefined) return { status: 400 };
  return { status: 202, received: { ...email, operationId: send.headers['operation-id'] ?? '' } };
}

/** The key the suite wrote, or undefined before it has. */
function keyIn(file: string): string | undefined {
  try {
    const key = readFileSync(file, 'utf8').trim();
    return key === '' ? undefined : key;
  } catch {
    return undefined;
  }
}

/** The sink as a server: `/health` for compose, the send for the API, one log line per send. */
export function mailSink(keyFile: string, log: (line: string) => void): Server {
  return createServer((request, response) => {
    if (request.method === 'GET' && request.url === '/health') {
      response.writeHead(200).end();
      return;
    }
    const chunks: Buffer[] = [];
    let size = 0;
    request.on('data', (chunk: Buffer) => {
      size += chunk.length;
      // Read to the end, keeping nothing past the bound, so the answer is always a status.
      if (size <= MOST_BODY_BYTES) chunks.push(chunk);
    });
    request.on('end', () => {
      if (size > MOST_BODY_BYTES) {
        log(JSON.stringify({ event: 'mail.refused', status: 413 }));
        response.writeHead(413).end();
        return;
      }
      const headers = Object.fromEntries(
        Object.entries(request.headers).map(([name, value]) => [name, Array.isArray(value) ? value[0] : value]),
      );
      const send = {
        method: request.method ?? '',
        target: request.url ?? '',
        headers,
        body: Buffer.concat(chunks).toString('utf8'),
      };
      const { status, received } = checkSend(send, keyIn(keyFile));
      log(
        JSON.stringify(
          received === undefined ? { event: 'mail.refused', status } : { event: 'mail.received', ...received },
        ),
      );
      response.writeHead(status).end();
    });
  });
}

if (import.meta.main) {
  const server = mailSink(KEY_FILE, (line) => {
    process.stdout.write(`${line}\n`);
  });
  server.listen(8080, '0.0.0.0');
  process.on('SIGTERM', () => server.close());
}
