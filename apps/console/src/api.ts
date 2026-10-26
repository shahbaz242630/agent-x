// The console's one way to the API (6A1): its own origin, its own cookies, and
// the headers every request needs. Authority stays on the server; this only
// asks and reads its answers.
// - Every request names the browser's time zone (`x-time-zone`, ADR-011 §7),
//   which the activity log keeps as "reported by the browser".
// - A request in an organisation names it (`agentx-organization`), as the
//   access hook checks the person's membership there.
// - A write carries a fresh idempotency key, so a retry of the same press is
//   the same write (the API's idempotency, BR-14).
// The browser adds `Origin` to every write itself, which the API's Origin
// check needs (SEC-WEB-01).

/** A refusal or a failure, by the API's one error body (errors.ts). */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string) {
    super(`The API answered ${String(status)} ${code}`);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

/** The browser's own time zone, as Intl names it; none when the browser can't say. */
function timeZone(): string | undefined {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  } catch {
    return undefined;
  }
}

/** The error body's reason code, or `UNREADABLE` for an answer that isn't one (a proxy's page, a cut connection). */
async function codeOf(response: Response): Promise<string> {
  try {
    const body: unknown = await response.json();
    if (typeof body === 'object' && body !== null && 'error' in body) {
      const error: unknown = body.error;
      if (typeof error === 'object' && error !== null && 'code' in error && typeof error.code === 'string') {
        return error.code;
      }
    }
  } catch {
    // Not JSON: the answer below says so.
  }
  return 'UNREADABLE';
}

export interface RequestOptions {
  /** The organisation the request acts in; none for the person's own reads (their session, their organisations). */
  readonly organization?: string | undefined;
  /** A write's JSON body; a write with none sends no body at all. */
  readonly body?: unknown;
}

/** Sends one request and gives back its JSON answer, or throws ApiError. */
async function send<T>(method: 'GET' | 'POST', path: string, options: RequestOptions): Promise<T> {
  const headers = new Headers({ accept: 'application/json' });
  const zone = timeZone();
  if (zone !== undefined) headers.set('x-time-zone', zone);
  if (options.organization !== undefined) headers.set('agentx-organization', options.organization);
  if (method === 'POST') headers.set('idempotency-key', crypto.randomUUID());
  let body: string | null = null;
  if (options.body !== undefined) {
    headers.set('content-type', 'application/json');
    body = JSON.stringify(options.body);
  }
  const response = await fetch(path, { method, headers, body, credentials: 'same-origin', cache: 'no-store' });
  if (!response.ok) throw new ApiError(response.status, await codeOf(response));
  return (await response.json()) as T;
}

export const api = {
  get: <T>(path: string, options: RequestOptions = {}): Promise<T> => send<T>('GET', path, options),
  post: <T>(path: string, options: RequestOptions = {}): Promise<T> => send<T>('POST', path, options),
};

/** Whether an error means the person isn't signed in (any more): their session ended, or never was. */
export const isSignedOut = (error: unknown): boolean => error instanceof ApiError && error.status === 401;

/** Where the browser goes to sign in, coming back to `returnTo` (a path of this console) after. */
export function signInAddress(returnTo: string): string {
  return `/v1/auth/sign-in?${new URLSearchParams({ returnTo }).toString()}`;
}
