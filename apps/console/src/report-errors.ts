// The console's own failures, sent to the API (6A2, ADR-013): a script error,
// a promise nothing caught, a screen React couldn't draw. Only to our own
// origin (POST /v1/client-errors), never an outside service. A few a page
// load at most, so a failure that repeats can't flood the API, and a report
// that fails is let go: reporting must never be what breaks the page.
const ADDRESS = '/v1/client-errors';

/** The most reports one page load sends. */
const MOST_REPORTS = 10;

/** The fields' caps, as the API's own (apps/api/src/browser-errors.ts). */
const MESSAGE_LENGTH = 500;
const STACK_LENGTH = 4000;
const PAGE_LENGTH = 200;

/** A console page's path, as the API accepts it (and no longer than it takes); anything else is reported as the home page. */
const PAGE = /^\/(?:[a-z0-9-]+(?:\/[a-z0-9-]+)*)?$/;

type Kind = 'error' | 'rejection' | 'render';

let sent = 0;

/** Starts counting a page load's reports afresh: for tests. */
export function resetReports(): void {
  sent = 0;
}

function messageOf(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return (message === '' ? 'No message' : message).slice(0, MESSAGE_LENGTH);
}

export function report(kind: Kind, error: unknown): void {
  if (sent >= MOST_REPORTS) return;
  sent += 1;
  const path = window.location.pathname;
  const stack = error instanceof Error ? error.stack?.slice(0, STACK_LENGTH) : undefined;
  const body = JSON.stringify({
    kind,
    message: messageOf(error),
    page: path.length <= PAGE_LENGTH && PAGE.test(path) && !/^\/(?:v1|health)(?:\/|$)/.test(path) ? path : '/',
    ...(stack !== undefined && stack !== '' && { stack }),
  });
  try {
    void fetch(ADDRESS, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body,
      credentials: 'same-origin',
      keepalive: true,
    }).catch(() => undefined);
  } catch {
    // No fetch at all: nothing to report with.
  }
}

/** The root's options reporting a screen React couldn't draw, caught by a boundary or not. */
export const RENDER_ERRORS = {
  onUncaughtError: (error: unknown) => {
    report('render', error);
  },
  onCaughtError: (error: unknown) => {
    report('render', error);
  },
};

/** Reports the page's uncaught errors and rejections from now on. */
export function reportErrors(target: Window = window): void {
  target.addEventListener('error', (event) => {
    report('error', event.error ?? event.message);
  });
  target.addEventListener('unhandledrejection', (event) => {
    report('rejection', event.reason);
  });
}
