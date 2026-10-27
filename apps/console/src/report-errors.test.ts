// 6A2, ADR-013: the console's errors go to our own API only, in the shape it
// takes, ten a page load at most, and a report that fails is let go.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { RENDER_ERRORS, report, reportErrors, resetReports } from './report-errors.ts';

let sent: { path: string; init: RequestInit }[];

beforeEach(() => {
  sent = [];
  resetReports();
  window.history.replaceState(null, '', '/approvals');
  vi.stubGlobal(
    'fetch',
    vi.fn((path: string, init: RequestInit) => {
      sent.push({ path, init });
      return Promise.resolve(new Response('{}', { status: 202 }));
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

const bodies = () => sent.map(({ init }) => JSON.parse(init.body as string) as Record<string, unknown>);

describe('report', () => {
  it('sends an error to our own API with its message, page and stack', () => {
    const error = new TypeError('x is undefined');

    report('render', error);

    expect(sent[0]?.path).toBe('/v1/client-errors');
    expect(sent[0]?.init).toMatchObject({ method: 'POST', credentials: 'same-origin', keepalive: true });
    expect(bodies()).toEqual([{ kind: 'render', message: 'x is undefined', page: '/approvals', stack: error.stack }]);
  });

  it('cuts a long message and stack to the API’s caps, and names an empty one', () => {
    const long = new Error('m'.repeat(600));
    long.stack = 's'.repeat(5000);

    report('error', long);
    report('rejection', '');

    expect(bodies()[0]).toMatchObject({ message: 'm'.repeat(500), stack: 's'.repeat(4000) });
    expect(bodies()[1]).toEqual({ kind: 'rejection', message: 'No message', page: '/approvals' });
  });

  it.each(['/Approvals', '/v1/statements', '/health', `/${'a'.repeat(200)}`])(
    'reports %s, not a console page, as the home page',
    (page) => {
      window.history.replaceState(null, '', page);

      report('error', 'oops');

      expect(bodies()[0]?.page).toBe('/');
    },
  );

  it('sends ten a page load at most', () => {
    for (let count = 0; count < 12; count += 1) report('error', 'again');

    expect(sent).toHaveLength(10);
  });

  it('lets a report that fails go, whether the request fails or fetch itself throws', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.reject(new TypeError('Failed to fetch'))),
    );
    expect(() => {
      report('error', 'one');
    }).not.toThrow();
    vi.stubGlobal(
      'fetch',
      vi.fn(() => {
        throw new TypeError('no fetch');
      }),
    );
    expect(() => {
      report('error', 'two');
    }).not.toThrow();
    await Promise.resolve();
  });
});

describe('RENDER_ERRORS', () => {
  it('reports a screen React couldn’t draw, caught by a boundary or not', () => {
    RENDER_ERRORS.onUncaughtError(new Error('uncaught'));
    RENDER_ERRORS.onCaughtError(new Error('caught'));

    expect(bodies().map(({ kind, message }) => [kind, message])).toEqual([
      ['render', 'uncaught'],
      ['render', 'caught'],
    ]);
  });
});

describe('reportErrors', () => {
  it('reports the page’s uncaught errors and rejections', () => {
    reportErrors();

    window.dispatchEvent(new ErrorEvent('error', { error: new Error('thrown'), message: 'thrown' }));
    window.dispatchEvent(new ErrorEvent('error', { message: 'Script error.' }));
    const rejected = new Event('unhandledrejection');
    Object.assign(rejected, { reason: new Error('rejected') });
    window.dispatchEvent(rejected);

    expect(bodies().map(({ kind, message }) => [kind, message])).toEqual([
      ['error', 'thrown'],
      ['error', 'Script error.'],
      ['rejection', 'rejected'],
    ]);
  });
});
