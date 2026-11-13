// SA3e: Zitadel's machine IDs, over HTTP with a stub sequence, and the FNV search behind them.
import { createLogger } from '@agentx/platform/observability';
import { LogCapture } from '@agentx/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { bodyOf, fnv1Of, MACHINE_ID_PATH, machineNameFor, MOST_TRIES } from './machine-ids.ts';
import { closeServers, routeServer } from './route-server.helper.test.ts';

const INTERNAL_HOST = 'ax-staging-api.internal.example.uaenorth.azurecontainerapps.io';

afterEach(closeServers);

/** Go's hash/fnv New32, its low 16 bits as Zitadel keeps them (internal/id/sonyflake.go). */
const zitadelId = (body: string): number => fnv1Of(body) & 0xff_ff;

describe('FNV-1 32, as Go hash/fnv New32 computes it', () => {
  it("gives the FNV reference values (FNV-1, not FNV-1a, whose 'a' is e40c292c)", () => {
    expect(fnv1Of('').toString(16)).toBe('811c9dc5');
    expect(fnv1Of('a').toString(16)).toBe('50c5d7e');
    expect(fnv1Of('foobar').toString(16)).toBe('31f0b262');
  });

  it('agrees with Go 1.25 hash/fnv New32 on the bodies it hands out (printed by a Go program, S189)', () => {
    // fnv.New32(); h.Write([]byte(body)); h.Sum32() and uint16(h.Sum32()), run on Go 1.25.5.
    const fromGo = [
      { body: '{"machine":"agentx-0-66366"}', sum: 0xac_81_00_00, id: 0 },
      { body: '{"machine":"agentx-1-34817"}', sum: 0x09_cc_00_01, id: 1 },
      { body: '{"machine":"agentx-4242-83851"}', sum: 0xec_6a_10_92, id: 4242 },
      { body: '{"machine":"agentx-65535-184362"}', sum: 0x1b_80_ff_ff, id: 65_535 },
    ];
    for (const { body, sum, id } of fromGo) {
      expect({ body, sum: fnv1Of(body), id: zitadelId(body) }).toEqual({ body, sum, id });
      expect(bodyOf(machineNameFor(id) ?? '')).toBe(body);
    }
  });

  it('carries on from an earlier hash as hashing the text whole does', () => {
    expect(fnv1Of('bar', fnv1Of('foo'))).toBe(fnv1Of('foobar'));
  });
});

describe('the name for a machine ID', () => {
  it("is found for IDs across the range, each body hashing to its own ID in Zitadel's way", () => {
    for (const id of [0, 1, 2, 255, 256, 4242, 32_768, 65_534, 65_535]) {
      const name = machineNameFor(id);
      expect(name).toMatch(new RegExp(`^agentx-${String(id)}-\\d+$`));
      expect(zitadelId(bodyOf(name ?? ''))).toBe(id);
    }
  });

  it('starts at the first try: 14359 fits at k = 0 (Go 1.25.5 hash/fnv New32 of its body: d6f3817)', () => {
    expect(machineNameFor(14_359)).toBe('agentx-14359-0');
    expect(fnv1Of(bodyOf('agentx-14359-0'))).toBe(0x0d_6f_38_17);
  });

  it('is none at once for anything but a 16-bit whole number, never a search to the cap', () => {
    // An endless cap: without the check, each of these would spin for ever and time the test out.
    for (const id of [-1, 65_536, 1.5, Number.NaN]) {
      expect({ id, name: machineNameFor(id, Number.POSITIVE_INFINITY) }).toEqual({ id, name: undefined });
    }
  });

  it('is none once the tries run out, and the cap leaves room many times the one in 65,536 needed', () => {
    // agentx-0's first fit is its 66,366th try (above).
    expect(machineNameFor(0, 66_366)).toBeUndefined();
    expect(machineNameFor(0, 66_367)).toBe('agentx-0-66366');
    expect(MOST_TRIES).toBeGreaterThanOrEqual(64 * 65_536);
  });
});

/** A server with the machine IDs on INTERNAL_HOST (or off), drawing from `next`, and its log. */
async function server(next: () => Promise<number | undefined>, on = true) {
  const capture = new LogCapture();
  const logger = createLogger({
    service: 'api',
    config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 10_000 } },
    destination: capture,
  });
  const app = await routeServer({ logger, machineIds: on ? { host: INTERNAL_HOST, next } : undefined });
  return { app, capture };
}

const ask = (app: Awaited<ReturnType<typeof server>>['app'], host: string, headers: Record<string, string> = {}) =>
  app.inject({ method: 'GET', url: MACHINE_ID_PATH, headers: { host, ...headers } });

describe(`GET ${MACHINE_ID_PATH}`, () => {
  it('hands out the next ID on the internal host, as a body whose bytes hash to it, and logs which', async () => {
    const turns = [42, 43];
    const next = vi.fn(() => Promise.resolve(turns.shift()));
    const { app, capture } = await server(next);
    const first = await ask(app, INTERNAL_HOST);
    const second = await ask(app, `${INTERNAL_HOST.toUpperCase()}:443`);
    expect(first.statusCode).toBe(200);
    expect(second.statusCode).toBe(200);
    // Zitadel is given no JSONPath, so it hashes the body exactly as sent.
    expect(zitadelId(first.payload)).toBe(42);
    expect(zitadelId(second.payload)).toBe(43);
    expect(first.payload).toBe(bodyOf(machineNameFor(42) ?? ''));
    expect(first.headers['content-type']).toMatch(/^application\/json/);
    expect(next).toHaveBeenCalledTimes(2);
    expect(capture.lines().filter((line) => line.event === 'machine_ids.handed_out')).toMatchObject([
      { level: 'info', id: 42 },
      { level: 'info', id: 43 },
    ]);
  });

  it('is the 404 of an address that does not exist on any other host, drawing nothing', async () => {
    const next = vi.fn(() => Promise.resolve(7));
    const { app } = await server(next);
    for (const host of [
      // The public doors' hosts, which the app door sends every path of to the API.
      'app.agentx.example',
      'auth.agentx.example',
      // The internal name as a suffix or prefix of another, and an empty Host.
      `evil.${INTERNAL_HOST}`,
      `${INTERNAL_HOST}.evil.example`,
      '',
    ]) {
      const answer = await ask(app, host);
      expect({ host, status: answer.statusCode, code: answer.json<{ error: { code: string } }>().error.code }).toEqual({
        host,
        status: 404,
        code: 'NOT_FOUND',
      });
    }
    // X-Forwarded-Host is the client's to write: only the Host itself counts.
    const forwarded = await ask(app, 'app.agentx.example', { 'x-forwarded-host': INTERNAL_HOST });
    expect(forwarded.statusCode).toBe(404);
    expect(next).not.toHaveBeenCalled();
  });

  it('is a 404 on every host where it is off', async () => {
    const { app } = await server(() => Promise.resolve(7), false);
    expect((await ask(app, INTERNAL_HOST)).statusCode).toBe(404);
  });

  it('fails, with its plain error line, when the sequence gives no 16-bit number', async () => {
    for (const drawn of [undefined, -1, 65_536, 1.5]) {
      const { app, capture } = await server(() => Promise.resolve(drawn));
      const answer = await ask(app, INTERNAL_HOST);
      expect(answer.statusCode).toBe(500);
      expect(answer.json<{ error: { code: string } }>().error.code).toBe('INTERNAL_ERROR');
      expect(capture.lines().find((line) => line.event === 'machine_ids.failed')).toMatchObject({ level: 'error' });
    }
  });

  it('fails as any request does when the database does, so Zitadel asks again', async () => {
    const { app } = await server(() => Promise.reject(new Error('connection lost')));
    expect((await ask(app, INTERNAL_HOST)).statusCode).toBe(500);
  });
});
