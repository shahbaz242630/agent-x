// ADR-013, SEC-DATA-01: pino publishes each log call's data on the
// `pino_asJson` diagnostics channel before its own hooks run, so anything in
// the process that subscribes (an APM agent, a dependency) would see it. The
// logger cleans every field before pino sees it, so what the channel carries
// is already redacted. Product code can't subscribe (lint bans the module);
// this check, outside product code, does, to prove the data is clean.
import { tracingChannel } from 'node:diagnostics_channel';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createLogger } from '../../packages/platform/src/observability/index.ts';
import { findLeaks, LogCapture, SENSITIVE_SAMPLES } from '../../packages/testing/src/log-scan.ts';

const PLANTED = 'planted value that must not appear';
const channel = tracingChannel('pino_asJson');
const seen: string[] = [];
const subscribers = {
  start: (message: unknown): void => {
    seen.push(JSON.stringify((message as { arguments?: unknown }).arguments ?? message));
  },
  end: (): void => undefined,
  asyncStart: (): void => undefined,
  asyncEnd: (): void => undefined,
  error: (): void => undefined,
};

beforeAll(() => {
  channel.subscribe(subscribers);
});

afterAll(() => {
  channel.unsubscribe(subscribers);
});

describe('ADR-013 a diagnostics-channel subscriber sees only redacted data', () => {
  it('receives each log call, with every field already cleaned', () => {
    const logger = createLogger({
      service: 'diagnostics-check',
      config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: 100 } },
      destination: new LogCapture(),
    });
    const samples = Object.values(SENSITIVE_SAMPLES);
    logger.child({ correlationId: 'c-1' }).info('check.sample', {
      password: PLANTED,
      notes: samples,
      err: Object.assign(new Error(`failed for ${SENSITIVE_SAMPLES.email}`), { detail: PLANTED }),
    });
    // An invalid event name is written as a field, so it's cleaned before pino sees it too.
    logger.info(`Bad name ${SENSITIVE_SAMPLES.email}`);

    expect(seen.length).toBeGreaterThan(0);
    const published = seen.join('\n');
    expect(published).toContain('check.sample');
    expect(findLeaks(published, [PLANTED, ...samples])).toEqual([]);
  });
});
