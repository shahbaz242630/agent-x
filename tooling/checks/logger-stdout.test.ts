// ADR-013, SEC-DATA-01: the logger's real output path, end to end. A separate
// Node process installs the output guard, creates a logger with the default
// destination (stdout), logs every sensitive sample, a flood and an error,
// then writes stray text to stdout and stderr the way a dependency or Node
// itself might. Its stdout and stderr must carry no leak, the logger's lines
// must be JSON, and the count of held-back lines must be exact. The unit tests
// capture output in memory; this is the one test of the real streams.
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { describe, expect, it } from 'vitest';

import { findLeaks, SENSITIVE_SAMPLES } from '../../packages/testing/src/log-scan.ts';

const LOGGER = pathToFileURL(path.resolve('packages/platform/src/observability/index.ts')).href;
const SAMPLES = Object.values(SENSITIVE_SAMPLES);
/** Above the number of samples, which share one event name; the flood goes past it. */
const CAP = SAMPLES.length + 5;
const FLOOD = CAP + 15;

/** Runs in the child process. Node strips the TypeScript types of the imported files itself. */
const SCRIPT = `
const { createLogger, guardOutputs } = await import(${JSON.stringify(LOGGER)});
guardOutputs(process);
const logger = createLogger({
  service: 'stdout-check',
  config: { environment: 'test', release: 'r-1', log: { level: 'info', eventCapPerMinute: ${CAP} } },
});
const samples = ${JSON.stringify(SAMPLES)};
for (const sample of samples) logger.info('check.sample', { note: 'seen ' + sample, password: sample });
for (let i = 0; i < ${FLOOD}; i++) logger.warn('check.flood');
logger.error('check.failed', { err: new Error('failed for ' + samples.join(' ')) });
logger.flush();
console.log('stray output ' + samples.join(' '));
console.error('stray error ' + samples.join(' '));
process.emitWarning('warning about ' + samples.join(' '));
`;

interface Line {
  event?: string;
  level?: string;
  suppressedCount?: number;
  err?: { type?: string; message?: string };
}

describe('ADR-013 stdout and stderr carry only redacted output', () => {
  const run = spawnSync(process.execPath, ['--input-type=module', '--eval', SCRIPT], {
    encoding: 'utf8',
    timeout: 60_000,
  });
  const lines = run.stdout
    .split('\n')
    .filter((line) => line.startsWith('{'))
    .map((line) => JSON.parse(line) as Line);

  it('runs cleanly', () => {
    expect(run.error).toBeUndefined();
    expect(run.status).toBe(0);
  });

  it('writes one JSON line per event: the samples, the capped flood, its exact count and the error', () => {
    const events = lines.map((line) => line.event);
    expect(events.filter((event) => event === 'check.sample')).toHaveLength(SAMPLES.length);
    expect(events.filter((event) => event === 'check.flood')).toHaveLength(CAP);
    expect(lines.find((line) => line.event === 'log.suppressed')).toMatchObject({
      level: 'warn',
      suppressedCount: FLOOD - CAP,
    });
    expect(lines.find((line) => line.event === 'check.failed')?.err).toMatchObject({ type: 'Error' });
  });

  it('cleans stray text written to stdout and stderr some other way', () => {
    expect(run.stdout).toContain('stray output [email]');
    expect(run.stderr).toContain('stray error [email]');
    expect(run.stderr).toContain('warning about [email]');
  });

  it('carries no sensitive sample, on stdout or stderr', () => {
    expect(findLeaks(run.stdout, SAMPLES)).toEqual([]);
    expect(findLeaks(run.stderr, SAMPLES)).toEqual([]);
  });
});
