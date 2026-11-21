// The `jobs` side's list as a config makes it (4D2e D): the jobs a config can leave off (the factor removals, the
// background downloads, a durable anchor log) made on where it names them, and listed either way. Made only: nothing
// starts, so no database is reached.
import { checkStatesWith, statesDigest } from '@agentx/core/modules/audit';
import { LONGEST_ABSOLUTE_SECONDS } from '@agentx/core/modules/identity';
import { APPROVAL_HORIZON_MS } from '@agentx/core/modules/spend-requests';
import { type DigestLog, subjectKey } from '@agentx/platform/audit-chain';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { loadConfig } from '@agentx/platform/config';
import { createLogger } from '@agentx/platform/observability';
import { FixedClock, LogCapture, testLogger } from '@agentx/testing';
import { describe, expect, it, vi } from 'vitest';

import type { Leadership } from './background.ts';
import { type Booted, sharedParts } from './boot.ts';
import { integrityPasses, oneCopyJobs } from './job-list.ts';
import type { OwedPasses } from './org-passes.ts';

const BASE = {
  AGENTX_ENV: 'test',
  AGENTX_DB_HOST: 'db',
  AGENTX_DB_PASSWORD: 'app login for these tests',
  AGENTX_KEYS_DIR: '/mnt/secrets',
};
const ISSUER = 'http://auth.test';
// Plain words, built at run time, as every stand-in for a secret here.
const EVERYTHING_ON = {
  ...BASE,
  AGENTX_OUTBOUND_ALLOWED_ORIGINS: ISSUER,
  AGENTX_OIDC_ISSUER: ISSUER,
  AGENTX_OIDC_CLIENT_ID: 'agentx-api',
  AGENTX_OIDC_CLIENT_SECRET: ['stand', 'in', 'client', 'words'].join('-'),
  AGENTX_FACTOR_RESET_TOKEN: ['reset', 'words'].join('-'),
  AGENTX_ACTIVITY_DOWNLOADS_DIR: '/tmp/downloads-not-made',
  AGENTX_AUDIT_ANCHORS_DIR: '/tmp/anchors-not-made',
};

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);

/** A database no list here may reach: making the jobs must not touch it. */
const untouched = new Proxy(
  {},
  {
    get: () => {
      throw new Error('the database was reached while the jobs were only made');
    },
  },
);

const leadership: Leadership = {
  start: () => Promise.resolve(),
  leading: () => true,
  onlyWhileLeading: (work) => work,
  onlyWhileNotLeading: (work) => work,
  stop: () => Promise.resolve(),
};

/** The `jobs` side's jobs, as the config given makes them, under the leadership given. */
function jobsWith(env: Record<string, string>, under: Leadership) {
  const config = loadConfig(env);
  const logger = createLogger({ service: 'api', config, destination: new LogCapture() });
  const booted: Booted = {
    host: {} as Booted['host'],
    config,
    keys,
    logger,
    database: untouched as Booted['database'],
    atCrash: () => undefined,
  };
  return oneCopyJobs(booted, sharedParts(booted, under), under).jobs;
}

describe('a jobs copy that follows still reads the store (TR-1 A)', () => {
  it.each([
    ['a store named: its read, gated to run only while this copy doesn’t lead', EVERYTHING_ON, ['anchors_follow']],
    ['none: listed, with nothing to run', BASE, []],
  ])('%s', async (_what, env, gatedToFollow) => {
    const gated: string[] = [];
    const idle = (work: { readonly name: string }) => ({ name: work.name, run: () => Promise.resolve() });
    const recording: Leadership = {
      ...leadership,
      onlyWhileLeading: idle,
      onlyWhileNotLeading: (work) => {
        gated.push(work.name);
        return idle(work);
      },
    };
    const follow = jobsWith(env, recording).find(({ name }) => name === 'anchors_follow');
    if (follow === undefined) throw new Error('anchors_follow should be listed');
    // Started, as start-jobs.ts starts it: the gate is put round its work then.
    await follow.start().stop();
    expect(gated).toEqual(gatedToFollow);
  });
});

/** The `jobs` side's names, as the config given makes them. */
function namesWith(env: Record<string, string>) {
  return jobsWith(env, leadership).map(({ name }) => name);
}

describe('the jobs side as a config makes it (4D2e D10)', () => {
  it('lists the factor removals, the background downloads and the hold history whether or not the config names them', () => {
    for (const names of [namesWith(EVERYTHING_ON), namesWith(BASE)]) {
      expect(names).toEqual(expect.arrayContaining(['factor_resets', 'background_downloads', 'hold_history']));
    }
  });

  it('makes the same list with every job the config can leave off on', () => {
    expect(namesWith(EVERYTHING_ON)).toEqual(namesWith(BASE));
  });
});

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const ALL = Array.from({ length: 48 }, (_, at) => `0199d011-0000-7000-8000-${String(at).padStart(12, '0')}`);
const MARKED = [ALL[0] ?? ''];

const passesAt = (start: string) => {
  const clock = new FixedClock(new Date(start));
  const passes = integrityPasses({
    all: () => Promise.resolve(ALL),
    marked: () => Promise.resolve(MARKED),
    logger: testLogger(),
    clock,
  });
  return { clock, passes };
};

/** What the passes list, each organisation then finished. */
const listedOnce = async (passes: OwedPasses) => {
  const listed = await passes.list();
  for (const orgId of listed) passes.done(orgId);
  return listed;
};

describe('the integrity passes as the jobs side wires them, each bound (4D2e D11, decision 2)', () => {
  it('the holdings check: the marked each run, every organisation hourly', async () => {
    const { clock, passes } = passesAt('2026-11-04T10:00:00.000Z');
    expect(await listedOnce(passes.holdings)).toEqual(ALL);
    clock.advanceBy(HOUR - 1);
    expect(await listedOnce(passes.holdings)).toEqual(MARKED);
    clock.advanceBy(1);
    expect(await listedOnce(passes.holdings)).toEqual(ALL);
  });

  it.each(['sealCheck', 'securitySeal'] as const)(
    'the %s: each organisation once in 6 hours, by half-hour slots',
    async (pass) => {
      const { clock, passes } = passesAt('2026-11-04T00:00:00.000Z');
      expect(await listedOnce(passes[pass])).toEqual(ALL);
      const seen: string[] = [];
      for (let run = 0; run < 12; run += 1) {
        clock.advanceBy(30 * MINUTE);
        seen.push(...(await listedOnce(passes[pass])));
      }
      expect(seen.toSorted()).toEqual(ALL.toSorted());
      // A slot is half an hour: a run a moment short of the next lists none.
      clock.advanceBy(30 * MINUTE - 1);
      expect(await listedOnce(passes[pass])).toEqual([]);
    },
  );

  it('the activity seal: every organisation once a UTC day, once yesterday can be sealed, at 00:15', async () => {
    const { clock, passes } = passesAt('2026-11-04T00:10:00.000Z');
    expect(await listedOnce(passes.seal)).toEqual(ALL);
    clock.advanceBy(5 * MINUTE - 1);
    expect(await listedOnce(passes.seal)).toEqual([]);
    clock.advanceBy(1);
    expect(await listedOnce(passes.seal)).toEqual(ALL);
    clock.advanceBy(24 * HOUR - 1);
    expect(await listedOnce(passes.seal)).toEqual([]);
  });

  it.each(['sweep', 'securitySweep'] as const)(
    'the %s (idempotency keys; each organisation’s own security events, 6E1b): every organisation once a UTC day, from midnight',
    async (which) => {
      const { clock, passes } = passesAt('2026-11-04T23:59:00.000Z');
      expect(await listedOnce(passes[which])).toEqual(ALL);
      clock.advanceBy(MINUTE - 1);
      expect(await listedOnce(passes[which])).toEqual([]);
      clock.advanceBy(1);
      expect(await listedOnce(passes[which])).toEqual(ALL);
    },
  );

  it('owes the security events’ sweep apart from the idempotency sweep: one finished leaves the other owed', async () => {
    const { passes } = passesAt('2026-11-04T10:00:00.000Z');
    expect(await listedOnce(passes.sweep)).toEqual(ALL);
    expect(await passes.securitySweep.list()).toEqual(ALL);
  });
});

describe('the digest a jobs copy keeps in memory alone, with no store named (AT13d/g)', () => {
  it('forgets session ends past the longest session and requests past the approval horizon, as the kept one does', () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    try {
      const at = new Date('2026-11-21T09:00:00.000Z').getTime();
      vi.setSystemTime(at);
      namesWith(BASE);
      const digest = statesDigest() as DigestLog;
      const chain = { kind: 'organisation', orgId: '0199a0f0-0000-7000-8000-000000000001' } as const;
      const platform = { kind: 'platform' } as const;
      const REQUEST = '0199a0f0-0000-7000-8000-0000000000c1';
      const ENDED = '0199a0f0-0000-7000-8000-0000000000aa:0199a0f0-0000-7000-8000-0000000000bb';
      digest.record(chain, new Map([[subjectKey('spend_request', REQUEST), 3n]]), new Date(at));
      digest.record(platform, new Map([[subjectKey('identity.session_ended', ENDED), 4n]]), new Date(at));
      const DAY = 86_400_000;
      vi.setSystemTime(at + LONGEST_ABSOLUTE_SECONDS * 1000 + DAY + 60_000);
      digest.record(chain, new Map(), new Date());
      expect(digest.latest(platform, 'identity.session_ended', ENDED)).toBeUndefined();
      expect(digest.latest(chain, 'spend_request', REQUEST)).toBe(3n);
      vi.setSystemTime(at + APPROVAL_HORIZON_MS + DAY + 3_600_000);
      digest.record(chain, new Map(), new Date());
      expect(digest.latest(chain, 'spend_request', REQUEST)).toBeUndefined();
    } finally {
      checkStatesWith(undefined);
      vi.useRealTimers();
    }
  });
});
