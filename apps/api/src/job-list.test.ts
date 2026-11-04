// The `jobs` side's list as a config makes it (4D2e D): the jobs a config can leave off (the factor removals, the
// background downloads, a durable anchor log) made on where it names them, and listed either way. Made only: nothing
// starts, so no database is reached.
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { loadConfig } from '@agentx/platform/config';
import { createLogger } from '@agentx/platform/observability';
import { LogCapture } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import type { Leadership } from './background.ts';
import { type Booted, sharedParts } from './boot.ts';
import { oneCopyJobs } from './job-list.ts';

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
  stop: () => Promise.resolve(),
};

/** The `jobs` side's names, as the config given makes them. */
function namesWith(env: Record<string, string>) {
  const config = loadConfig(env);
  const logger = createLogger({ service: 'api', config, destination: new LogCapture() });
  const booted = { host: {} as Booted['host'], config, keys, logger, database: untouched as Booted['database'] };
  return oneCopyJobs(booted, sharedParts(booted, leadership), leadership).jobs.map(({ name }) => name);
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
