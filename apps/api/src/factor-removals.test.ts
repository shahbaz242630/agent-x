// B6-3c: resets carried out as the API runs it: off unless the config names
// the reset token and sign-in; on, the job never throws.
import { systemClock } from '@agentx/core/shared-kernel';
import { loadConfig } from '@agentx/platform/config';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import { LogCapture, SequentialIds } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { resetRemovalsFrom } from './factor-removals.ts';

const ISSUER = 'https://auth.agentx.example';

const BASE = {
  AGENTX_ENV: 'development',
  AGENTX_DB_HOST: 'db',
  AGENTX_DB_PASSWORD: 'app login for these tests',
  AGENTX_KEYS_DIR: '/mnt/secrets',
};
const SIGN_IN = {
  ...BASE,
  AGENTX_OUTBOUND_ALLOWED_ORIGINS: ISSUER,
  AGENTX_OIDC_ISSUER: ISSUER,
  AGENTX_OIDC_CLIENT_ID: 'agentx-api',
  AGENTX_OIDC_CLIENT_SECRET: 'client pass words',
};
// Plain words, built at run time, as every stand-in for a secret here.
const RESETS = { ...SIGN_IN, AGENTX_FACTOR_RESET_TOKEN: ['reset', 'words'].join('-') };

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);

/** The job a config gives, with a database that fails every query. */
function removalsWith(env: Record<string, string>) {
  const capture = new LogCapture();
  const failing = new Proxy(
    {},
    {
      get: () => () => {
        throw new Error('no database in this test');
      },
    },
  );
  const removals = resetRemovalsFrom({
    config: loadConfig(env),
    database: failing as never,
    keys,
    ids: new SequentialIds(),
    clock: systemClock,
    outbox: {} as never,
    fetch: () => Promise.reject(new Error('not called')),
    logger: createLogger({ service: 'api', config: loadConfig(BASE), destination: capture }),
  });
  return { removals, capture };
}

describe('SEC-OPS-04 resets carried out as the API runs it (B6-3c)', () => {
  it('is off without the reset token or sign-in in the config, and on with both', () => {
    expect(removalsWith(BASE).removals).toBeUndefined();
    expect(removalsWith(SIGN_IN).removals).toBeUndefined();
    expect(removalsWith(RESETS).removals).toBeDefined();
  });

  it('never throws when it can’t list the organisations: it logs, and waits for its next run', async () => {
    const { removals, capture } = removalsWith(RESETS);

    await expect(removals?.run()).resolves.toBeUndefined();
    expect(capture.lines().map(({ event }) => event)).toEqual(['factor_resets.run_failed']);
  });
});
