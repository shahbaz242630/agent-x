// B6-2b: the login service's events copied as the API runs it: off unless the
// config names the directory token (email) and sign-in; on, it reads the
// issuer's event search with that token.
import { systemClock } from '@agentx/core/shared-kernel';
import { loadConfig } from '@agentx/platform/config';
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { createLogger } from '@agentx/platform/observability';
import type { OutboundFetch } from '@agentx/platform/outbound';
import { LogCapture, SequentialIds } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { idpEventCopierFrom } from './idp-events.ts';

const ISSUER = 'https://auth.agentx.example';
const ENDPOINT = 'https://acs.agentx.example';

const BASE = {
  AGENTX_ENV: 'development',
  AGENTX_DB_HOST: 'db',
  AGENTX_DB_PASSWORD: 'app login for these tests',
  AGENTX_KEYS_DIR: '/mnt/secrets',
};
const SIGN_IN = {
  ...BASE,
  AGENTX_OUTBOUND_ALLOWED_ORIGINS: `${ISSUER},${ENDPOINT}`,
  AGENTX_OIDC_ISSUER: ISSUER,
  AGENTX_OIDC_CLIENT_ID: 'agentx-api',
  AGENTX_OIDC_CLIENT_SECRET: 'client pass words',
};
const EMAIL = {
  ...SIGN_IN,
  AGENTX_EMAIL_ENDPOINT: ENDPOINT,
  AGENTX_EMAIL_SENDER: 'DoNotReply@agentx.example',
  // Plain words, built at run time, as every stand-in for a secret here.
  AGENTX_EMAIL_ACCESS_KEY: Buffer.from('stand in email words').toString('base64'),
  AGENTX_DIRECTORY_TOKEN: ['directory', 'words'].join('-'),
};

const keys = createKeyProvider(
  Object.fromEntries(
    PURPOSES.map((purpose, index) => [purpose, { current: 1, versions: new Map([[1, Buffer.alloc(32, index + 1)]]) }]),
  ),
);

/** The copier a config gives, with a database that fails every query, and a feed call recorded. */
function copierWith(env: Record<string, string>, fetch: OutboundFetch = () => Promise.reject(new Error('not called'))) {
  const capture = new LogCapture();
  const failing = new Proxy(
    {},
    {
      get: () => () => {
        throw new Error('no database in this test');
      },
    },
  );
  const copier = idpEventCopierFrom({
    config: loadConfig(env),
    database: failing as never,
    keys,
    ids: new SequentialIds(),
    clock: systemClock,
    outbox: {} as never,
    fetch,
    logger: createLogger({ service: 'api', config: loadConfig(BASE), destination: capture }),
  });
  return { copier, capture };
}

describe('SEC-OPS-02 the login service’s events copied as the API runs it (B6-2b)', () => {
  it('is off without email or sign-in in the config, and on with both', () => {
    expect(copierWith(BASE).copier).toBeUndefined();
    expect(copierWith(SIGN_IN).copier).toBeUndefined();
    expect(copierWith(EMAIL).copier).toBeDefined();
  });

  it('reads the second factors a person holds with the reset token when the config names it (the S68 audit)', () => {
    // Plain words, built at run time, as every stand-in for a secret here.
    const withResets = { ...EMAIL, AGENTX_FACTOR_RESET_TOKEN: ['reset', 'words'].join('-') };

    expect(loadConfig(withResets).factorResets).toBeDefined();
    expect(copierWith(withResets).copier).toBeDefined();
  });

  it('never throws when it can’t read where it got to: it logs, and waits for its next run', async () => {
    const { copier, capture } = copierWith(EMAIL);

    await expect(copier?.run()).resolves.toBeUndefined();
    expect(capture.lines().map(({ event }) => event)).toEqual(['idp_events.run_failed']);
  });
});
