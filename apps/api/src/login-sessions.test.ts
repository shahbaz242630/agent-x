// S88: the sign-out's session ending at the login service, as the API wires
// it: off unless the config names the reset token and sign-in.
import { loadConfig } from '@agentx/platform/config';
import { describe, expect, it } from 'vitest';

import { loginSessionsFrom } from './login-sessions.ts';

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

describe('ending the login service sessions at sign-out, as the API wires it', () => {
  it('is off without the reset token or sign-in in the config, and on with both', () => {
    expect(loginSessionsFrom(loadConfig(BASE))).toBeUndefined();
    expect(loginSessionsFrom(loadConfig(SIGN_IN))).toBeUndefined();
    expect(loginSessionsFrom(loadConfig(RESETS))).toBeDefined();
  });

  it('asks nothing of the login service for a person of another one', async () => {
    const sessions = loginSessionsFrom(loadConfig(RESETS));

    expect(await sessions?.endAll({ issuer: 'https://other.example', subject: '1' })).toBe(0);
  });
});
