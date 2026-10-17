// Decision 25: the login service's names, as the API runs it: off unless the
// config names the directory token (email) and sign-in; on, it asks the
// issuer with that token.
import { loadConfig } from '@agentx/platform/config';
import { describe, expect, it } from 'vitest';

import { contactFillFrom, directoryNamesFrom } from './kept-names.ts';

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

describe('the login service’s names for the audit log (decision 25)', () => {
  it('is off without sign-in, or without the directory token', () => {
    const fetch = () => Promise.reject(new Error('not called'));
    expect(directoryNamesFrom(loadConfig(BASE), fetch)).toBeUndefined();
    expect(directoryNamesFrom(loadConfig(SIGN_IN), fetch)).toBeUndefined();
  });

  it('asks the issuer with the directory token when both are named', async () => {
    const asked: { url: string; authorization: string | null }[] = [];
    const directory = directoryNamesFrom(loadConfig(EMAIL), (url, init = {}) => {
      asked.push({ url: String(url), authorization: new Headers(init.headers).get('authorization') });
      return Promise.resolve(Response.json({ result: [] }));
    });

    expect(directory?.issuer).toBe(ISSUER);
    await directory?.entriesOf(['101']);
    expect(asked).toEqual([{ url: `${ISSUER}/v2/users`, authorization: 'Bearer directory-words' }]);
  });

  it('fills kept names only with the login service’s names to fill them from', () => {
    const fetch = () => Promise.reject(new Error('not called'));
    const parts = { database: {} as never, keys: {} as never, clock: { now: () => new Date() }, logger: {} as never };
    expect(contactFillFrom({ directory: undefined, ...parts })).toBeUndefined();
    expect(contactFillFrom({ directory: directoryNamesFrom(loadConfig(EMAIL), fetch), ...parts })).toHaveProperty(
      'run',
    );
  });
});
