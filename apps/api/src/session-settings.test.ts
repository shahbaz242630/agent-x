// The sessions' sweep (B2-4a) deletes a session unused past the longest idle
// timeout there can be (LONGEST_IDLE_SECONDS), whatever this process's own
// setting. That holds only while the config refuses anything longer: if its
// maximum grew alone, a session a longer setting still accepts could be swept.
import { LONGEST_IDLE_SECONDS } from '@agentx/core/modules/identity';
import { ConfigError, loadConfig } from '@agentx/platform/config';
import { describe, expect, it } from 'vitest';

const DB_LOGIN = 'app login for these tests';
const LOCAL = {
  AGENTX_ENV: 'development',
  AGENTX_DB_HOST: 'db',
  AGENTX_DB_PASSWORD: DB_LOGIN,
  AGENTX_KEYS_DIR: '/mnt/secrets',
  AGENTX_SESSION_ABSOLUTE_HOURS: '24',
};

describe("the longest idle timeout: the config's and the sweep's are one", () => {
  it('takes an idle timeout of exactly the longest the sweep allows for', () => {
    expect(loadConfig({ ...LOCAL, AGENTX_SESSION_IDLE_MINUTES: String(LONGEST_IDLE_SECONDS / 60) }).sessions).toEqual({
      idleSeconds: LONGEST_IDLE_SECONDS,
      absoluteSeconds: 24 * 3600,
    });
  });

  it('refuses a minute more', () => {
    expect(() => loadConfig({ ...LOCAL, AGENTX_SESSION_IDLE_MINUTES: String(LONGEST_IDLE_SECONDS / 60 + 1) })).toThrow(
      ConfigError,
    );
  });
});
