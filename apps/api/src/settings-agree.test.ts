// Limits the config and a module each hold, which must agree.
//
// - The sessions' sweep (B2-4a) deletes a session unused past the longest idle
//   timeout there can be (LONGEST_IDLE_SECONDS), whatever this process's own
//   setting. That holds only while the config refuses anything longer: if its
//   maximum grew alone, a session a longer setting still accepts could be swept.
// - The security events' module refuses a retention under LEAST_RETENTION_DAYS
//   (B2-5a); the config's minimum must be the same, or a start would fail on a
//   setting the config had accepted.
import { LONGEST_IDLE_SECONDS } from '@agentx/core/modules/identity';
import { LEAST_RETENTION_DAYS } from '@agentx/core/modules/security-events';
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

describe("the security events' shortest retention: the config's and the module's are one", () => {
  it('takes exactly the shortest the module allows', () => {
    expect(
      loadConfig({ ...LOCAL, AGENTX_SECURITY_EVENT_RETENTION_DAYS: String(LEAST_RETENTION_DAYS) }).securityEvents,
    ).toEqual({ retentionDays: LEAST_RETENTION_DAYS });
  });

  it('refuses a day less', () => {
    expect(() =>
      loadConfig({ ...LOCAL, AGENTX_SECURITY_EVENT_RETENTION_DAYS: String(LEAST_RETENTION_DAYS - 1) }),
    ).toThrow(ConfigError);
  });
});
