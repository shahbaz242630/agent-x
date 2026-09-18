import { describe, expect, it } from 'vitest';

import { PURPOSES } from '../../packages/platform/src/keys/purposes.ts';
import { APP_KEYS, appKeysProblems } from './app-keys.ts';

const EVERY_V1 = PURPOSES.map((purpose) => `key-${purpose}-v1`);

describe("ADR-011 §2: the app's keys on Azure are the ones the API starts with", () => {
  it('holds a version 1 key for every purpose the app knows, and nothing else', () => {
    expect([...APP_KEYS].sort()).toEqual([...EVERY_V1].sort());
  });

  it('accepts a later version beside the first, as a rotation adds one', () => {
    expect(appKeysProblems([...EVERY_V1, 'key-audit-mac-v2'])).toEqual([]);
  });

  it.each([
    ['not a list', { keys: EVERY_V1 }, 'app-keys.json must be a list of key names'],
    ['a list with something else in it', [...EVERY_V1, 1], 'app-keys.json must be a list of key names'],
    [
      'a purpose the app has no key for',
      [...EVERY_V1, 'key-api-token-v1'],
      'key-api-token-v1 is not key-<purpose>-v<version> with a purpose the app knows',
    ],
    [
      'a name in another shape',
      [...EVERY_V1, 'audit-mac-v2'],
      'audit-mac-v2 is not key-<purpose>-v<version> with a purpose the app knows',
    ],
    [
      'version 0',
      [...EVERY_V1, 'key-audit-mac-v0'],
      'key-audit-mac-v0 is not key-<purpose>-v<version> with a purpose the app knows',
    ],
    ['a key twice', [...EVERY_V1, 'key-audit-mac-v1'], 'a key is listed more than once'],
    [
      'a purpose without its version 1',
      EVERY_V1.filter((key) => key !== 'key-audit-anchor-v1'),
      'key-audit-anchor-v1 is missing: the API needs it to start',
    ],
    [
      'a second payee index key',
      [...EVERY_V1, 'key-payee-index-v2'],
      'payee-index is never rotated in place (ADR-014 §3): only key-payee-index-v1 may exist',
    ],
  ])('refuses %s', (_what, list, problem) => {
    expect(appKeysProblems(list)).toEqual([problem]);
  });
});
