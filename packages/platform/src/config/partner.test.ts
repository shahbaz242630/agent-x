import { describe, expect, it } from 'vitest';

import { ConfigError } from './common.ts';
import {
  BUILT_PARTNER,
  declarationProblems,
  declarePartner,
  type PartnerDeclaration,
  recordedStartWith,
  startedLive,
} from './partner.ts';

const LIVE = 'https://pay.bank.example';
const SANDBOX = 'https://sandbox.bank.example';
const GOOD: PartnerDeclaration = { liveOrigins: [LIVE], sandboxOrigins: [SANDBOX] };
const NOT_AN_ORIGIN =
  'is not an https origin as the allowlist writes it: lowercase, no default port, path, user name or trailing dot';

describe('SEC-OPS-07 the partner’s declaration is checked where it is written (PM3, S138 review)', () => {
  it('takes https origins written as the allowlist writes them, and keeps a frozen copy', () => {
    const live = [LIVE];
    const declared = declarePartner({ liveOrigins: live, sandboxOrigins: [SANDBOX] });
    live.push('https://other.bank.example');
    expect(declared).toEqual(GOOD);
    expect(Object.isFrozen(declared)).toBe(true);
    expect(Object.isFrozen(declared.liveOrigins)).toBe(true);
    expect(Object.isFrozen(declared.sandboxOrigins)).toBe(true);
    expect(declarationProblems({ liveOrigins: [LIVE, 'https://pay.bank.example:8443'], sandboxOrigins: [] })).toEqual(
      [],
    );
  });

  it('refuses a declaration with no live origin, which would let any allowlist through', () => {
    expect(declarationProblems({ liveOrigins: [], sandboxOrigins: [SANDBOX] })).toEqual([
      "BUILT_PARTNER: declares no live origin, so nothing would keep an app that isn't live from reaching it",
    ]);
  });

  it.each([
    ['a trailing slash', `${LIVE}/`],
    ['a path', `${LIVE}/v1`],
    ['a query', `${LIVE}?x=1`],
    ['a fragment', `${LIVE}#x`],
    ['a user name', 'https://someone@pay.bank.example'],
    ['upper case', 'https://Pay.Bank.example'],
    ['the default port', 'https://pay.bank.example:443'],
    ['a trailing dot', 'https://pay.bank.example.'],
    ['a trailing dot before a port', 'https://pay.bank.example.:8443'],
    ['plain http', 'http://pay.bank.example'],
    ['another scheme', 'wss://pay.bank.example'],
    ['no scheme', 'pay.bank.example'],
    ['a wildcard', 'https://*.bank.example'],
    ['nothing', ''],
  ])('refuses a live or sandbox origin with %s', (_, origin) => {
    expect(declarationProblems({ liveOrigins: [LIVE, origin], sandboxOrigins: [SANDBOX] })).toEqual([
      `BUILT_PARTNER: live origin 2 ${NOT_AN_ORIGIN}`,
    ]);
    expect(declarationProblems({ liveOrigins: [LIVE], sandboxOrigins: [origin, SANDBOX, origin] })).toEqual([
      `BUILT_PARTNER: sandbox origin 1, 3 ${NOT_AN_ORIGIN}`,
    ]);
  });

  it('refuses an origin declared both live and sandbox', () => {
    expect(declarationProblems({ liveOrigins: [SANDBOX, LIVE], sandboxOrigins: [LIVE] })).toEqual([
      "BUILT_PARTNER: live origin 2 is a sandbox origin too, so live and sandbox can't be told apart",
    ]);
  });

  it('reports every problem at once, and declarePartner throws them as a config error', () => {
    const wrong = { liveOrigins: [], sandboxOrigins: [`${SANDBOX}/`] };
    expect(() => declarePartner(wrong)).toThrow(ConfigError);
    try {
      declarePartner(wrong);
    } catch (error) {
      expect((error as ConfigError).problems).toEqual([
        "BUILT_PARTNER: declares no live origin, so nothing would keep an app that isn't live from reaching it",
        `BUILT_PARTNER: sandbox origin 1 ${NOT_AN_ORIGIN}`,
      ]);
    }
  });

  it('holds no partner until its adapter is built (Phase 5), and a built one passes its own check', () => {
    expect(BUILT_PARTNER === undefined || declarationProblems(BUILT_PARTNER).length === 0).toBe(true);
  });
});

describe('SEC-OPS-07 the point-of-use check reads the start this process recorded (ADR-014 §4)', () => {
  it('is live only once a live start is recorded, and follows each start recorded after', () => {
    expect(startedLive()).toBe(false);
    recordedStartWith({ mode: 'fake' });
    expect(startedLive()).toBe(false);
    recordedStartWith({ mode: 'sandbox' });
    expect(startedLive()).toBe(false);
    recordedStartWith({ mode: 'live', gateRef: `LMG-v1-sha256:${'ab'.repeat(32)}` });
    expect(startedLive()).toBe(true);
    recordedStartWith({ mode: 'fake' });
    expect(startedLive()).toBe(false);
    recordedStartWith({ mode: 'live', gateRef: `LMG-v1-sha256:${'ab'.repeat(32)}` });
    recordedStartWith(undefined);
    expect(startedLive()).toBe(false);
  });
});
