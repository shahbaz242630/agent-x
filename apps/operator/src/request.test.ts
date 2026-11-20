// The request's format, shared by the command that reads it (main.ts) and the
// tool that writes it (deploy/azure/operator.ts). Both take its limit from
// here, so they can't disagree about it; what matters is that no name the
// organisation's rules allow is too long for it.
import { organizationName } from '@agentx/core/modules/organizations';
import { describe, expect, it } from 'vitest';

import {
  chainFlags,
  chainRecoveryRequest,
  chainRestoreRequest,
  createOrganizationRequest,
  DISCARD_FORK,
  PLAN_DIGEST_HEX,
  REQUEST_LIMIT_BYTES,
  SHORT_OF_ANCHOR,
  UUID_V7,
} from './request.ts';

describe('B1c-2b the request the operator is sent', () => {
  it('holds the longest name an organisation may have, in the widest letters UTF-8 writes, with room to spare', () => {
    // A letter beyond the first 65,536: four bytes in UTF-8, and one character to the name rules.
    const letter = String.fromCodePoint(0x1d49c);
    expect(() => organizationName(letter.repeat(201))).toThrow();
    const longest = organizationName(letter.repeat(200));
    const id = '0199a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b';
    expect(id).toMatch(UUID_V7);

    expect(Buffer.byteLength(createOrganizationRequest(longest, id))).toBeLessThan(REQUEST_LIMIT_BYTES);
  });

  it('is the command and its words, then the ID, as a JSON list', () => {
    expect(JSON.parse(createOrganizationRequest('Zephyrine Trading Test Co', 'an ID'))).toEqual([
      'create-organization',
      '--name',
      'Zephyrine Trading Test Co',
      '--id',
      'an ID',
    ]);
  });
});

describe('4D2e E10 the chain repair and its plan, asked with or without the named fork flag', () => {
  const asked = { orgId: 'org', planId: 'plan', digest: 'digest', id: 'id' };

  it('names the flag last, only when asked', () => {
    expect(JSON.parse(chainRecoveryRequest('org', 'plan'))).toEqual([
      'chain-recovery-plan',
      '--org',
      'org',
      '--id',
      'plan',
    ]);
    expect((JSON.parse(chainRecoveryRequest('org', 'plan', { discardFork: true })) as string[]).at(-1)).toBe(
      DISCARD_FORK,
    );
    expect(JSON.parse(chainRestoreRequest(asked))).toEqual([
      'chain-restore',
      '--org',
      'org',
      '--plan',
      'plan',
      '--digest',
      'digest',
      '--id',
      'id',
    ]);
    expect((JSON.parse(chainRestoreRequest(asked, { discardFork: true })) as string[]).at(-1)).toBe(DISCARD_FORK);
    // AT9: the short flag after the fork's, each only when asked.
    expect((JSON.parse(chainRestoreRequest(asked, { shortOfAnchor: true })) as string[]).at(-1)).toBe(SHORT_OF_ANCHOR);
    expect(
      (JSON.parse(chainRecoveryRequest('org', 'plan', { discardFork: true, shortOfAnchor: true })) as string[]).slice(
        -2,
      ),
    ).toEqual([DISCARD_FORK, SHORT_OF_ANCHOR]);
  });

  it('reads the named flags each at most once, in either order, and nothing else (AT9)', () => {
    expect(chainFlags([])).toEqual({ discardFork: false, shortOfAnchor: false });
    expect(chainFlags([SHORT_OF_ANCHOR])).toEqual({ discardFork: false, shortOfAnchor: true });
    expect(chainFlags([SHORT_OF_ANCHOR, DISCARD_FORK])).toEqual({ discardFork: true, shortOfAnchor: true });
    expect(chainFlags([DISCARD_FORK, DISCARD_FORK])).toBeUndefined();
    expect(chainFlags([SHORT_OF_ANCHOR, '--force'])).toBeUndefined();
  });

  it("takes a plan's digest as 64 lower-case hex digits alone", () => {
    expect('ab'.repeat(32)).toMatch(PLAN_DIGEST_HEX);
    expect('AB'.repeat(32)).not.toMatch(PLAN_DIGEST_HEX);
    expect('ab'.repeat(33)).not.toMatch(PLAN_DIGEST_HEX);
  });
});
