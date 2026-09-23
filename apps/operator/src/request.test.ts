// The request's format, shared by the command that reads it (main.ts) and the
// tool that writes it (deploy/azure/operator.ts). Both take its limit from
// here, so they can't disagree about it; what matters is that no name the
// organisation's rules allow is too long for it.
import { organizationName } from '@agentx/core/modules/organizations';
import { describe, expect, it } from 'vitest';

import { createOrganizationRequest, REQUEST_LIMIT_BYTES, UUID_V7 } from './request.ts';

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
