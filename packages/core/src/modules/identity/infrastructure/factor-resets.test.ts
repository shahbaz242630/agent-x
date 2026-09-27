// B6-3b-3: a contact's link token read back, the public route's only input:
// three IDs and a secret of 32 random bytes in base64url, joined by dots,
// nothing before or after.
import { describe, expect, it } from 'vitest';

import { resetLinkToken } from './factor-resets.ts';

const ORG = '0199A0F0-0000-7000-8000-00000000B6F1';
const RESET = '0199a0f0-0000-7000-8000-00000000b6f2';
const CONTACT = '0199a0f0-0000-7000-8000-00000000b6f3';
/** The link's last part: base64url's every kind of character, built as the test runs. */
const LAST = ['Ab-_', '0123456789', 'x'.repeat(29)].join('');

describe('SEC-OPS-04 a contact’s link token (B6-3b-3)', () => {
  it('reads the organisation, reset and contact in lower case, and the secret as written', () => {
    expect(LAST).toHaveLength(43);

    expect(resetLinkToken(`${ORG}.${RESET}.${CONTACT}.${LAST}`)).toEqual({
      orgId: ORG.toLowerCase(),
      resetId: RESET,
      contactId: CONTACT,
      secret: LAST,
    });
  });

  it.each([
    ['a secret a character short', `${ORG}.${RESET}.${CONTACT}.${LAST.slice(1)}`],
    ['a secret a character long', `${ORG}.${RESET}.${CONTACT}.${LAST}A`],
    ['a secret with a character base64url has none of', `${ORG}.${RESET}.${CONTACT}.${LAST.slice(1)}+`],
    ['anything before it', `x${ORG}.${RESET}.${CONTACT}.${LAST}`],
    ['anything after it', `${ORG}.${RESET}.${CONTACT}.${LAST}.x`],
    ['an ID missing', `${ORG}.${RESET}.${LAST}`],
    ['an ID not one', `${ORG}.${RESET}.not-an-id.${LAST}`],
    ['nothing', ''],
  ])('reads nothing from a token with %s', (_what, token) => {
    expect(resetLinkToken(token)).toBeUndefined();
  });
});
