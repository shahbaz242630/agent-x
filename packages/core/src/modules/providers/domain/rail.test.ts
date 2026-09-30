// The S68 audit: a partner's page is sent to a person's browser only when it is
// the partner's own, over HTTPS, naming no one's credentials.
import { describe, expect, it } from 'vitest';

import { isPartnerPage } from './rail.ts';

const ORIGIN = 'https://bank.partner.example';

describe('isPartnerPage (the S68 audit)', () => {
  it('takes a page of the partner’s own origin, over HTTPS', () => {
    expect(isPartnerPage(`${ORIGIN}/authorise/abc?x=1`, ORIGIN)).toBe(true);
  });

  it.each([
    ['a script', 'javascript:alert(1)'],
    ['data', 'data:text/html,hi'],
    ['another host', 'https://bank.partner.example.evil.example/authorise'],
    ['another port', 'https://bank.partner.example:8443/authorise'],
    ['a name', 'https://someone@bank.partner.example/authorise'],
    ['a password', 'https://:words@bank.partner.example/authorise'],
    ['no address', 'bank.partner.example/authorise'],
  ])('refuses %s', (_what, page) => {
    expect(isPartnerPage(page, ORIGIN)).toBe(false);
  });

  it('refuses plain HTTP even from an adapter that names a plain-HTTP origin by mistake', () => {
    expect(isPartnerPage('http://bank.partner.example/authorise', 'http://bank.partner.example')).toBe(false);
  });
});
