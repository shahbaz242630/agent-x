import { describe, expect, it } from 'vitest';

import { clientAddress, clientKey, UNREADABLE_ADDRESS } from './rate-limit.ts';

describe('SEC-AV-07 the key a request is counted under', () => {
  it.each([
    ['an IPv4 address', '203.0.113.9', '203.0.113.9'],
    ['an IPv4 address with a port', '203.0.113.9:40001', '203.0.113.9'],
    ['an IPv4-mapped address, as a dual-stack server sees IPv4 clients', '::ffff:203.0.113.9', '203.0.113.9'],
    ['an IPv6 address, counted per /64', '2001:db8:1:2:aaaa:bbbb:cccc:dddd', '2001:db8:1:2::'],
    ['another address in the same /64', '2001:db8:1:2::7', '2001:db8:1:2::'],
    ['a bracketed IPv6 address with a port', '[2001:db8:1:2::7]:443', '2001:db8:1:2::'],
    ['a bracketed IPv6 address without one', '[2001:db8:1:2::7]', '2001:db8:1:2::'],
  ])('keys %s by the address', (_what, ip, expected) => {
    expect(clientKey(ip)).toBe(expected);
  });

  it.each([
    ["a request whose connection closed first, so Node can't give its address", undefined],
    ['text that is no address', 'unknown'],
    ['an empty value', ''],
    ['an IPv4 address with a port too big', '203.0.113.9:999999'],
    ['an IPv6 address with a zone', 'fe80::1%eth0'],
  ])('puts %s in one shared bucket, and never throws', (_what, ip) => {
    expect(clientKey(ip)).toBe(UNREADABLE_ADDRESS);
  });
});

describe('SEC-AV-07 the client address the security events keep', () => {
  it.each([
    ['an IPv4 address', '203.0.113.9', '203.0.113.9'],
    ['an IPv4 address with a port', '203.0.113.9:40001', '203.0.113.9'],
    ['an IPv4-mapped address', '::ffff:203.0.113.9', '::ffff:203.0.113.9'],
    ['an IPv6 address, whole, never per /64', '2001:db8:1:2:aaaa:bbbb:cccc:dddd', '2001:db8:1:2:aaaa:bbbb:cccc:dddd'],
    ['a bracketed IPv6 address with a port', '[2001:db8:1:2::7]:443', '2001:db8:1:2::7'],
    ['a bracketed IPv6 address without one', '[2001:db8:1:2::7]', '2001:db8:1:2::7'],
  ])('keeps %s without its port or brackets', (_what, ip, expected) => {
    expect(clientAddress(ip)).toBe(expected);
  });

  it.each([
    ['a request whose connection closed first', undefined],
    ['text that is no address', 'unknown'],
    ['an empty value', ''],
    ['an IPv4 address with a port too big', '203.0.113.9:999999'],
    ['an IPv6 address with a zone', 'fe80::1%eth0'],
    ['text that passes a URL parse as a bracketed host', '::1]/x'],
  ])('has none for %s, and never throws', (_what, ip) => {
    expect(clientAddress(ip)).toBeUndefined();
  });
});
