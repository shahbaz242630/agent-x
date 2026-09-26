import { findLeaks, SENSITIVE_SAMPLES as SAMPLES } from '@agentx/testing';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { hasValidIbanCheckDigits, isPlainConstant, passesLuhn, scrub } from './scrub.ts';

/** Built from parts, so secret scanners reading this file don't mistake it for a real credential. */
const join = (...parts: string[]): string => parts.join('');
const NBSP = String.fromCharCode(0xa0);
/** fast-check runs are seeded, so the tests are deterministic (Rule Book §6). */
const RUNS = { numRuns: 300, seed: 20_260_914 };

describe('SEC-DATA-01 scrub: secrets and credentials', () => {
  it.each([
    ['a JWT', `seen ${SAMPLES.jwt} today`, 'seen [jwt] today'],
    ['a JWT cut short', `eyJ${'a'.repeat(30)}`, '[jwt]'],
    ['a JWT run into a word', `jwt_${SAMPLES.jwt}`, 'jwt_[jwt]'],
    ['a Bearer token', `header ${SAMPLES.bearer}`, 'header Bearer [redacted]'],
    ['a lowercase bearer token', `bearer ${'q'.repeat(12)}`, 'Bearer [redacted]'],
    ['a Bearer token run into a word', `x${SAMPLES.bearer}`, 'xBearer [redacted]'],
    ['Basic credentials', `header ${SAMPLES.basic}`, 'header Basic [redacted]'],
    ['an Authorization header, whatever its scheme', 'Authorization: Token abc123def456', 'Authorization: [redacted]'],
    [
      'an authorization field inside JSON text',
      '{"authorization":"Token abc123def456"}',
      '{"authorization":"[redacted]"}',
    ],
    ['an agent key, keeping its key ID', `key ${SAMPLES.agentKey} used`, 'key axk_k7Fq2_… used'],
    ['an agent key run into a word', `key_${SAMPLES.agentKey}`, 'key_axk_k7Fq2_…'],
    ['an agent key in standard base64', join('axk_k7Fq2_', 'abcDEF+ghiJKL/mnoPQR='), 'axk_k7Fq2_…'],
    ['a password given in text', SAMPLES.secretAssignment, 'password=[redacted]'],
    ['an access token inside JSON text', SAMPLES.jsonSecret, '{"access_token":[redacted]}'],
    ['an API key header line', join('x-api-key: ', 'sk_live_', 'abc123'), 'x-api-key: [redacted]'],
    [
      'a client secret in a form body',
      join('client_secret=', 'abc', '&grant_type=authorization_code'),
      'client_secret=[redacted]&grant_type=authorization_code',
    ],
    ['a session ID', join('session_id=', 'abc123'), 'session_id=[redacted]'],
    ['a signature parameter', join('?sig=', 'abcdef123'), '?sig=[redacted]'],
  ])('%s', (_what, text, expected) => {
    expect(scrub(text)).toBe(expected);
  });
});

describe('SEC-DATA-01 scrub: OAuth code and state (ADR-011 §7)', () => {
  it.each([
    ['in a callback URL', SAMPLES.oauthCallback, 'https://console.example/callback'],
    ['in a relative callback path', SAMPLES.relativeCallback, '/oauth/callback'],
    [
      'in an error message',
      join('token exchange failed: code=', 'c0dexxxx state=', 's7yyyy'),
      'token exchange failed: code=[redacted] state=[redacted]',
    ],
    [
      'in a URL without a scheme',
      join('console.example.com/callback?code=', 'c0dexxxxxxxx'),
      'console.example.com/callback?code=[redacted]',
    ],
    [
      'in a URL with a long scheme',
      join('mycompanyoauthcallbackapp://cb?code=', 'c0dexxxxxxxx'),
      'mycompanyoauthcallbackapp://cb',
    ],
    [
      'in a JSON-escaped URL',
      join('{"redirect":"https:\\/\\/console.example\\/cb?code=', 'c0dexxxxxxxx"}'),
      '{"redirect":"https:\\/\\/console.example\\/cb?code=[redacted]"}',
    ],
  ])('%s', (_what, text, expected) => {
    expect(scrub(text)).toBe(expected);
  });

  it.each(['exit code=1', 'state=APPROVED', 'state=pending', 'code=ECONNRESET', 'code=23505'])(
    'keeps %s, which is plainly not a secret',
    (text) => {
      expect(scrub(text)).toBe(text);
    },
  );
});

describe('SEC-DATA-01 scrub: personal and payment details', () => {
  it.each([
    ['an email', `contact ${SAMPLES.email} now`, 'contact [email] now'],
    ['an email with a long domain', 'x@mail.sub.example.co.uk', '[email]'],
    ['an email in another script', `from ${SAMPLES.unicodeEmail}`, 'from [email]'],
    ['a URL-encoded email', '/users/someone%40example.com/x', '/users/[email]/x'],
    ['a UAE IBAN', `pay ${SAMPLES.uaeIban}.`, 'pay [iban].'],
    ['a UAE IBAN in spaced groups', `pay ${SAMPLES.spacedUaeIban}`, 'pay [iban]'],
    ['another country’s IBAN', join('GB82', 'WEST', '1234', '5698', '7654', '32'), '[iban]'],
    ['an IBAN after the word IBAN', join('IBAN', SAMPLES.uaeIban), 'IBAN[iban]'],
    ['an IBAN followed by lowercase text', join(SAMPLES.uaeIban, 'is'), '[iban]is'],
    ['an IBAN, then a word starting with a capital', `${SAMPLES.uaeIban} Bearer`, '[iban] Bearer'],
    ['a spaced IBAN, then a word starting with a capital', `${SAMPLES.spacedUaeIban} Bearer`, '[iban] Bearer'],
    [
      'a spaced IBAN ending in a full group of four, then a capital',
      join('CZ65 ', '0800 ', '0000 ', '1920 ', '0014 ', '5399', ' Bearer'),
      '[iban] Bearer',
    ],
    ['a lowercase IBAN with valid check digits', `iban ${SAMPLES.lowercaseIban}`, 'iban [iban]'],
    ['a dashed lowercase IBAN', join('gb82-', 'west-', '1234-', '5698-', '7654-', '32'), '[iban]'],
    ['an IBAN grouped with non-breaking spaces', ['gb82', 'west', '1234', '5698', '7654', '32'].join(NBSP), '[iban]'],
    ['an Emirates ID', `id ${SAMPLES.emiratesId}`, 'id [emirates-id]'],
    ['an Emirates ID without dashes', join('784', '1990', '1234567', '1'), '[emirates-id]'],
    ['a card number', `card ${SAMPLES.card}`, 'card [card]'],
    ['a dashed card number', join('4111-', '1111-', '1111-', '1111'), '[card]'],
    ['a card number run together', join('4111', '1111', '1111', '1111'), '[card]'],
    ['a card number right after another number', `call 050 123 4567 ${SAMPLES.card} now`, 'call [phone] [card] now'],
    ['an American Express layout', join('3782 ', '822463 ', '10005'), '[card]'],
    ['a Diners layout', join('3056 ', '930902 ', '5904'), '[card]'],
    ['a phone number', `call ${SAMPLES.phone}`, 'call [phone]'],
    ['a phone number without spaces', 'call +971501234567', 'call [phone]'],
    ['a phone number with 00', 'call 00971501234567', 'call [phone]'],
    ['a phone number with brackets', 'call +971 (50) 123 4567', 'call [phone]'],
    ['a phone number with dots', 'call +971.50.123.4567', 'call [phone]'],
    ['a phone number with double spaces', 'call +971  50  123  4567', 'call [phone]'],
    ['a UAE mobile written locally', `call ${SAMPLES.localMobile}`, 'call [phone]'],
    ['a UAE mobile written locally without spaces', 'call 0501234567', 'call [phone]'],
  ])('%s', (_what, text, expected) => {
    expect(scrub(text)).toBe(expected);
  });
});

describe('SEC-DATA-01 scrub: IP addresses (ADR-011 §7)', () => {
  it.each([
    ['IPv4 addresses', `from ${SAMPLES.ipv4} via 10.0.0.1`, 'from [ip] via [ip]'],
    ['an IPv4 address ending a sentence', `from ${SAMPLES.ipv4}.`, 'from [ip].'],
    ['an IPv4 address after a dot', `host.${SAMPLES.ipv4}`, 'host.[ip]'],
    ['an IPv4 address with padded parts', '192.000.002.044', '[ip]'],
    ['an IPv6 address', `from ${SAMPLES.ipv6}`, 'from [ip]'],
    ['an IPv6 address written in full', '2001:0db8:0000:0000:0000:ff00:0042:8329', '[ip]'],
    ['an IPv6 address with a zone', 'fe80::1%eth0', '[ip]%eth0'],
    ['an IPv6 address ending in IPv4', `peer ${SAMPLES.mappedIpv6}`, 'peer [ip]'],
    ['an IPv6 address ending in IPv4, with a port', `${SAMPLES.mappedIpv6}:52341`, '::ffff:[ip]:52341'],
    ['an IPv6 address after a colon', `peer:${SAMPLES.ipv6}`, 'peer:[ip]'],
    ['an IPv6 address in brackets with a port', '[2001:db8::1]:443', '[[ip]]:443'],
    ['a full IPv6 address ending in IPv4', '1:2:3:4:5:6:1.2.3.4', '[ip]'],
  ])('%s', (_what, text, expected) => {
    expect(scrub(text)).toBe(expected);
  });
});

describe('SEC-DATA-01 scrub: URLs keep where they point, and lose credentials, query and fragment', () => {
  it.each([
    ['a user name and password', SAMPLES.credentialUrl, 'https://api.partner.example/v1'],
    ['a fragment', 'https://console.example/app#section', 'https://console.example/app'],
    [
      'trailing punctuation, which stays',
      'see (https://api.partner.example/x?y=1).',
      'see (https://api.partner.example/x).',
    ],
    [
      'a database URL',
      join('postgres://app', ':', 'plain-words', '@db.example:5432/agentx?sslmode=require'),
      'postgres://db.example:5432/agentx',
    ],
    [
      'a database URL whose password contains a slash, which the parser refuses',
      join('postgres://app', ':', 'Zm9vYmFy/cXV4eg', '@db.example:5432/agentx'),
      'postgres://db.example:5432/agentx',
    ],
    ['an IP address host', 'http://192.0.2.10:8080/health', 'http://[ip]:8080/health'],
    ['an email in the path', `https://api.example/users/${SAMPLES.email}/x`, 'https://api.example/users/[email]/x'],
    ['a relative path with a query, as a framework logs it', 'GET /v1/requests?limit=10 200', 'GET /v1/requests 200'],
    // The 0e D security review: a quote in a query used to end the match, and what followed stayed.
    [
      'a relative path whose query holds a quote',
      "GET /v1/suppliers/x?a='note=private-query-value 200",
      'GET /v1/suppliers/x 200',
    ],
    [
      'a quoted path whose query holds a quote, as Fastify quotes it',
      `in "/v1/suppliers/x?a='note=private-query-value" (GET)`,
      'in "/v1/suppliers/x" (GET)',
    ],
    [
      'a URL inside JSON text, which keeps the fields after it',
      'partner said {"next":"https://api.partner.example/v1?page=2","code":"E_LIMIT","retry":30}',
      'partner said {"next":"https://api.partner.example/v1","code":"E_LIMIT","retry":30}',
    ],
    [
      'a URL whose query holds a quote',
      "calling https://api.partner.example/v1?a='note=private-query-value now",
      'calling https://api.partner.example/v1 now',
    ],
    [
      'a quoted URL with no query, which stays as written',
      "'https://api.partner.example/v1'",
      "'https://api.partner.example/v1'",
    ],
  ])('%s', (_what, text, expected) => {
    expect(scrub(text)).toBe(expected);
  });
});

describe('scrub: ordinary log text is left alone', () => {
  it.each([
    ['an ISO timestamp', '2026-09-14T10:15:30.123Z'],
    ['a time of day', '10:15:30'],
    ['a UUIDv7', '01920000-0000-7000-8000-000000000001'],
    ['an uppercase UUID', '0192A1B2-C3D4-7E5F-8A9B-0C1D2E3F4A5B'],
    ['a UUID with an IBAN-shaped group whose check digits are right', '01a0ddb2-aa97-74f9-a825-d554be9c16c3'],
    ['the same UUID in capitals', '01A0DDB2-AA97-74F9-A825-D554BE9C16C3'],
    ['a config hash', `sha256:${'ab12'.repeat(16)}`],
    ['a short lowercase hex value', 'ab12cd34ef56ab78cd90ef12ab34cd56'],
    ['a reason code', 'DUPLICATE_ORDER_REFERENCE'],
    ['an event name', 'spend_request.decided'],
    ['a version', 'pino 10.3.1'],
    ['a stack position', 'at loadConfig (/app/packages/platform/src/config/config.ts:141:11)'],
    ['a Windows stack position', 'at run (C:\\app\\src\\main.ts:12:34)'],
    ['a package path in a stack', 'at x (/app/node_modules/.pnpm/vitest@4.1.11/node_modules/vitest/dist/index.js:1:2)'],
    ['an amount', 'AED 1,000.00'],
    ['a short word after Bearer, too short to be a token', 'Bearer abc'],
    ['an octet out of range', '256.1.1.1'],
    ['C++-style scope', 'std::string'],
    ['a MAC address', '00:1a:2b:3c:4d:5e'],
    ['a plain http origin with a port', 'http://localhost:8080'],
    ['a state-machine state', 'state: UNKNOWN'],
    ['words about tokens and authorization', 'the token expired; authorization failed: role missing'],
    ['a sixteen-digit number that fails the Luhn check', '4111111111111112'],
    ['a long run of number groups with no card in it', '2026 09 14 1015 3000 1200 4500 7800 9900'],
    ['digits that pass the Luhn check, grouped unlike a card', '4111 11 1111 1111 11'],
    ['a status and a duration', 'status 404 after 1200 ms'],
  ])('%s', (_what, text) => {
    expect(scrub(text)).toBe(text);
  });

  // Each of these would, inside other text, look like a phone number or an Emirates ID in part.
  const PHONE_LIKE = `0012345678${'ab'.repeat(27)}`;
  const EMIRATES_ID_LIKE = `ab784198712345671${'c'.repeat(47)}`;

  it.each([
    ['a hash', PHONE_LIKE],
    ['another hash', EMIRATES_ID_LIKE],
    ['a config hash', `sha256:${PHONE_LIKE}`],
  ])('%s, whole, even where part of it looks like a personal detail', (_what, hash) => {
    expect(hash).toMatch(/^(?:sha256:)?[0-9a-f]{64}$/);
    expect(scrub(hash)).toBe(hash);
  });

  it.each([
    ['after other text', `head ${PHONE_LIKE}`],
    ['before other text', `${PHONE_LIKE} seen`],
    ['cut short', PHONE_LIKE.slice(0, 63)],
    ['in capitals', PHONE_LIKE.toUpperCase()],
    ['with another prefix', `sha1:${EMIRATES_ID_LIKE}`],
  ])('but cleans the same text %s, as usual', (_what, text) => {
    expect(scrub(text)).not.toBe(text);
  });
});

describe('scrub: check-digit helpers', () => {
  it.each([
    [SAMPLES.uaeIban, true],
    [SAMPLES.lowercaseIban, true],
    [join('AE07', '0331', '2345', '6789', '0123', '457'), false],
  ])('IBAN %s has valid check digits: %s', (iban, valid) => {
    expect(hasValidIbanCheckDigits(iban)).toBe(valid);
  });

  it.each([
    ['4111111111111111', true],
    ['4111111111111112', false],
    ['79927398713', true],
  ])('%s passes the Luhn check: %s', (digits, valid) => {
    expect(passesLuhn(digits)).toBe(valid);
  });

  it.each([
    ['1', true],
    ['23505', true],
    ['approved', true],
    ['ERR_HTTP2_STREAM_ERROR', true],
    ['c0deAbc123', false],
    ['1234567', false],
  ])('%s is a plain constant: %s', (value, plain) => {
    expect(isPlainConstant(value)).toBe(plain);
  });
});

describe('scrub: properties that hold for any text', () => {
  const filler = fc.string({ unit: fc.constantFrom(...Array.from('abcdefghij klmnop,;()')), maxLength: 30 });
  const separator = fc.constantFrom(' ', '.', ',', ';', '(', ')', '"', '\t', '\n');
  const sample = fc.constantFrom(...Object.values(SAMPLES));

  it('hides each sensitive sample, whatever punctuation and text surround it', () => {
    fc.assert(
      fc.property(filler, separator, sample, separator, filler, (before, open, secret, close, after) => {
        const cleaned = scrub(`${before}${open}${secret}${close}${after}`);
        expect(cleaned).not.toContain(secret);
        expect(findLeaks(cleaned)).toEqual([]);
      }),
      RUNS,
    );
  });

  it('leaves any UUID as it is, in either case, whole or in a sentence', () => {
    fc.assert(
      fc.property(fc.uuid(), (id) => {
        expect(scrub(id)).toBe(id);
        expect(scrub(id.toUpperCase())).toBe(id.toUpperCase());
        // In a sentence, one starting `00` is hidden as a phone number, the safe way to be wrong;
        // ours are UUIDv7s, whose time can't start `00` after 2004.
        if (!id.startsWith('00')) expect(scrub(`invitation ${id} accepted`)).toBe(`invitation ${id} accepted`);
      }),
      { ...RUNS, numRuns: 5000 },
    );
  });

  it('changes nothing when run twice', () => {
    const text = fc.array(fc.oneof(filler, sample), { maxLength: 6 }).map((parts) => parts.join(' '));
    fc.assert(
      fc.property(text, (value) => {
        const once = scrub(value);
        expect(scrub(once)).toBe(once);
      }),
      RUNS,
    );
  });
});

describe('scrub: runs in time proportional to the text, so a hostile value cannot stall logging', () => {
  // 150,000 characters: measured on this code, an unbounded email pattern takes
  // about 1 second at 50,000 and grows with the square, so about 9 seconds
  // here; the bounded patterns take milliseconds.
  const LENGTH = 150_000;
  it.each([
    ['a long run of email characters with no @', 'a'.repeat(LENGTH)],
    ['a long run of email characters, then an @ and no domain end', `${'a'.repeat(LENGTH)}@${'b'.repeat(100)}`],
    ['many agent-key starts', 'axk_a'.repeat(LENGTH / 5)],
    ['many colons', ':a'.repeat(LENGTH / 2)],
    ['many dots between digits', '1.'.repeat(LENGTH / 2)],
    ['many scheme-like words', 'ab://'.repeat(LENGTH / 5)],
    ['a long run of capitals and digits', 'AB12'.repeat(LENGTH / 4)],
    ['many name-like prefixes', 'a_'.repeat(LENGTH / 2)],
    ['many path starts', ' /'.repeat(LENGTH / 2)],
    ['many code parameters', 'code='.repeat(LENGTH / 5)],
    ['many card-like groups', '4111 '.repeat(LENGTH / 5)],
    ['many IBAN-like groups', 'AE07 '.repeat(LENGTH / 5)],
    ['many phone-like starts', '+9 '.repeat(LENGTH / 3)],
    ['a long run of closing brackets after a scheme', `a://${')'.repeat(LENGTH)}x`],
  ])('%s', (_what, text) => {
    const started = performance.now();
    scrub(text);
    expect(performance.now() - started).toBeLessThan(1500);
  });
});
