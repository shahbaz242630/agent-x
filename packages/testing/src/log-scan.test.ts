import { describe, expect, it } from 'vitest';

import { findLeaks, LogCapture, SENSITIVE_SAMPLES as SAMPLES } from './log-scan.ts';

describe('FX-LOGSCAN: each detector finds what it is for', () => {
  it.each([
    ['uae-iban', SAMPLES.uaeIban],
    ['uae-iban', SAMPLES.spacedUaeIban],
    ['iban', SAMPLES.lowercaseIban],
    ['iban', 'gb82 west 1234 5698 7654 32 today'],
    ['email', SAMPLES.email],
    ['email', SAMPLES.unicodeEmail],
    ['email', 'someone%40example.com'],
    ['ipv4', SAMPLES.ipv4],
    ['ipv6', SAMPLES.ipv6],
    ['ipv6', '2001:0db8:0000:0000:0000:ff00:0042:8329'],
    ['phone', SAMPLES.phone],
    ['phone', SAMPLES.localMobile],
    ['card', SAMPLES.card],
    ['emirates-id', SAMPLES.emiratesId],
    ['bearer-token', SAMPLES.bearer],
    ['basic-credentials', SAMPLES.basic],
    ['oauth-parameter', SAMPLES.oauthCallback],
    ['oauth-parameter', SAMPLES.relativeCallback],
    ['oauth-parameter', '{"code":"c0dexxxxxxxx"}'],
    ['secret-assignment', SAMPLES.secretAssignment],
    ['secret-assignment', SAMPLES.jsonSecret],
    ['agent-key', SAMPLES.agentKey],
    ['jwt', SAMPLES.jwt],
  ])('%s finds %s', (detector, sample) => {
    expect(findLeaks(`{"note":"seen ${sample} here"}`).map((leak) => leak.detector)).toContain(detector);
  });

  it('finds every planted marker, in any case', () => {
    expect(findLeaks('{"note":"A Planted Value"}', ['a planted value', 'absent'])).toEqual([
      { detector: 'planted', found: 'a planted value' },
    ]);
  });

  it('finds every sample in the shared set with at least one detector', () => {
    expect(Object.entries(SAMPLES).filter(([, sample]) => findLeaks(sample).length === 0)).toEqual([]);
  });
});

describe('FX-LOGSCAN: redacted forms and ordinary log text are not leaks', () => {
  it.each([
    ['the redacted labels', '[redacted] [email] [iban] [ip] [phone] [card] [emirates-id] [jwt]'],
    ['a redacted Bearer token', 'Bearer [redacted]'],
    ['a redacted secret field', '{"password":"[redacted]","access_token":[redacted]}'],
    ['a redacted OAuth code', '/cb?code=[redacted]&state=[redacted]'],
    ['an agent key with its secret removed', 'axk_k7Fq2_…'],
    ['an error code', '{"code":"ECONNRESET"}'],
    ['a plain state', '{"state":"UNKNOWN"} state=approved code=23505'],
    ['an ISO timestamp', '2026-09-14T10:15:30.123Z'],
    ['a time of day', '10:15:30'],
    ['a version', '10.3.1'],
    ['an octet out of range', '999.1.1.1'],
    ['a package path in a stack', 'at x (/app/node_modules/.pnpm/vitest@4.1.11/node_modules/vitest/dist/index.js:1:2)'],
    ['a URL without a code or state', 'https://console.example/callback'],
    ['a UUID', '01920000-0000-7000-8000-000000000001'],
    ['a lowercase hex value', 'ab12cd34ef56ab78cd90ef12ab34cd56'],
    ['a sixteen-digit number that fails the Luhn check', '4111 1111 1111 1112'],
    // A random ID ending in digits that read as a phone number (main's end-to-end run, S55), as the logger writes it.
    ['a whole ID whose last group reads as a phone number', '{"noticeId":"01a0f000-0000-7000-8000-009114682700"}'],
  ])('%s', (_what, text) => {
    expect(findLeaks(text)).toEqual([]);
  });

  it('skips only a whole ID: the same digits in other text, or a real leak beside one, are still found', () => {
    const id = '01a0f000-0000-7000-8000-009114682700';
    expect(findLeaks(`{"note":"ref ${id}"}`)).toEqual([{ detector: 'phone', found: '009114682700' }]);
    expect(findLeaks(`{"id":"${id}-x"}`)).toEqual([{ detector: 'phone', found: '009114682700' }]);
    expect(findLeaks(`{"id":"${id}","to":"${SAMPLES.phone}"}`)).toEqual([{ detector: 'phone', found: SAMPLES.phone }]);
    expect(findLeaks(`{"id":"${id}"}`, [id])).toEqual([{ detector: 'planted', found: id }]);
  });
});

describe('FX-LOGSCAN: LogCapture', () => {
  it('collects every chunk written, and parses each line', () => {
    const capture = new LogCapture();
    capture.write('{"event":"a.one"}\n');
    capture.write('{"event":"b.two"}\n');
    expect(capture.text).toBe('{"event":"a.one"}\n{"event":"b.two"}\n');
    expect(capture.lines()).toEqual([{ event: 'a.one' }, { event: 'b.two' }]);
  });

  it('fails on a line that is not JSON, which is itself a logging failure', () => {
    const capture = new LogCapture();
    capture.write('not json\n');
    expect(() => capture.lines()).toThrow(SyntaxError);
  });
});
