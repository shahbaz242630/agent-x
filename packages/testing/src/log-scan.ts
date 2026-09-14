// FX-LOGSCAN (Security Test Catalogue): captures what the logger writes and
// scans it for anything that must never reach a log (SEC-DATA-01, 02, 05).
// The detectors are written separately from the logger's own cleaning patterns
// on purpose: if they shared code, a mistake in one would hide itself. So they
// check the same things a different way (the IBAN check digits with BigInt,
// for example).

/** Collects the logger's output instead of stdout. Pass it as the logger's `destination`. */
export class LogCapture {
  readonly #chunks: string[] = [];

  write(chunk: string): void {
    this.#chunks.push(chunk);
  }

  get text(): string {
    return this.#chunks.join('');
  }

  /** Each line parsed as JSON. Throws if any line isn't JSON, which is itself a failure. */
  lines(): Record<string, unknown>[] {
    return this.text
      .split('\n')
      .filter((line) => line !== '')
      .map((line) => JSON.parse(line) as Record<string, unknown>);
  }
}

export interface Leak {
  readonly detector: string;
  readonly found: string;
}

/** What a detector finds, and what counts as a real find (the rest look alike but are safe). */
interface Detector {
  readonly name: string;
  readonly pattern: RegExp;
  readonly isLeak?: (found: string) => boolean;
}

/** A value that isn't a secret: redacted, a small number, or a word or constant. */
const HARMLESS_VALUE = /^(?:\[|\d{1,6}(?:\D|$)|[A-Za-z_]+(?:[^A-Za-z0-9_-]|$)|[A-Z0-9_]+(?:[^A-Za-z0-9_-]|$))/;

function ibanChecksumIsValid(compact: string): boolean {
  const upper = compact.toUpperCase();
  const digits = Array.from(upper.slice(4) + upper.slice(0, 4))
    .map((character) => (/\d/.test(character) ? character : String(character.charCodeAt(0) - 55)))
    .join('');
  return compact.length >= 15 && compact.length <= 34 && BigInt(digits) % 97n === 1n;
}

/** A grouped match may run into the next word, so every length ending at a group's end is tried. */
function containsValidIban(found: string): boolean {
  const groups = found.split(/[ \u00A0-]/);
  return groups.some((_, index) => ibanChecksumIsValid(groups.slice(0, index + 1).join('')));
}

/** Every second digit from the right is doubled and its digits summed; this table holds the result for 0–9. */
const DOUBLED = '0246813579';

function luhnIsValid(found: string): boolean {
  const digits = found.replace(/\D/g, '');
  const total = Array.from(digits)
    .reverse()
    .reduce((sum, digit, index) => sum + Number(index % 2 === 1 ? DOUBLED.charAt(Number(digit)) : digit), 0);
  return digits.length >= 13 && total % 10 === 0;
}

const DETECTORS: readonly Detector[] = [
  // A UAE IBAN is AE and 21 digits, joined or in spaced groups of four.
  { name: 'uae-iban', pattern: /AE\d{2}(?: ?\d){19}/gi },
  // Any country's IBAN, in any case, joined or grouped, with valid check digits.
  {
    name: 'iban',
    pattern: /\b[A-Za-z]{2}\d{2}(?:[A-Za-z0-9]{11,30}|(?:[ \u00A0-][A-Za-z0-9]{1,4}){3,8})\b/g,
    isLeak: containsValidIban,
  },
  // The domain has no slash, so a package path in a stack trace (`vitest@4.1.11/dist/…`) isn't an email.
  {
    name: 'email',
    pattern: /[\p{L}\p{N}._%+-]{1,64}(?:@|%40)[\p{L}\p{N}-]{1,63}(?:\.[\p{L}\p{N}-]{1,63}){0,10}\.\p{L}{2,24}/gu,
  },
  {
    name: 'ipv4',
    pattern: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g,
    isLeak: (found) => found.split('.').every((part) => Number(part) <= 255),
  },
  {
    // Hex groups joined by colons, with `::` or all eight groups: a time like 10:15:30 has neither.
    name: 'ipv6',
    pattern: /[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}/gi,
    isLeak: (found) => /[0-9a-f]/i.test(found) && (found.includes('::') || found.split(':').length === 8),
  },
  // A Gulf-region international number (+9…), or a UAE mobile written locally.
  { name: 'phone', pattern: /(?:\+|\b00)9\d{2}(?:[ .()-]{0,3}\d){7,12}|\b05\d(?:[ .-]?\d){7}\b/g },
  { name: 'card', pattern: /\b\d{4}([ -]?)\d{4}\1\d{4}\1\d{1,7}\b/g, isLeak: luhnIsValid },
  { name: 'emirates-id', pattern: /\b784-?\d{4}-?\d{7}-?\d\b/g },
  { name: 'bearer-token', pattern: /bearer\s+[^\s"[]+/gi },
  { name: 'basic-credentials', pattern: /basic\s+[a-z0-9+/]{8,}=*/gi },
  // An OAuth `code` or `state` (ADR-011 §7), in a URL, in text or as a JSON field, unless plainly harmless.
  {
    name: 'oauth-parameter',
    pattern: /(?<![A-Za-z0-9_])(?:code|state)(?:=|":")[^\s&"#]+/gi,
    isLeak: (found) => !HARMLESS_VALUE.test(found.replace(/^[a-z]+(?:=|":")/i, '')),
  },
  // A secret-bearing name given a value in text: `password=…`, `"access_token":"…"`, `x-api-key: …`.
  {
    name: 'secret-assignment',
    pattern: /(?:password|passwd|secret|token|api[_-]?key)["']?\s*[:=]\s*["']?[^\s"'&,}]+/gi,
    isLeak: (found) => !/[:=]\s*["']?\[/.test(found),
  },
  // `axk_<keyId>_<secret>`. The logged form keeps only the key ID: `axk_<keyId>_…`.
  { name: 'agent-key', pattern: /axk_[a-z0-9-]+_[a-z0-9_+/=-]{8,}/gi },
  { name: 'jwt', pattern: /eyJ[A-Za-z0-9_-]{8,}/g },
];

/** Built from parts when the tests run, so secret scanners reading the source don't mistake them for real secrets. */
const join = (...parts: string[]): string => parts.join('');

/**
 * One of each kind of value that must never reach a log, for tests to plant in
 * log fields and error messages. Documentation-only values: the example.com
 * domain, the 192.0.2.0/24 and 2001:db8::/32 address ranges, the IBAN
 * registry's own examples, and the standard Visa test card number.
 */
export const SENSITIVE_SAMPLES = {
  email: 'someone.name+tag@example.com',
  unicodeEmail: 'josé.núñez@example.com',
  uaeIban: join('AE07', '0331', '2345', '6789', '0123', '456'),
  spacedUaeIban: join('AE07 ', '0331 ', '2345 ', '6789 ', '0123 ', '456'),
  lowercaseIban: join('gb82', 'west', '1234', '5698', '7654', '32'),
  ipv4: '192.0.2.44',
  ipv6: '2001:db8::7',
  mappedIpv6: '::ffff:192.0.2.45',
  phone: '+971 50 123 4567',
  localMobile: '050 123 4567',
  card: join('4111 ', '1111 ', '1111 ', '1111'),
  emiratesId: join('784-', '1990-', '1234567-', '1'),
  bearer: join('Bearer ', 'b'.repeat(40)),
  basic: join('Basic ', Buffer.from('someone:plain words').toString('base64')),
  agentKey: join('axk_', 'k7Fq2', '_', 's'.repeat(43)),
  jwt: join('eyJ', 'a'.repeat(20), '.', 'b'.repeat(20), '.', 'c'.repeat(20)),
  oauthCallback: join(
    'https://console.example/callback',
    '?code=',
    'c0de',
    'x'.repeat(8),
    '&state=',
    's7',
    'y'.repeat(10),
  ),
  relativeCallback: join('/oauth/callback', '?code=', 'c0de', 'x'.repeat(8), '&state=', 's7', 'y'.repeat(10)),
  credentialUrl: join('https://someone', ':', 'plain-words', '@api.partner.example/v1'),
  secretAssignment: join('password', '=', 'plain-words-pw'),
  jsonSecret: join('{"access_', 'token":"', 'opaque value 1234"}'),
} as const;

/**
 * Every leak in the text. `planted` are marker values a test put somewhere it
 * must never reach the log, such as a secret setting or a password field.
 */
export function findLeaks(text: string, planted: readonly string[] = []): Leak[] {
  const found = DETECTORS.flatMap(({ name, pattern, isLeak }) =>
    [...text.matchAll(pattern)]
      .map((match) => match[0])
      .filter((value) => isLeak?.(value) ?? true)
      .map((value) => ({ detector: name, found: value })),
  );
  const lowered = text.toLowerCase();
  const markers = planted
    .filter((marker) => lowered.includes(marker.toLowerCase()))
    .map((marker) => ({ detector: 'planted', found: marker }));
  return [...found, ...markers];
}
