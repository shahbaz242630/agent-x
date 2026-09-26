// SEC-DATA-01, SEC-DATA-02 (ADR-011 §7, ADR-013): the logger cleans every
// string it writes, in every field. Name-based redaction (redact.ts) hides
// values under sensitive field names; this hides sensitive text wherever it
// turns up, such as an email inside an error message or a token in a URL.
//
// Each pattern swaps what it finds for a fixed label, and no label contains
// text any pattern matches, so cleaning twice changes nothing.
//
// Every pattern runs in time proportional to the text: unbounded runs only
// follow a fixed literal, and everything else has a bounded repeat. The caller
// also caps each string's length first (redact.ts), so a hostile value can't
// make logging slow.

const LABELS = {
  secret: '[redacted]',
  jwt: '[jwt]',
  email: '[email]',
  iban: '[iban]',
  emiratesId: '[emirates-id]',
  card: '[card]',
  phone: '[phone]',
  ip: '[ip]',
} as const;

/** A value that isn't a label; labels start with `[`, so a second pass leaves them alone. */
const VALUE = String.raw`(?:"[^"]{0,4096}"|'[^']{0,4096}'|[^\s"'&,;}\][][^\s"'&,;}\]]{0,4095})`;

/**
 * `name: value` or `name=value` for secret-bearing names, in any text: a query
 * (`?access_token=…`), a form body, JSON inside a message (`"password":"…"`),
 * or a header line (`x-api-key: …`). A short prefix or suffix is allowed, so
 * `client_secret`, `id_token` and `x-api-key` count.
 */
const SECRET_NAMES =
  'password|passwd|pwd|passphrase|passcode|secret|token|jwt|api[_.-]?key|access[_.-]?key|private[_.-]?key|' +
  'signing[_.-]?key|secret[_.-]?key|session(?:[_.-]?id)?|cookie|signature|sig|otp|pin|code[_.-]?verifier';
const SECRET_ASSIGNMENT = new RegExp(
  String.raw`(?<![A-Za-z0-9])(["']?(?:[A-Za-z0-9]{1,20}[_.-])?(?:${SECRET_NAMES})(?:[_.-][A-Za-z0-9]{1,20})?["']?\s{0,5}[:=]\s{0,5})${VALUE}`,
  'gi',
);

/** The whole value of an Authorization header, whatever its scheme (`Bearer`, `Basic`, `Token`…). */
const AUTHORIZATION = /\b((?:proxy-)?authorization["']?\s{0,5}[:=]\s{0,5}["']?)[^"'\r\n[][^"'\r\n]{0,4095}/gi;

/**
 * An OAuth `code` or `state` given as `name=value` (ADR-011 §7). A value that
 * is plainly not a secret stays (see isPlainConstant).
 */
const OAUTH_PARAMETER = /(?<![A-Za-z0-9_])((?:code|state)=)([^&\s"'#;<>[][^&\s"'#;<>]{0,4095})/gi;

/**
 * A small number (`exit code=1`, SQL state 23505), a word (`approved`,
 * `UNKNOWN`, `ERR_INVALID_URL`) or an upper-case code (`ERR_HTTP2_STREAM_ERROR`).
 * OAuth codes and states are random mixed-case text, so they don't qualify.
 */
const PLAIN_CONSTANT = /^(?:\d{1,6}|[A-Za-z][A-Za-z_]{0,63}|[A-Z][A-Z0-9_]{0,63})$/;

export function isPlainConstant(value: string): boolean {
  return PLAIN_CONSTANT.test(value);
}

/** A JWT, or any base64url-encoded JSON object (they all start `eyJ`), whole or cut short. */
const ENCODED_JSON = /eyJ[A-Za-z0-9_-]{8,4096}(?:\.[A-Za-z0-9_-]{0,4096}){0,2}/g;

/**
 * An absolute URL, with a scheme and `//`. Its host and path end at a quote, as
 * when the URL is quoted in a message. Its query and fragment run past a single
 * quote, which a query can hold (`?a='…`), and end at a space, `"`, `<` or `>`,
 * so a URL inside JSON text leaves the fields after it. (A raw `"` in an
 * incoming request's query only reaches a log in Fastify's messages, and the
 * API's framework logger takes those addresses out whole.)
 */
const URL_CANDIDATE = /\b[a-z][a-z0-9+.-]{0,40}:\/\/[^\s"'<>`?#]{1,4096}(?:[?#][^\s"<>]{0,4096})?/gi;
const TRAILING_PUNCTUATION = new Set([')', '.', ',', ';', ':', '!', '?', ']']);
const URL_CREDENTIALS = /\/\/[^\s]{0,512}@/;
const URL_QUERY_OR_FRAGMENT = /[?#].*$/s;

/**
 * A path with a query or fragment (`/callback?code=…`), as a web framework logs
 * a request: the path stays. The query ends like a URL's (URL_CANDIDATE).
 */
const PATH_QUERY = /(^|[\s"'(=,])(\/[^\s?#"'<>]{0,2048})[?#][^\s"<>]{0,4096}/g;

/**
 * HTTP authorisation values: Bearer tokens (even run into the word before, so
 * `xBearer <token>` counts), and Basic user:password pairs (base64).
 */
const BEARER = /Bearer\s{1,10}[A-Za-z0-9._~+/-]{8,4096}=*/gi;
const BASIC = /\bBasic\s{1,10}[A-Za-z0-9+/]{8,4096}={0,2}/gi;

/**
 * An agent key, `axk_<keyId>_<secret>` (ADR-011 §1). The key ID stays, so logs
 * can say which key was used; the secret becomes `…`, however long and in
 * whichever base64 alphabet. This relies on key IDs never containing `_`.
 */
const AGENT_KEY = /(axk_[A-Za-z0-9-]{1,64}_)[A-Za-z0-9_+/=-]+/g;

/** An email address, in any script, with `@` or its URL-encoded form `%40`. */
const EMAIL = /[\p{L}\p{N}._%+-]{1,64}(?:@|%40)[\p{L}\p{N}-]{1,63}(?:\.[\p{L}\p{N}-]{1,63}){0,8}\.\p{L}{2,24}/gu;

/**
 * An IBAN written in capitals, as banks print it: two letters and two check
 * digits, then either 11 to 30 capitals or digits run together, or groups of
 * four with a shorter last group, ending at a word's end (so it never takes the
 * first letter of the next word). A digit right before it would mean the middle
 * of a longer number. It's hidden even when its check digits are wrong.
 */
const IBAN = /(?<![0-9])[A-Z]{2}\d{2}(?:(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,4})?(?![A-Za-z0-9])|[A-Z0-9]{11,30})/g;

/**
 * An IBAN in any case, grouped with spaces, non-breaking spaces or dashes. Hex
 * hashes look like this in lower case, so it's hidden only when its check
 * digits are right (ISO 13616: the number mod 97 is 1).
 */
const IBAN_ANY_CASE =
  /(?<![A-Za-z0-9])[A-Za-z]{2}\d{2}(?:(?:[ \u00A0-][A-Za-z0-9]{4}){2,7}(?:[ \u00A0-][A-Za-z0-9]{1,4})?|[A-Za-z0-9]{11,30})(?![A-Za-z0-9])/g;

/** An Emirates ID: 784, then the birth year, seven digits and a check digit, dashed or not. */
const EMIRATES_ID = /(?<![0-9])784[- ]?\d{4}[- ]?\d{7}[- ]?\d(?![0-9])/g;

/**
 * A card number that passes the Luhn check: 13 to 19 digits run together, or
 * written in groups. Groups are found as a run of digit groups separated by
 * single spaces or dashes, and every card-shaped window of the run is tried,
 * so a card right after another number (`… 4567 4111 1111 1111`) is still
 * found. Neither may start or end inside a longer run of letters and digits.
 * A run of groups also can't start or end inside a longer code: not right
 * after a digit and a dash, nor right before a dash and a digit, so the digit
 * groups of an ID such as a UUID (`01920000-0000-7000-…`) never count. A card
 * run together needs no such rule, since no group of a UUID holds 13 digits:
 * it is found after `7-` too. A card joined to a word by a dash
 * (`4111 1111 1111 1111-paid`, `ref-4111…`) is found either way (S54).
 */
const CARD_JOINED = /(?<![0-9A-Za-z])\d{13,19}(?![0-9A-Za-z])/g;
const DIGIT_GROUPS = /(?<![0-9A-Za-z]|[0-9]-)\d{1,7}(?:[ -]\d{1,7}){2,15}(?![0-9A-Za-z]|-[0-9])/g;

/**
 * A phone number: international with `+` or `00`, spaced, dotted, dashed or
 * bracketed; or a UAE mobile written locally (05X XXX XXXX). Neither may start
 * or end inside a longer run of letters and digits; a dash beside one doesn't
 * matter (`call-050 123 4567`, `5-0501234567`, S54). An ID's digit groups
 * still never make one: no UUID group holds a mobile's ten digits, and ten
 * digits across its groups of four always end inside the next group.
 */
const PHONE = /(?:\+|(?<![0-9A-Za-z])00)[1-9](?:[ .()-]{0,3}\d){7,14}(?![0-9])/g;
const UAE_MOBILE = /(?<![0-9A-Za-z])05\d(?:[ .-]{0,2}\d){7}(?![0-9A-Za-z])/g;

/**
 * Text shaped like an IPv6 address, including one ending in an IPv4 address
 * (`::ffff:192.0.2.1`), which is tried first so it's replaced whole. Each
 * candidate is then checked by the URL parser, which accepts only real
 * addresses, so times (`10:15:30`) and stack positions (`file.ts:12:34`) are
 * left alone. It mustn't stop in the middle of an IPv4 address.
 */
const IPV6_CANDIDATE =
  /(?<![0-9A-Za-z])(?:[0-9A-Fa-f]{0,4}:){2,7}(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f]{0,4})(?![0-9A-Za-z:]|\.\d)/g;

/** Four numbers joined by dots, not part of a longer dotted number; kept only if some part is over 255. */
const IPV4_CANDIDATE = /(?<!\d|\d\.)\d{1,3}(?:\.\d{1,3}){3}(?!\d|\.\d)/g;

/**
 * A SHA-256 hash on its own, as the app logs one (a chain's head, the config
 * fingerprint's hash). Random hex can by chance look like a phone number or an
 * Emirates ID in part, and a hash changed in a log is no longer evidence. Only
 * a whole value is let through: a hash inside other text, which could be a
 * token in a query, is cleaned as usual.
 */
const WHOLE_HASH = /^(?:sha256:)?[0-9a-f]{64}$/;

/**
 * A UUID on its own, as the app logs every ID, in either case: it holds no
 * personal detail, yet about one in a few hundred has a group like
 * `aa97-74f9-a825` whose IBAN check digits happen to be right (S54, a random
 * ID in a test's log line), and one starting `00` looks like an international
 * phone number in part. Only a whole value is let through, as a hash is: an ID
 * inside other text may be hidden in part, the safe way to be wrong, since an
 * IBAN right after one must still be found.
 */
const WHOLE_UUID = /^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$/;

function trailingPunctuation(text: string): number {
  let length = 0;
  while (length < text.length && TRAILING_PUNCTUATION.has(text.charAt(text.length - 1 - length))) length += 1;
  return length;
}

function cleanUrl(candidate: string): string {
  const cut = trailingPunctuation(candidate);
  const body = candidate.slice(0, candidate.length - cut);
  const trailing = candidate.slice(candidate.length - cut);
  // Keep where it points; drop who is calling (user name and password) and
  // what is asked (query and fragment), which can carry tokens, codes and IDs.
  // A URL with none of those stays exactly as written.
  if (URL.canParse(body)) {
    const url = new URL(body);
    if (url.username === '' && url.password === '' && url.search === '' && url.hash === '') return candidate;
    return `${url.protocol}//${url.host}${url.pathname}${trailing}`;
  }
  // The parser refused it. Everything up to the last @ may be credentials, since
  // a password can contain a slash.
  return body.replace(URL_CREDENTIALS, '//').replace(URL_QUERY_OR_FRAGMENT, '') + trailing;
}

function cleanOauthParameter(match: string, name: string, value: string): string {
  return PLAIN_CONSTANT.test(value) ? match : `${name}${LABELS.secret}`;
}

/** ISO 13616: move the first four characters to the end, turn letters into numbers (A=10…), and the result mod 97 is 1. */
export function hasValidIbanCheckDigits(text: string): boolean {
  const compact = text.replace(/[ \u00A0-]/g, '').toUpperCase();
  let remainder = 0;
  for (const character of compact.slice(4) + compact.slice(0, 4)) {
    const value = Number.parseInt(character, 36);
    remainder = (value > 9 ? remainder * 100 + value : remainder * 10 + value) % 97;
  }
  return remainder === 1;
}

function cleanIbanAnyCase(candidate: string): string {
  return hasValidIbanCheckDigits(candidate) ? LABELS.iban : candidate;
}

/** The Luhn check used by card numbers. */
export function passesLuhn(digits: string): boolean {
  let sum = 0;
  for (let index = 0; index < digits.length; index++) {
    const digit = Number(digits.charAt(digits.length - 1 - index));
    const doubled = index % 2 === 1 ? digit * 2 : digit;
    sum += doubled > 9 ? doubled - 9 : doubled;
  }
  return sum % 10 === 0;
}

function cleanJoinedCard(candidate: string): string {
  return passesLuhn(candidate) ? LABELS.card : candidate;
}

/**
 * How cards are printed: groups of four with a last group of one to seven, or
 * the American Express (4-6-5) and Diners (4-6-4) layouts.
 */
function isCardLayout(leading: readonly number[], last: number): boolean {
  const fours = leading.every((length) => length === 4) && last <= 7;
  const amexOrDiners = leading.join(',') === '4,6' && (last === 4 || last === 5);
  return fours || amexOrDiners;
}

/**
 * The token index of the last group of a card that starts at token `start`,
 * or -1 if none does. Tokens alternate: group, separator, group…
 */
function cardEnd(tokens: readonly string[], start: number): number {
  let digits = '';
  const leading: number[] = [];
  for (const [offset, token] of tokens.slice(start).entries()) {
    if (offset % 2 === 1) continue;
    digits += token;
    if (digits.length > 19) return -1;
    if (digits.length >= 13 && isCardLayout(leading, token.length) && passesLuhn(digits)) return start + offset;
    leading.push(token.length);
  }
  return -1;
}

function cleanDigitGroups(run: string): string {
  const tokens = run.split(/([ -])/);
  let cleaned = '';
  for (let index = 0; index < tokens.length; index += 2) {
    const end = cardEnd(tokens, index);
    // A card's groups become one label; the separator after the last group stays.
    cleaned +=
      end === -1 ? tokens.slice(index, index + 2).join('') : LABELS.card + tokens.slice(end + 1, end + 2).join('');
    if (end !== -1) index = end;
  }
  return cleaned;
}

function cleanIpv6(candidate: string): string {
  return URL.canParse(`http://[${candidate}]/`) ? LABELS.ip : candidate;
}

function cleanIpv4(candidate: string): string {
  return candidate.split('.').every((part) => Number(part) <= 255) ? LABELS.ip : candidate;
}

/** Returns the text with every secret, personal detail and payment detail replaced by a label. */
export function scrub(text: string): string {
  if (WHOLE_HASH.test(text) || WHOLE_UUID.test(text)) return text;
  return (
    text
      // URLs first: their credentials and whole query go, before anything else changes their text.
      .replace(URL_CANDIDATE, cleanUrl)
      .replace(PATH_QUERY, '$1$2')
      // Then named secrets, so a secret that looks like something else (an email) is hidden whole.
      .replace(AUTHORIZATION, `$1${LABELS.secret}`)
      .replace(SECRET_ASSIGNMENT, `$1${LABELS.secret}`)
      .replace(OAUTH_PARAMETER, cleanOauthParameter)
      .replace(ENCODED_JSON, LABELS.jwt)
      .replace(BEARER, `Bearer ${LABELS.secret}`)
      .replace(BASIC, `Basic ${LABELS.secret}`)
      .replace(AGENT_KEY, '$1…')
      .replace(EMAIL, LABELS.email)
      .replace(IBAN, LABELS.iban)
      .replace(IBAN_ANY_CASE, cleanIbanAnyCase)
      .replace(EMIRATES_ID, LABELS.emiratesId)
      .replace(CARD_JOINED, cleanJoinedCard)
      .replace(DIGIT_GROUPS, cleanDigitGroups)
      .replace(PHONE, LABELS.phone)
      .replace(UAE_MOBILE, LABELS.phone)
      .replace(IPV6_CANDIDATE, cleanIpv6)
      .replace(IPV4_CANDIDATE, cleanIpv4)
  );
}
