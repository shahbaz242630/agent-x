// SEC-DATA-05 (ADR-011 §7): which field names mark a value that is never
// logged. A name is read as words ("clientIP" is client + ip, "x-api-key" is
// x + api + key), so short words like `pin` and `ip` count only as whole words
// ("mapping" and "zip" don't), while long unambiguous names count anywhere in a
// name ("userPassword").

/** How a field's value is treated, going by its name. */
export type NameRule = 'keep' | 'redact' | 'redact-unless-constant';

/** Names that look sensitive but aren't: public identifiers. Compared after removing case and punctuation. */
const ALLOWED = new Set(['keyid', 'keyversion', 'idempotencykey', 'publickey']);

/** Long, unambiguous names, matched anywhere in the name with case and punctuation removed. */
const NAME_PARTS = [
  'password',
  'passwd',
  'passphrase',
  'passcode',
  'secret',
  'token',
  'authorization',
  'cookie',
  'apikey',
  'accesskey',
  'privatekey',
  'signingkey',
  'encryptionkey',
  'secretkey',
  'hmackey',
  'webhookkey',
  'pepper',
  'credential',
  'session',
  'signature',
  'onetimepass',
  'iban',
  'accountnumber',
  'accountno',
  'cardnumber',
  'cardno',
  'creditcard',
  'email',
  'phone',
  'mobile',
  'msisdn',
  'address',
  'beneficiary',
  'firstname',
  'lastname',
  'middlename',
  'fullname',
  'displayname',
  'username',
  'holdername',
  'accountholder',
  'payeename',
  'customername',
  'surname',
  'dateofbirth',
  'birthdate',
  'passport',
  'nationalid',
  'emiratesid',
  'connectionstring',
  'databaseurl',
  'codeverifier',
];

/** Short words that are sensitive only as a whole word of the name. */
const WORDS = new Set([
  'pwd',
  'pass',
  'pin',
  'otp',
  'ip',
  'ipv4',
  'ipv6',
  'dob',
  'ssn',
  'salt',
  'auth',
  'sig',
  'nonce',
  'jwt',
  'cvv',
  'cvc',
  // A card's primary account number.
  'pan',
  'dsn',
  // Never logged whole (logging standard §2, ADR-011 §7): request bodies and query strings.
  'body',
  'query',
  'querystring',
]);

/** Words that make `name` a person's name: `payeeName`, `holderName`, `firstName`… */
const PERSON_WORDS = new Set([
  'full',
  'first',
  'last',
  'middle',
  'given',
  'family',
  'display',
  'user',
  'payee',
  'beneficiary',
  'holder',
  'customer',
  'contact',
  'supplier',
  'legal',
  'person',
  'recipient',
  'sender',
  'account',
]);

/** Words that make `code` a secret one: `verificationCode`, `resetCode`… */
const SECRET_CODE_WORDS = new Set([
  'verification',
  'reset',
  'sms',
  'login',
  'access',
  'security',
  'confirmation',
  'activation',
  'recovery',
  'backup',
  'invite',
]);

/** A camelCase, snake_case or kebab-case name as lower-case words. */
export function wordsOf(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((word) => word !== '');
}

export function ruleForName(name: string): NameRule {
  const normalised = name.toLowerCase().replace(/[^a-z0-9]/g, '');
  if (ALLOWED.has(normalised)) return 'keep';
  const words = wordsOf(name);
  const last = words.at(-1);
  const before = words.at(-2) ?? '';
  const sensitive =
    NAME_PARTS.some((part) => normalised.includes(part)) ||
    words.some((word) => WORDS.has(word)) ||
    // Any kind of key but the public identifiers above: apiKey, signingKey, key…
    last === 'key' ||
    (words.includes('name') && (words.length === 1 || words.some((word) => PERSON_WORDS.has(word)))) ||
    (last === 'code' && SECRET_CODE_WORDS.has(before)) ||
    (last === 'id' && before === 'tax');
  if (sensitive) return 'redact';
  // An error or reason code, or a state-machine state, is useful; an OAuth code or state is a secret.
  return last === 'code' || last === 'state' ? 'redact-unless-constant' : 'keep';
}
