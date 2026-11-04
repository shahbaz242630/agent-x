// The app's keys on Azure (ADR-011 §2): one vault secret per key version,
// named as the API reads them, `key-<purpose>-v<version>`. app-keys.json holds
// the list, which names.bicep loads (appKeys) for secrets.bicep to create each
// once and apps.bicep to mount each into the API; the deploy tool makes their
// values and the policy checks who reads them from the same list. It is checked
// here against the purposes the app knows, so the vault can't lack a key the
// API needs at start-up or hold one it would refuse.
// A new key goes at the top of app-keys.json: added after another key's name,
// gitleaks reads the pair as `key = "value"` and refuses the push (S173).
//
// The operator's own key (PL-57) is mounted into the operator's job alone; the
// API is given its public half instead, a secret of its own,
// `public-<purpose>-v<version>`, made from the same value in the same run and
// created once, as the key is (PUBLIC_HALVES).
import { createPrivateKey, createPublicKey, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';

import { KEY_PURPOSES, OPERATOR_ONLY, PURPOSES } from '../../packages/platform/src/keys/purposes.ts';

const KEY_NAME = /^key-([a-z-]+)-v([1-9][0-9]{0,5})$/;

/** Why a list can't be the app's keys, or nothing: the same rules the API starts by. */
export function appKeysProblems(parsed: unknown): string[] {
  if (!Array.isArray(parsed) || !parsed.every((entry) => typeof entry === 'string')) {
    return ['app-keys.json must be a list of key names'];
  }
  const names: readonly string[] = parsed;
  const problems: string[] = [];
  const versions = new Map<string, number[]>();
  for (const name of names) {
    const [, purpose = '', version = ''] = KEY_NAME.exec(name) ?? [];
    if (!Object.hasOwn(KEY_PURPOSES, purpose)) {
      problems.push(`${name} is not key-<purpose>-v<version> with a purpose the app knows`);
      continue;
    }
    versions.set(purpose, [...(versions.get(purpose) ?? []), Number(version)]);
  }
  if (new Set(names).size < names.length) problems.push('a key is listed more than once');
  for (const purpose of PURPOSES) {
    const held = versions.get(purpose) ?? [];
    // The API starts with version 1 current unless told otherwise (AGENTX_KEYS_CURRENT).
    if (!held.includes(1)) problems.push(`key-${purpose}-v1 is missing: the API needs it to start`);
    if (!KEY_PURPOSES[purpose].rotates && held.some((version) => version !== 1)) {
      problems.push(`${purpose} is never rotated in place (ADR-014 §3): only key-${purpose}-v1 may exist`);
    }
  }
  return problems;
}

function readAppKeys(): readonly string[] {
  const parsed: unknown = JSON.parse(readFileSync(new URL('./app-keys.json', import.meta.url), 'utf8'));
  const problems = appKeysProblems(parsed);
  if (problems.length > 0) throw new Error(`app-keys.json can't be used:\n- ${problems.join('\n- ')}`);
  return Object.freeze(parsed as string[]);
}

/** Every key the app reads, each a vault secret created once. */
export const APP_KEYS: readonly string[] = readAppKeys();

/** Whether a key is one only the operator's job holds (PL-57). */
export const operatorOnly = (key: string): boolean =>
  OPERATOR_ONLY.some((purpose) => key.startsWith(`key-${purpose}-v`));

/** Each operator-only key's public half, a vault secret the API reads (PL-57), by the key's name. */
export const PUBLIC_HALVES: ReadonlyMap<string, string> = new Map(
  APP_KEYS.filter(operatorOnly).map((key) => [key, `public-${key.slice('key-'.length)}`]),
);

/** Ed25519's PKCS #8 wrapping of a 32-byte seed (RFC 8410), as the app's key provider reads one. */
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

/** An Ed25519 seed's public half, as base64url. */
function publicHalf(seed: Buffer): string {
  const key = createPrivateKey({ key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]), format: 'der', type: 'pkcs8' });
  return String(createPublicKey(key).export({ format: 'jwk' }).x);
}

/**
 * A fresh value for every key, as the one JSON value secrets.bicep takes them
 * in: 32 random bytes each, as base64url, and each operator-only key's public
 * half beside it. Only a key the vault lacks is written.
 */
export function newAppKeys(random: (bytes: number) => Buffer = randomBytes): string {
  return JSON.stringify(
    Object.fromEntries(
      APP_KEYS.flatMap((key) => {
        const seed = random(32);
        const half = PUBLIC_HALVES.get(key);
        // Made with its key, from the same bytes, so the two the vault creates together always match.
        return [[key, seed.toString('base64url')], ...(half === undefined ? [] : [[half, publicHalf(seed)]])];
      }),
    ),
  );
}
