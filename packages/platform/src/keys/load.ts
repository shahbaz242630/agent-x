// Reads the app's keys from a directory the platform mounts them in (ADR-010:
// secrets arrive as files, never through a cloud SDK), one file per key
// version, named `key-<purpose>-v<version>` and holding 32 random bytes as
// base64url. Other files there (a database password) are left alone.
//
// Anything wrong refuses the start, with every problem listed: a key file
// with a name the app doesn't know, or for a purpose the process doesn't
// hold, one that can't be read or doesn't hold a key, a purpose without its
// current version, a copy of another key, or a second version of a key that
// is never rotated in place. Problems name the file, never what it holds.
//
// Beside them, the public half of another process's signing key, for a process
// that checks its signatures without holding it (the API, the operator's key;
// PL-57): `public-<purpose>-v<version>`, the 32-byte Ed25519 public key as
// base64url. One for a purpose the process doesn't check with is refused as a
// key file is; none at all is no refusal, since a signature it can't check is
// never believed (platform-chain.ts), so the deployment that brings the first
// one can come after the image.
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { ConfigError } from '../config/common.ts';
import {
  createKeyProvider,
  KEY_BYTES,
  type KeyMaterial,
  keyMaterialProblems,
  type KeyProvider,
  publicKeyProblems,
  type PublicKeys,
} from './key-provider.ts';
import { isKeyPurpose, type KeyPurpose, PURPOSES, type SigningPurpose } from './purposes.ts';

export interface KeySettings {
  /** Where the key files are. */
  readonly directory: string;
  /** Each purpose's current version, where it isn't 1: new work uses it, and the others only check and read. */
  readonly current: Partial<Readonly<Record<KeyPurpose, number>>>;
}

/** A key file's name, in any case, so a file that looks like one but is misspelt is refused rather than ignored. */
const LOOKS_LIKE_A_KEY = /^key-/i;

/** A public half's file name, likewise. */
const LOOKS_LIKE_A_PUBLIC_HALF = /^public-/i;
const PUBLIC_FILE = /^public-([a-z-]+)-v([1-9][0-9]{0,5})$/;

/** A version is a whole number from 1, written without leading zeros. */
const KEY_FILE = /^key-([a-z-]+)-v([1-9][0-9]{0,5})$/;

/** 32 bytes as base64url with no padding is 43 characters. */
const ENCODED_KEY = /^[A-Za-z0-9_-]{43}$/;

type Found = { readonly purpose: KeyPurpose; readonly version: number } | { readonly problem: string };

function parseName(name: string): Found {
  const [, purpose = '', version = ''] = KEY_FILE.exec(name) ?? [];
  if (!isKeyPurpose(purpose)) {
    return {
      problem: `${name} is not a key the app knows: key files are named key-<purpose>-v<version>, the purpose one of ${PURPOSES.join(', ')}`,
    };
  }
  return { purpose, version: Number(version) };
}

/** The key a file holds, or why it holds none. A file's one trailing line break is dropped, as tools add one. */
function readKey(path: string, name: string): Buffer | string {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch {
    return `${name} can't be read`;
  }
  const encoded = text.replace(/\r?\n$/, '');
  const key = ENCODED_KEY.test(encoded) ? Buffer.from(encoded, 'base64url') : undefined;
  // The last character carries 2 spare bits: the key must be written the one way that encodes it.
  return key?.length === KEY_BYTES && key.toString('base64url') === encoded
    ? key
    : `${name} must hold one key: ${KEY_BYTES} random bytes written as base64url, 43 characters`;
}

/** The public halves found for the purposes `checks`, by version, and the problems with any file of one. */
function readPublicHalves(
  directory: string,
  names: readonly string[],
  checks: readonly SigningPurpose[],
): { readonly halves: PublicKeys; readonly problems: readonly string[] } {
  const problems: string[] = [];
  const halves = new Map<SigningPurpose, Map<number, Buffer>>();
  for (const name of names.filter((entry) => LOOKS_LIKE_A_PUBLIC_HALF.test(entry)).sort()) {
    const [, purpose = '', version = ''] = PUBLIC_FILE.exec(name) ?? [];
    const checked = checks.find((each) => each === purpose);
    if (checked === undefined) {
      problems.push(
        `${name} is not a public half this process checks with: only public-<purpose>-v<version> for ${checks.join(', ') || 'none'}`,
      );
      continue;
    }
    const key = readKey(join(directory, name), name);
    if (typeof key === 'string') problems.push(key);
    else halves.set(checked, (halves.get(checked) ?? new Map<number, Buffer>()).set(Number(version), key));
  }
  return { halves: Object.fromEntries(halves), problems };
}

/**
 * Reads every key file, or throws a ConfigError listing every problem. A
 * process holds the keys of the purposes `held` (every purpose when not
 * given) and no others: a file or a current version for another purpose is
 * refused, not ignored, since a key mounted where it has no use is one more
 * place it can leak from. It checks signatures of the purposes `checks` with
 * their public halves alone (PL-57), each only one it doesn't hold.
 */
export function loadKeys(
  settings: KeySettings,
  held: readonly KeyPurpose[] = PURPOSES,
  checks: readonly SigningPurpose[] = [],
): KeyProvider {
  let names: string[];
  try {
    names = readdirSync(settings.directory);
  } catch {
    throw new ConfigError(["AGENTX_KEYS_DIR names a folder that can't be read"]);
  }

  const problems: string[] = [];
  const keys: { readonly purpose: KeyPurpose; readonly version: number; readonly key: Buffer }[] = [];
  for (const name of names.filter((entry) => LOOKS_LIKE_A_KEY.test(entry)).sort()) {
    const found = parseName(name);
    if ('problem' in found) {
      problems.push(found.problem);
      continue;
    }
    if (!held.includes(found.purpose)) {
      // Left unread: what it holds changes nothing.
      problems.push(`${name} is a key this process doesn't hold: only ${held.join(', ')} may be mounted for it`);
      continue;
    }
    const key = readKey(join(settings.directory, name), name);
    if (typeof key === 'string') problems.push(key);
    else keys.push({ ...found, key });
  }
  for (const purpose of PURPOSES) {
    if (settings.current[purpose] !== undefined && !held.includes(purpose)) {
      problems.push(`AGENTX_KEYS_CURRENT names ${purpose}, a key this process doesn't hold`);
    }
  }

  const material: KeyMaterial = Object.fromEntries(
    held.map((purpose) => [
      purpose,
      {
        current: settings.current[purpose] ?? 1,
        versions: new Map(keys.filter((found) => found.purpose === purpose).map((found) => [found.version, found.key])),
      },
    ]),
  );
  problems.push(...keyMaterialProblems(material, held));
  const { halves, problems: halfProblems } = readPublicHalves(settings.directory, names, checks);
  problems.push(...halfProblems, ...publicKeyProblems(halves, held));
  if (problems.length > 0) throw new ConfigError(problems);
  return createKeyProvider(material, held, halves);
}
