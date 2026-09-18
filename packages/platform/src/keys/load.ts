// Reads the app's keys from a directory the platform mounts them in (ADR-010:
// secrets arrive as files, never through a cloud SDK), one file per key
// version, named `key-<purpose>-v<version>` and holding 32 random bytes as
// base64url. Other files there (a database password) are left alone.
//
// Anything wrong refuses the start, with every problem listed: a key file
// with a name the app doesn't know, one that can't be read or doesn't hold a
// key, a purpose without its current version, a copy of another key, or a
// second version of a key that is never rotated in place. Problems name the
// file, never what it holds.
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { ConfigError } from '../config/common.ts';
import {
  createKeyProvider,
  KEY_BYTES,
  type KeyMaterial,
  keyMaterialProblems,
  type KeyProvider,
} from './key-provider.ts';
import { byPurpose, isKeyPurpose, type KeyPurpose, PURPOSES } from './purposes.ts';

export interface KeySettings {
  /** Where the key files are. */
  readonly directory: string;
  /** Each purpose's current version, where it isn't 1: new work uses it, and the others only check and read. */
  readonly current: Partial<Readonly<Record<KeyPurpose, number>>>;
}

/** A key file's name, in any case, so a file that looks like one but is misspelt is refused rather than ignored. */
const LOOKS_LIKE_A_KEY = /^key-/i;

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

/** Reads every key file, or throws a ConfigError listing every problem. */
export function loadKeys(settings: KeySettings): KeyProvider {
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
    const key = readKey(join(settings.directory, name), name);
    if (typeof key === 'string') problems.push(key);
    else keys.push({ ...found, key });
  }

  const material: KeyMaterial = byPurpose((purpose) => ({
    current: settings.current[purpose] ?? 1,
    versions: new Map(keys.filter((found) => found.purpose === purpose).map((found) => [found.version, found.key])),
  }));
  problems.push(...keyMaterialProblems(material));
  if (problems.length > 0) throw new ConfigError(problems);
  return createKeyProvider(material);
}
