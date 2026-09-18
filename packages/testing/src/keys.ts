import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

/** A folder of stand-in keys for a test run, and how to remove it. */
export interface TestKeys {
  readonly directory: string;
  remove(): void;
}

/**
 * Writes a stand-in key file for each purpose, version 1, as the platform
 * mounts real ones (`key-<purpose>-v<version>`, 32 bytes as base64url). Each
 * key is 32 bytes of one fixed value, its own for each purpose, so a run is
 * repeatable and no key is ever real. The purposes are passed in, since this
 * package doesn't depend on the platform that defines them.
 */
export function writeTestKeys(purposes: readonly string[]): TestKeys {
  const directory = mkdtempSync(path.join(tmpdir(), 'agentx-test-keys-'));
  for (const [index, purpose] of purposes.entries()) {
    writeFileSync(path.join(directory, `key-${purpose}-v1`), `${Buffer.alloc(32, index + 1).toString('base64url')}\n`);
  }
  return {
    directory,
    remove: () => {
      rmSync(directory, { recursive: true, force: true });
    },
  };
}
