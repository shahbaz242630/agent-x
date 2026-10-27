// A request a job holds as a secret of its own, written onto it before a run
// (B1c-2a): the operator's (operator.ts) and the load test's (load.ts). A run
// started with containers of its own loses every mounted file, its login and
// keys among them, so what changes from one run to the next reaches the job
// this way. These are the parts both write it with: the job's other secrets,
// sent back exactly as read (Azure's PATCH replaces the list whole), and the
// PATCH itself, from a file of this user's own, never a command line.
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { text } from './deploy.ts';
import type { JobSteps } from './jobs.ts';
import { azureRefusal, record } from './release.ts';

/** One of a job's secrets that the vault holds, as Azure gives it back: sent back just so. */
export interface VaultReference {
  readonly name: string;
  readonly keyVaultUrl: string;
  readonly identity: string;
}

/** An error's message, or what was thrown when it isn't an Error. */
export const reason = (error: unknown): string => (error instanceof Error ? error.message : String(error));

/**
 * A job's secrets as Azure lists them, checked: its request `held` there once
 * with nothing of it shown, and every other secret exactly a reference to the
 * vault, which `refuse` is told of otherwise. Gives back those references.
 */
export function vaultReferences(
  secrets: unknown,
  held: string,
  refuse: (why: string) => never,
): readonly VaultReference[] {
  if (!Array.isArray(secrets)) return refuse('its secrets are not a list');
  const listed = secrets.map(record);
  const holding = listed.filter((secret) => secret.name === held);
  if (holding.length !== 1 || Object.keys(holding[0] ?? {}).some((field) => field !== 'name')) {
    refuse(`it must hold ${held} once, nothing of it shown`);
  }
  return listed
    .filter((secret) => secret.name !== held)
    .map(({ name, keyVaultUrl, identity, ...other }) =>
      typeof name === 'string' &&
      typeof keyVaultUrl === 'string' &&
      typeof identity === 'string' &&
      Object.keys(other).length === 0
        ? { name, keyVaultUrl, identity }
        : refuse(
            'a secret other than its request must be exactly a reference to the vault: a name, a URL and an identity',
          ),
    );
}

/** When Azure last took a change to a resource: a change of ours has settled only once this moves on. */
export const lastModified = (found: Readonly<Record<string, unknown>>): string =>
  text(record(found.systemData).lastModifiedAt);

/**
 * JSON text with every character past ASCII written as its escape: the file
 * then reads the same in any encoding the CLI might take it to be in, and a
 * name is never kept misread for good.
 */
export const asciiJson = (json: string): string =>
  json.replace(/[^ -~]/g, (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`);

/**
 * Sends a PATCH to `url` from a file in a folder of its own in this user's
 * temporary folder (inside their profile on Windows, so theirs alone), removed
 * straight after: the request stays off every command line. Azure's message
 * isn't shown, since it can quote what was sent. A folder that can't be
 * removed (a scanner holding the file, say) is said, never taken for a PATCH
 * that failed.
 */
export function sendPatch(steps: JobSteps, url: string, body: string, what: string): void {
  const folder = mkdtempSync(path.join(tmpdir(), 'agentx-operator-'));
  try {
    const file = path.join(folder, 'patch.json');
    writeFileSync(file, body, { mode: 0o600 });
    const done = steps.az.run(['rest', '--method', 'patch', '--url', url, '--body', `@${file}`]);
    if (done.status !== 0) {
      throw new Error(
        `Azure refused ${what} (${azureRefusal(done.stderr)}). Its message isn't shown, since it can quote what was sent: the resource group's activity log has it.`,
      );
    }
  } finally {
    try {
      rmSync(folder, { recursive: true, force: true, maxRetries: 5 });
    } catch (error) {
      steps.say(`Couldn't remove ${folder}, which holds what was sent: remove it by hand (${reason(error)}).`);
    }
  }
}
