// The monthly refresh's check of DB-IP's new place file (Phase 3 L4b), before
// anything is published: it must be DB-IP City Lite, built in the month asked
// for, and read by the API's own place finder (client-clues.ts) to the right
// countries for addresses whose country doesn't move. Run in the refresh's
// read-only job, after the packages are installed; it prints the .gz's
// SHA-256, which the writing job checks its own download against.
//
//   node tooling/places/check.ts <dbip-city-lite-YYYY-MM.mmdb.gz> <YYYY-MM>
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';

import { placeFinderOf } from '../../apps/api/src/client-clues.ts';

/** Addresses whose country doesn't move: a file that places them elsewhere is not the one we want. */
export const KNOWN_PLACES: Readonly<Record<string, string>> = {
  // Google's public DNS.
  '8.8.8.8': 'US',
  // Emirates Integrated Telecommunications (du)'s and Etisalat's own ranges.
  '94.200.0.1': 'AE',
  '2001:8f8::1': 'AE',
};

/** What's wrong with a downloaded file for this month, in plain words, or undefined when it is right. */
export function fileProblem(gz: Buffer, month: string): string | undefined {
  let finder: ReturnType<typeof placeFinderOf>;
  try {
    finder = placeFinderOf(gunzipSync(gz));
  } catch (error) {
    return `The download is not DB-IP City Lite: ${error instanceof Error ? error.message : String(error)}.`;
  }
  const built = finder.built.toISOString().slice(0, 7);
  if (built !== month) return `The download was built in ${built}, not ${month}: DB-IP may not have published yet.`;
  for (const [address, country] of Object.entries(KNOWN_PLACES)) {
    const found = finder.placeOf(address)?.country;
    if (found !== country) {
      return `The download places ${address} in ${found ?? 'no country'}, not ${country}: it is not a file to trust.`;
    }
  }
  return undefined;
}

function main([path = '', month = '']: readonly string[]): number {
  const gz = readFileSync(path);
  const problem = fileProblem(gz, month);
  if (problem !== undefined) {
    process.stderr.write(`${problem}\n`);
    return 1;
  }
  process.stdout.write(createHash('sha256').update(gz).digest('hex'));
  return 0;
}

if (import.meta.main) process.exitCode = main(process.argv.slice(2));
