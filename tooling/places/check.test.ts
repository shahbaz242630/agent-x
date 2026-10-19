// L4b: the refresh's check of a new month's file, on small files of the real
// format: right type, month and known countries pass; anything else is
// refused in plain words.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';

import { describe, expect, it } from 'vitest';

import { PLACES_STALE_DAYS } from '../../apps/api/src/client-clues.ts';
import { placeFile } from '../../apps/api/src/place-file.helper.test.ts';
import { fileProblem, KNOWN_PLACES } from './check.ts';
import { MOST_AGE_DAYS } from './pin.ts';

/** The helper's files are built on 1 October 2026. */
const MONTH = '2026-10';

const knownPlaces = (country: (address: string) => string) =>
  Object.keys(KNOWN_PLACES).map((address) => ({
    network: address.includes(':') ? `${address}/128` : `${address}/32`,
    record: { country: { iso_code: country(address) } },
  }));

const RIGHT = gzipSync(placeFile(knownPlaces((address) => KNOWN_PLACES[address] ?? '')));

describe('the refresh’s check of a new place file (L4b)', () => {
  it('passes DB-IP City Lite of the month, placing the known addresses rightly', () => {
    expect(fileProblem(RIGHT, MONTH)).toBeUndefined();
  });

  it('refuses a file of another month', () => {
    expect(fileProblem(RIGHT, '2026-11')).toMatch(/built in 2026-10, not 2026-11/);
  });

  it('refuses a file placing a known address elsewhere', () => {
    const wrong = gzipSync(placeFile(knownPlaces((address) => (address === '8.8.8.8' ? 'CN' : 'AE'))));
    expect(fileProblem(wrong, MONTH)).toMatch(/places 8\.8\.8\.8 in CN, not US/);
  });

  it('refuses a file with a known address missing', () => {
    expect(fileProblem(gzipSync(placeFile([])), MONTH)).toMatch(/in no country, not US/);
  });

  it('judges staleness on the same day count as the API', () => {
    expect(MOST_AGE_DAYS).toBe(PLACES_STALE_DAYS);
  });

  it('refuses a file of another kind, or not a place file at all', () => {
    expect(fileProblem(gzipSync(placeFile([], 'GeoLite2-City')), MONTH)).toMatch(/not DB-IP City Lite/);
    expect(fileProblem(gzipSync(Buffer.from('<html>not found</html>')), MONTH)).toMatch(/not DB-IP City Lite/);
    expect(fileProblem(Buffer.from('not gzip'), MONTH)).toMatch(/not DB-IP City Lite/);
  });
});

describe('the check’s command line, as the refresh runs it', () => {
  const run = (file: Buffer, month: string) => {
    const directory = mkdtempSync(join(tmpdir(), 'agentx-check-'));
    try {
      const path = join(directory, 'places.mmdb.gz');
      writeFileSync(path, file);
      return spawnSync(process.execPath, ['tooling/places/check.ts', path, month], { encoding: 'utf8' });
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  };

  it('prints the right file’s SHA-256 alone, for the writing job to check its download against', () => {
    const passed = run(RIGHT, MONTH);

    expect(passed.status).toBe(0);
    expect(passed.stdout).toBe(createHash('sha256').update(RIGHT).digest('hex'));
  });

  it('fails a wrong file, saying why and printing no checksum', () => {
    const failed = run(RIGHT, '2026-11');

    expect(failed.status).toBe(1);
    expect(failed.stdout).toBe('');
    expect(failed.stderr).toMatch(/built in 2026-10, not 2026-11/);
  });
});
