// L4: the activity log's clues. The place finder reads a real MaxMind-format
// file (a small one, written by the helper) through mmdb-lib, as it reads
// DB-IP's in the image: a country by code, a city as one line of text, and no
// place for an address not in it. A deployed API without the file won't start;
// a developer's records no place. A browser's time zone is taken only as a
// zone Intl knows.
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { DAY_MS } from '@agentx/core/shared-kernel';
import { createLogger } from '@agentx/platform/observability';
import { LogCapture } from '@agentx/testing';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  cityName,
  loadPlaces,
  PLACE_FILE,
  placeFinderOf,
  placeIn,
  PLACES_STALE_DAYS,
  timeZoneSent,
} from './client-clues.ts';
import { placeFile } from './place-file.helper.test.ts';

const ABU_DHABI = {
  country: { iso_code: 'AE', names: { en: 'United Arab Emirates' } },
  city: { names: { en: 'Abu Dhabi' } },
};

const PLACES = placeFile([
  { network: '94.200.0.0/16', record: ABU_DHABI },
  { network: '203.0.113.0/24', record: { country: { iso_code: 'US', is_in_european_union: false } } },
  { network: '2001:db8::/32', record: { country: { iso_code: 'DE' }, city: { names: { en: 'Frankfurt am Main' } } } },
  { network: '198.51.100.0/24', record: { country: { iso_code: 'ZZ' }, city: { names: { en: 'Nowhere' } } } },
]);

let directory: string;

beforeAll(async () => {
  directory = await mkdtemp(join(tmpdir(), 'agentx-places-'));
});

afterAll(async () => {
  await rm(directory, { recursive: true, force: true });
});

const logged = () => {
  const capture = new LogCapture();
  const config = {
    environment: 'test' as const,
    release: 'r-1',
    log: { level: 'info' as const, eventCapPerMinute: 100 },
  };
  return { capture, logger: createLogger({ service: 'api', config, destination: capture }) };
};

describe('the place finder (L4)', () => {
  const { placeOf, built } = placeFinderOf(PLACES);

  it('finds an address’s country and city, IPv4 and IPv6', () => {
    expect(placeOf('94.200.12.34')).toEqual({ country: 'AE', city: 'Abu Dhabi' });
    expect(placeOf('2001:db8:1::7')).toEqual({ country: 'DE', city: 'Frankfurt am Main' });
    expect(built).toEqual(new Date('2026-10-01T00:00:00.000Z'));
  });

  it('finds a country with no city', () => {
    expect(placeOf('203.0.113.7')).toEqual({ country: 'US', city: undefined });
  });

  it('finds no place for an address not in the file, a country not known, or text that isn’t an address', () => {
    expect(placeOf('10.40.0.16')).toBeUndefined();
    expect(placeOf('198.51.100.1')).toBeUndefined();
    expect(placeOf('not an address')).toBeUndefined();
    // Text the reader would read as some address all the same.
    expect(placeOf('94.200.1')).toBeUndefined();
    expect(placeOf('94.200.12.34/8')).toBeUndefined();
  });

  it('refuses a file of another kind', () => {
    expect(() => placeFinderOf(placeFile([], 'GeoLite2-Country'))).toThrow(/GeoLite2-Country, not DBIP-City-Lite/);
  });
});

describe('a record’s place', () => {
  it.each([
    ['nothing', null],
    ['no country', { city: { names: { en: 'Dubai' } } }],
    ['a country with no code', { country: { names: { en: 'UAE' } } }],
    ['a code not ISO’s', { country: { iso_code: 'ARE' } }],
    ['a code in lower case', { country: { iso_code: 'ae' } }],
    ['a code that isn’t text', { country: { iso_code: 784 } }],
    ['a code only inherited', { country: Object.create({ iso_code: 'AE' }) as unknown }],
  ])('is none for %s', (_what, record) => {
    expect(placeIn(record)).toBeUndefined();
  });

  it('keeps the country when the city is no name', () => {
    expect(placeIn({ country: { iso_code: 'AE' }, city: { names: { ar: 'دبي' } } })).toEqual({
      country: 'AE',
      city: undefined,
    });
  });
});

// Bidi controls, written as codes: right-to-left override, left-to-right isolate, Arabic letter mark.
const [OVERRIDE, ISOLATE, ARABIC_MARK] = [0x20_2e, 0x20_66, 0x06_1c].map((code) => String.fromCharCode(code));

describe('a city’s name', () => {
  it('is one line of plain text', () => {
    expect(cityName('  Ras  al\nKhaimah ')).toBe('Ras al Khaimah');
    expect(cityName(`Dubai${OVERRIDE}${ISOLATE}x`)).toBe('Dubai x');
    expect(cityName(`Dubai${ARABIC_MARK}`)).toBe('Dubai');
  });

  it('is at most 120 UTF-16 units, so never more characters than Postgres keeps', () => {
    expect(cityName('ق'.repeat(120))).toBe('ق'.repeat(120));
    expect(cityName('a'.repeat(121))).toBeUndefined();
    expect(cityName('𝔸'.repeat(61))).toBeUndefined();
  });

  it('is none for nothing, only spaces, or text that isn’t well formed', () => {
    expect(cityName(undefined)).toBeUndefined();
    expect(cityName(' \u0000 ')).toBeUndefined();
    expect(cityName('Dubai\ud800')).toBeUndefined();
  });
});

describe('loading the place file', () => {
  it('loads the file and says when it was built', async () => {
    const path = join(directory, 'places.mmdb');
    await writeFile(path, PLACES);
    const { capture, logger } = logged();

    const placeOf = await loadPlaces('staging', logger, path);

    expect(placeOf?.('94.200.1.1')).toEqual({ country: 'AE', city: 'Abu Dhabi' });
    expect(capture.lines()).toContainEqual(
      expect.objectContaining({
        event: 'activity.places_loaded',
        database: 'DBIP-City-Lite',
        built: '2026-10-01T00:00:00.000Z',
      }),
    );
  });

  it('warns when the file is past its refresh, and not before', async () => {
    const path = join(directory, 'aging.mmdb');
    await writeFile(path, PLACES);
    const built = Date.parse('2026-10-01T00:00:00.000Z');
    const fresh = logged();
    const stale = logged();

    await loadPlaces('staging', fresh.logger, path, new Date(built + PLACES_STALE_DAYS * DAY_MS));
    await loadPlaces('staging', stale.logger, path, new Date(built + (PLACES_STALE_DAYS + 1) * DAY_MS));

    expect(fresh.capture.lines()).not.toContainEqual(expect.objectContaining({ event: 'activity.places_stale' }));
    expect(stale.capture.lines()).toContainEqual(
      expect.objectContaining({ level: 'warn', event: 'activity.places_stale', days: PLACES_STALE_DAYS + 1 }),
    );
  });

  it.each(['development', 'test'] as const)('records no place in %s without the file', async (environment) => {
    const { capture, logger } = logged();

    await expect(loadPlaces(environment, logger, join(directory, 'none.mmdb'))).resolves.toBeUndefined();
    expect(capture.lines()).toContainEqual(expect.objectContaining({ event: 'activity.places_off' }));
  });

  it.each(['staging', 'production'] as const)('refuses to start in %s without the file', async (environment) => {
    await expect(loadPlaces(environment, logged().logger, join(directory, 'none.mmdb'))).rejects.toThrow(/ENOENT/);
  });

  it('refuses to start on a file it can’t read, even in development', async () => {
    await expect(loadPlaces('development', logged().logger, directory)).rejects.toThrow(/EISDIR/);
  });

  it('refuses to start on a file that isn’t a place file', async () => {
    const path = join(directory, 'other.mmdb');
    await writeFile(path, placeFile([], 'GeoLite2-City'));

    await expect(loadPlaces('development', logged().logger, path)).rejects.toThrow(/not DBIP-City-Lite/);
  });

  it('looks in the repository’s geo folder, where the image puts the file', () => {
    expect(PLACE_FILE.replaceAll('\\', '/')).toMatch(/\/geo\/dbip-city-lite\.mmdb$/);
    expect(PLACE_FILE.replaceAll('\\', '/')).not.toMatch(/apps\/api/);
  });
});

describe('the browser’s time zone', () => {
  it('is a zone Intl knows, as it names it', () => {
    expect(timeZoneSent('Asia/Dubai')).toBe('Asia/Dubai');
    expect(timeZoneSent('europe/london')).toBe('Europe/London');
    expect(timeZoneSent('UTC')).toBe('UTC');
  });

  it.each([
    ['none sent', undefined],
    ['sent twice', ['Asia/Dubai', 'Europe/London']],
    ['a zone Intl doesn’t know', 'Mars/Olympus_Mons'],
    ['a bare offset', '+04:00'],
    ['too long', `Asia/${'x'.repeat(60)}`],
    ['empty', ''],
  ])('is none when %s', (_what, header) => {
    expect(timeZoneSent(header)).toBeUndefined();
  });
});
