// The activity log's clues to where a client may be (Phase 3 L4, decision 26;
// ADR-011 §7): the approximate country and city its IP address is registered
// to, and the time zone its browser says it is in. Clues, never proof: a VPN
// or a company network shows somewhere else, and a browser says what it likes.
//
// - The place comes from DB-IP's IP to City Lite (CC BY 4.0: "IP Geolocation
//   by DB-IP", https://db-ip.com), a file the image holds (Dockerfile, pinned
//   by its SHA-256); nothing is asked of anyone at run time. The API reads it
//   whole at start (127 MB, about 45 ms) and looks an address up in about
//   10 µs. A deployed API refuses to start without it; a developer's runs
//   without it simply record no place.
// - The time zone is the `X-Time-Zone` header the console will send (Phase 6):
//   an IANA zone Intl knows, as it names it. Anything else is no zone.
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

import { type ClientPlace, COUNTRY_CODE, MOST_CITY_LENGTH, TIME_ZONE_NAME } from '@agentx/core/modules/activity';
import { isIpAddress, plainLine, timeZoneOf } from '@agentx/core/shared-kernel';
import { type Environment, LOCAL_ONLY } from '@agentx/platform/config';
import type { Logger } from '@agentx/platform/observability';
import { Reader } from 'mmdb-lib';

/** Where the image keeps the place file (Dockerfile); a developer may put a copy there too. */
export const PLACE_FILE = fileURLToPath(new URL('../../../geo/dbip-city-lite.mmdb', import.meta.url));

/** The only kind of file the place finder reads: another's records could mean something else. */
const PLACE_DATABASE_TYPE = 'DBIP-City-Lite';

/** The header a browser names its time zone in. */
export const TIME_ZONE_HEADER = 'x-time-zone';

/** The place an IP address is registered to, or undefined when none is known. */
export type PlaceOf = (address: string) => ClientPlace | undefined;

/** DB-IP's code for a country not known. */
const NO_COUNTRY = 'ZZ';

/** The text at a path through a record, if there is text there. */
function textAt(record: unknown, ...path: readonly string[]): string | undefined {
  let value = record;
  for (const key of path) {
    if (typeof value !== 'object' || value === null || !Object.hasOwn(value, key)) return undefined;
    value = (value as Record<string, unknown>)[key];
  }
  return typeof value === 'string' ? value : undefined;
}

/** A city's English name as one line of plain text, or undefined for none, or one too long to keep. */
export const cityName = (value: unknown): string | undefined => plainLine(value, MOST_CITY_LENGTH);

/** The place a record names: its country by ISO code, and its city when it names one. */
export function placeIn(record: unknown): ClientPlace | undefined {
  const country = textAt(record, 'country', 'iso_code');
  if (country === undefined || !COUNTRY_CODE.test(country) || country === NO_COUNTRY) return undefined;
  return { country, city: cityName(textAt(record, 'city', 'names', 'en')) };
}

/** The place finder over a DB-IP City Lite file's bytes. Throws for any other file. */
export function placeFinderOf(file: Buffer): { readonly placeOf: PlaceOf; readonly built: Date } {
  const reader = new Reader(file);
  const { databaseType, buildEpoch } = reader.metadata;
  if (databaseType !== PLACE_DATABASE_TYPE) {
    throw new Error(`the place file is ${databaseType}, not ${PLACE_DATABASE_TYPE}`);
  }
  return {
    // The reader reads any text as some address, so only a checked one is looked up.
    placeOf: (address) => (isIpAddress(address) ? placeIn(reader.get(address)) : undefined),
    built: buildEpoch,
  };
}

/** Whether an error says the file isn't there. */
const notThere = (error: unknown): boolean => error instanceof Error && 'code' in error && error.code === 'ENOENT';

/**
 * The place finder from the image's file, or undefined in development or a
 * test without one. Throws when a deployed API has none, or any file is not
 * DB-IP City Lite.
 */
export async function loadPlaces(
  environment: Environment,
  logger: Logger,
  path: string = PLACE_FILE,
): Promise<PlaceOf | undefined> {
  let file: Buffer;
  try {
    file = await readFile(path);
  } catch (error) {
    if (!notThere(error) || !LOCAL_ONLY.includes(environment)) throw error;
    logger.info('activity.places_off', { reason: 'no place file' });
    return undefined;
  }
  const { placeOf, built } = placeFinderOf(file);
  logger.info('activity.places_loaded', { database: PLACE_DATABASE_TYPE, built: built.toISOString() });
  return placeOf;
}

/** The time zone a request's browser named, as Intl names it, or undefined for none or one it doesn't know. */
export function timeZoneSent(header: string | string[] | undefined): string | undefined {
  // TIME_ZONE_NAME's own limit, before Intl is handed any amount of text.
  if (typeof header !== 'string' || header.length > 64) return undefined;
  const zone = timeZoneOf(header);
  return zone !== undefined && TIME_ZONE_NAME.test(zone) ? zone : undefined;
}
