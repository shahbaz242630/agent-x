// An order's canonical form (0067's `order_key_of`, PL-39, ADR-006 §5, SEC-DP-10):
// Unicode's full case fold from a table of its own, the same on every server.
import { createTestDatabase, type TestDatabase, type TestSession } from '@agentx/testing';
import { afterAll, beforeAll, describe, expect, inject, it } from 'vitest';

let database: TestDatabase;
let app: TestSession;

beforeAll(async () => {
  database = await createTestDatabase(inject('postgres'), { schema: 'migrated' });
  app = database.as('app');
});

afterAll(async () => {
  await database.drop();
});

const keyOf = async (reference: string): Promise<string> => {
  const [row] = await app.query<{ key: string }>('select spend_requests.order_key_of($1) as key', [reference]);
  return row?.key ?? '';
};

/** Every code point in use: a surrogate can't be text, and the edge refuses the rest of Unicode's "other" category. */
function pointsInUse(): string[] {
  const points: string[] = [];
  for (let c = 1; c <= 0x10ffff; c += 1) {
    if (c >= 0xd800 && c <= 0xdfff) continue;
    const text = String.fromCodePoint(c);
    if (!/\p{C}/u.test(text)) points.push(text);
  }
  return points;
}

/** Whether a code point can change under normalising or case, so a mark after it could matter. */
const canChange = (text: string): boolean =>
  text.normalize('NFKC') !== text ||
  text.normalize('NFD') !== text ||
  text.toLowerCase() !== text ||
  text.toUpperCase() !== text;

const lengthOf = (text: string): number => Array.from(text).length;

/** Each code point that can change with each mark Unicode composes: every pair that composes, one in 400 of the rest. */
function pairsToWeigh(): string[] {
  const points = pointsInUse();
  const marks = new Set(points.flatMap((text) => Array.from(text.normalize('NFD')).slice(1)));
  const pairs: string[] = [];
  let passed = 0;
  for (const base of points.filter(canChange)) {
    const alone = lengthOf(base.normalize('NFKC'));
    for (const mark of marks) {
      const pair = base + mark;
      passed += 1;
      if (lengthOf(pair.normalize('NFKC')) <= alone || passed % 400 === 0) pairs.push(pair);
    }
  }
  return pairs;
}

describe('the order key', () => {
  it.each([
    ['German sharp s', 'strasse-1', ['Straße-1', 'STRASSE-1', 'STRAẞE-1']],
    ['Turkish dotted and dotless i', 'inv', ['İNV', 'INV', 'Inv', 'ınv', 'İNV', 'i̇nv']],
    [
      'a styled capital I with a dot, which NFKC composes',
      'i',
      ['\u{1D43C}\u0307', '\u2110\u0307', '\uFF29\u0307', '\u0130'],
    ],
    ['Turkish, inside a word', 'kiz', ['KIZ', 'kız', 'KİZ', 'kiz']],
    ['Greek sigmas', 'σασ', ['ΣΑΣ', 'σας', 'Σας']],
    ['a ligature', 'fi-7', ['ﬁ-7', 'FI-7', 'Fi-7']],
    ['a full fold past NFKC', 'ss', ['ß', 'ẞ', 'SS', 'ſſ']],
    ['a composed and decomposed letter', 'école', ['ÉCOLE', 'ÉCOLE', 'école', 'École']],
    [
      'a mark that folds to a letter, in canonical order',
      `α${String.fromCharCode(0x323)}ι`,
      [`α${String.fromCharCode(0x345, 0x323)}`, `α${String.fromCharCode(0x323, 0x345)}`],
    ],
    ['a capital NFKC brings out', '°c', ['℃', '°C']],
    ['the Kelvin sign', 'k-1', ['K-1', 'K-1']],
    ['Roman numerals', 'viii', ['Ⅷ', 'ⅷ', 'VIII']],
    ['a title-case digraph', 'dž', ['ǅ', 'Ǆ', 'ǆ']],
    ['Cherokee, which folds to its capitals', 'Ꭰ', ['ꭰ', 'Ꭰ']],
    ['Georgian capitals', 'ა', ['Ა', 'ა']],
    ['past the first plane: Deseret', '\u{10428}', ['\u{10400}', '\u{10428}']],
    ['the newest table: Beria Erfe, Unicode 17', '\u{16EBB}', ['\u{16EA0}', '\u{16EBB}']],
    ['the one letter the edge knows and 18 can’t normalise', 's', ['꟱', 'S']],
    [
      'spaces, of every kind',
      'inv 22',
      ['  INV   22 ', `INV${String.fromCharCode(0xa0, 0x2003)}22`, `ＩＮＶ${String.fromCharCode(0x3000)}２２`],
    ],
    ['ASCII alone', 'inv 7/b (26)', ['  Inv 7/B   (26) ']],
  ])('makes one order of %s', async (_what, key, written) => {
    for (const each of [key, ...written]) expect(await keyOf(each)).toBe(key);
  });

  // The rows casefold() can't check below: its table is a version older.
  it('folds every cased letter new in Unicode 17', async () => {
    const beria = Array.from({ length: 25 }, (_, at) => 0x16ea0 + at);
    for (const point of [0xa7ce, 0xa7d2, 0xa7d4, ...beria]) {
      const letter = String.fromCodePoint(point);
      expect(await keyOf(letter)).toBe(letter.toLowerCase());
      expect(letter.toLowerCase()).not.toBe(letter);
    }
  });

  it.each([
    ['Latin and Cyrillic a: different letters, a look-alike is no case fold', 'inv-a', 'inv-а'],
    ['an accent', 'ecole', 'école'],
    ['Arabic-Indic and ASCII digits: possible duplicates, not exact ones (0043)', 'inv-12', 'inv-١٢'],
    ['one s and two', 's', 'ss'],
    ['a space kept between words', 'a b', 'ab'],
    ['another number', 'inv-1', 'inv-2'],
    ['another script', 'فاتورة', 'חשבונית'],
  ])('keeps apart %s', async (_what, one, other) => {
    expect(await keyOf(one)).not.toBe(await keyOf(other));
  });

  it("is the same in any locale: Turkish's own rules on I don't reach it", async () => {
    const rows = await app.query<{ plain: string; wider: string; turkish: string }>(
      `select spend_requests.order_key_of('INV' collate "tr-TR-x-icu") as plain,
              spend_requests.order_key_of('INVß' collate "tr-TR-x-icu") as wider,
              pg_catalog.lower('INV' collate "tr-TR-x-icu") as turkish`,
    );
    // The comparison proves the collation is really a Turkish one: lower() there gives no plain i.
    expect(rows).toEqual([{ plain: 'inv', wider: 'invss', turkish: 'ınv' }]);
  });

  it('is what the server may rest a key on: immutable, and the app may ask it but nobody else', async () => {
    const owner = database.as('owner');
    const rows = await owner.query(
      `select p.provolatile as volatility, p.proisstrict as strict,
              pg_catalog.has_function_privilege('agentx_backup', p.oid, 'execute') as backup
       from pg_catalog.pg_proc p
       where p.oid = 'spend_requests.order_key_of(text)'::pg_catalog.regprocedure`,
    );
    expect(rows).toEqual([{ volatility: 'i', strict: true, backup: false }]);
  });

  // The one part of the key the server's own tables decide. A new Postgres major that normalises any code point
  // differently moves a stored key away from a fresh one: this fails first, for a person to look before it is adopted.
  it('rests on the normalisation tables pinned for this server', async () => {
    const owner = database.as('owner');
    const [row] = await owner.query<{ major: number; tables: string; points: string }>(
      `select pg_catalog.current_setting('server_version_num')::int / 10000 as major,
              count(*)::text as points,
              pg_catalog.md5(pg_catalog.string_agg(
                pg_catalog.normalize(pg_catalog.chr(c), 'NFKC') || '|' || pg_catalog.normalize(pg_catalog.chr(c), 'NFD'), ','
                order by c)) as tables
       from pg_catalog.generate_series(1, 1114111) as c
       where c not between 55296 and 57343`,
    );
    const pinned: Record<number, string> = {
      16: '7bb8d930e144804f661b4e8e86e104f4',
      18: '5303ea0e062ba5edcb49b67f3efda5b4',
    };
    expect(row?.points).toBe('1112063');
    expect(row?.tables).toBe(pinned[row?.major ?? 0]);
  });

  // Past single code points: NFKC can compose a letter the fold's first pass never saw (a styled I + dot is U+0130).
  // Every pair that composes, and one in 400 of the rest, must give one key however it is written.
  it('gives one key to a code point and a combining mark, however they are written', { timeout: 120_000 }, async () => {
    const pairs = pairsToWeigh();
    expect(pairs.length).toBeGreaterThan(20_000);
    const wrong: string[] = [];
    for (let at = 0; at < pairs.length; at += 1000) {
      const rows = await app.query<{ written: string }>(
        `with keyed as materialized (
           select written, spend_requests.order_key_of(written) as key
           from pg_catalog.unnest($1::text[]) as written
         )
         select written from keyed
         where spend_requests.order_key_of(key) <> key
            or spend_requests.order_key_of(pg_catalog.normalize(written, 'NFKC')) <> key
            or spend_requests.order_key_of(pg_catalog.normalize(written, 'NFD')) <> key`,
        [pairs.slice(at, at + 1000)],
      );
      wrong.push(...rows.map(({ written }) => written));
    }
    expect(wrong).toEqual([]);
  });

  // Production's server against the edge's Unicode: a letter the edge lets in and the server can't normalise could
  // change key on a later server. Only U+A7F1 today, which 0067's table holds still. A new one needs the same.
  it('normalises as the edge does, but for the one letter its table holds still', async () => {
    const owner = database.as('owner');
    const [version] = await owner.query<{ major: number }>(
      "select pg_catalog.current_setting('server_version_num')::int / 10000 as major",
    );
    if (version?.major !== 18) return;
    const changed = await owner.query<{ c: number; nfkc: string; nfd: string }>(
      `select c, pg_catalog.normalize(pg_catalog.chr(c), 'NFKC') as nfkc, pg_catalog.normalize(pg_catalog.chr(c), 'NFD') as nfd
       from pg_catalog.generate_series(1, 1114111) as c
       where c not between 55296 and 57343
         and (pg_catalog.normalize(pg_catalog.chr(c), 'NFKC') <> pg_catalog.chr(c)
           or pg_catalog.normalize(pg_catalog.chr(c), 'NFD') <> pg_catalog.chr(c))`,
    );
    const server = new Map(changed.map(({ c, nfkc, nfd }) => [c, { nfkc, nfd }]));
    const apart: string[] = [];
    for (let c = 1; c <= 0x10ffff; c += 1) {
      if (c >= 0xd800 && c <= 0xdfff) continue;
      const text = String.fromCodePoint(c);
      const { nfkc, nfd } = server.get(c) ?? { nfkc: text, nfd: text };
      if (text.normalize('NFKC') !== nfkc || text.normalize('NFD') !== nfd) apart.push(c.toString(16));
    }
    expect(apart).toEqual(['a7f1']);
  });

  // Unicode's own method, as Postgres 18's casefold() does it: every code point in use must agree but what 0067 chose.
  it(
    'agrees with casefold() on every code point in use, and gives a key that is its own key',
    { timeout: 240_000 },
    async () => {
      const owner = database.as('owner');
      const [version] = await owner.query<{ major: number }>(
        "select pg_catalog.current_setting('server_version_num')::int / 10000 as major",
      );
      // casefold() has Unicode 16's table, 0067 Unicode 17's: its new letters are a named row above.
      const newInUnicode17 = 'c in (42958, 42962, 42964, 42993) or c between 93856 and 93880';
      const fold = (text: string) => `pg_catalog.casefold(${text} collate pg_unicode_fast)`;
      const nfkc = (text: string) => `pg_catalog.normalize(${text}, 'NFKC')`;
      const standard = nfkc(fold(nfkc(fold(`pg_catalog.normalize(pg_catalog.chr(c), 'NFD')`))));
      const turkish = nfkc(`pg_catalog.replace(pg_catalog.replace(${standard}, U&'\\0131', 'i'), U&'i\\0307', 'i')`);
      const expected = `pg_catalog.regexp_replace(pg_catalog.btrim(${turkish}), ' +', ' ', 'g')`;
      // 16 has no casefold(), and needs no second look: the key's table is the one function on both.
      const agrees = version?.major === 18 ? `(${newInUnicode17}) or key = ${expected}` : 'true';
      // eslint-disable-next-line agentx/no-string-built-sql -- Fixed text put together here, no value in it.
      const wrong = await owner.query(`
      with keyed as materialized (
        select c, spend_requests.order_key_of(pg_catalog.chr(c)) as key
        from pg_catalog.generate_series(1, 206000) as c
        where c not between 55296 and 57343
      )
      select c from keyed where not (${agrees}) or spend_requests.order_key_of(key) <> key limit 20`);
      expect(wrong).toEqual([]);
    },
  );
});
