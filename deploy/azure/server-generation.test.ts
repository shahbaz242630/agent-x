import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  baseServerOf,
  generationOf,
  generationsProblems,
  MOST_GENERATIONS,
  readGenerations,
  serverGenerationVerdict,
  serverNameOf,
  type ServerSaid,
  suffixOfVault,
  type VaultRead,
  vaultRead,
} from './server-generation.ts';
import { deploymentSnapshot, inCopy, type Snapshot } from './snapshot.ts';

const SUBSCRIPTION = '00000000-0000-0000-0000-000000000001';

describe('database-generation.json (AZ25)', () => {
  it('holds generation 0 for both environments today: the names every deployment has always used', () => {
    expect(readGenerations()).toEqual({ staging: 0, production: 0 });
  });

  it('refuses anything but a whole generation from 0 to the most for each environment, and no other key', () => {
    expect(generationsProblems({ staging: 2, production: MOST_GENERATIONS })).toEqual([]);
    expect(generationsProblems([])).toEqual(['database-generation.json must hold each environment and its generation']);
    expect(generationsProblems(null)).toHaveLength(1);
    expect(generationsProblems({ staging: 0 })).toEqual([
      "production's generation must be a whole number from 0 to 99",
    ]);
    for (const bad of [-1, 1.5, '1', MOST_GENERATIONS + 1, null]) {
      expect(generationsProblems({ staging: bad, production: 0 })).toEqual([
        "staging's generation must be a whole number from 0 to 99",
      ]);
    }
    expect(generationsProblems({ staging: 0, production: 0, dev: 0 })).toEqual([
      'dev is no environment: only staging and production have a server',
    ]);
    expect(() => readGenerations(() => '{"staging":-1,"production":0}')).toThrow(
      "database-generation.json can't be used:\n- staging's generation must be a whole number from 0 to 99",
    );
  });
});

describe('server names by generation', () => {
  it('adds nothing at generation 0 and -r<n> after it, and reads a generation back only from those names', () => {
    expect(serverNameOf('stg', 'abcdef', 0)).toBe('psql-agentx-stg-abcdef');
    expect(serverNameOf('prd', 'abcdef', 12)).toBe('psql-agentx-prd-abcdef-r12');
    expect(generationOf('psql-agentx-stg-abcdef', 'stg', 'abcdef')).toBe(0);
    expect(generationOf('psql-agentx-stg-abcdef-r3', 'stg', 'abcdef')).toBe(3);
    for (const other of [
      'psql-agentx-stg-drill',
      'psql-agentx-stg-before',
      'psql-agentx-stg-g-a1b2c3d4',
      'psql-agentx-stg-abcdef-r0',
      'psql-agentx-stg-abcdef-r01',
      'psql-agentx-stg-abcdef-r100',
      'psql-agentx-stg-abcdef-before',
      'psql-agentx-prd-abcdef',
      'psql-agentx-stg-zzzzzz',
      // Another suffix's later generation is no generation of this one's.
      'psql-agentx-stg-zzzzzz-r1',
    ]) {
      expect(generationOf(other, 'stg', 'abcdef')).toBeUndefined();
    }
    expect(suffixOfVault('kv-agentx-stg-abcdef', 'stg')).toBe('abcdef');
    expect(suffixOfVault('kv-agentx-stg-abcdefg', 'stg')).toBeUndefined();
    expect(suffixOfVault('kv-agentx-prd-abcdef', 'stg')).toBeUndefined();
    expect(baseServerOf('psql-agentx-stg-abcdef-r12')).toBe('psql-agentx-stg-abcdef');
    expect(baseServerOf('psql-agentx-stg-abcdef')).toBe('psql-agentx-stg-abcdef');
  });

  it('reads the vault list as none, one with its suffix, or unread', () => {
    expect(vaultRead([], 'stg')).toEqual({ kind: 'none' });
    expect(vaultRead(['kv-agentx-stg-abc123'], 'stg')).toEqual({ kind: 'read', suffix: 'abc123' });
    for (const listed of [undefined, {}, ['kv-agentx-stg-abc123', 'kv-agentx-stg-def456'], ['other'], [7]]) {
      expect(vaultRead(listed, 'stg')).toEqual({ kind: 'unread' });
    }
  });

  it('goes only to a generation whose server is there and none newer, or a first deploy, unless the operator says', () => {
    const read: VaultRead = { kind: 'read', suffix: 'abc123' };
    const verdict = (
      generation: number,
      servers: readonly string[] | undefined,
      vault: VaultRead = read,
      said: ServerSaid = {},
    ) => serverGenerationVerdict({ short: 'stg', generation, vault, servers, said }).kind;
    const base = 'psql-agentx-stg-abc123';
    const none: VaultRead = { kind: 'none' };
    const unread: VaultRead = { kind: 'unread' };
    expect(verdict(0, [base])).toBe('go');
    expect(verdict(1, [base, `${base}-r1`])).toBe('go');
    // The one true first deploy: no vault yet, nothing or nothing readable in the group.
    expect(verdict(0, [], none)).toBe('go');
    expect(verdict(0, undefined, none)).toBe('go');
    expect(verdict(0, [base], none)).toBe('refused');
    expect(verdict(0, [base], none, { firstServer: true })).toBe('go');
    expect(verdict(1, [], none, { firstServer: true })).toBe('refused');
    // A foundation ran (the vault is there) and the live server is missing, or can't be seen: a loss until said.
    expect(verdict(0, [])).toBe('refused');
    expect(verdict(0, undefined)).toBe('refused');
    expect(verdict(0, [base], unread)).toBe('refused');
    expect(verdict(0, ['psql-agentx-stg-before'])).toBe('refused');
    expect(verdict(0, [], read, { firstServer: true })).toBe('go');
    expect(verdict(0, undefined, read, { firstServer: true })).toBe('go');
    expect(verdict(0, [base], unread, { firstServer: true })).toBe('go');
    expect(verdict(1, undefined, read, { firstServer: true })).toBe('refused');
    // Two live databases: back to an older generation only when the operator names it.
    expect(verdict(0, [base, `${base}-r1`])).toBe('refused');
    expect(verdict(0, [base, `${base}-r1`], read, { backTo: 0 })).toBe('go');
    expect(verdict(0, [base, `${base}-r1`], read, { backTo: 1 })).toBe('refused');
    expect(verdict(1, [base, `${base}-r1`], read, { backTo: 0 })).toBe('refused');
    expect(verdict(1, [base, `${base}-r1`, `${base}-r2`], read, { backTo: 1 })).toBe('go');
    expect(verdict(1, [base])).toBe('refused');
    expect(verdict(2, [base])).toBe('refused');
    expect(verdict(0, [`${base}-r1`])).toBe('refused');
    expect(verdict(1, [])).toBe('refused');
    expect(verdict(1, undefined)).toBe('refused');
    expect(verdict(1, [base, `${base}-r1`], unread)).toBe('refused');
    // Another environment's suffix is not this one's server.
    expect(verdict(1, [base, 'psql-agentx-stg-zzzzzz-r1'])).toBe('refused');
  });
});

/** The server, the vault and the API's database host, as one deployment of each would name them. */
function names(dir: string): { server: string; vault: string; host: string } {
  const foundation = deploymentSnapshot(dir, 'staging.bicepparam', undefined, {}, SUBSCRIPTION);
  const apps = deploymentSnapshot(dir, 'staging.apps.bicepparam', 'rg-agentx-staging', {}, SUBSCRIPTION);
  const of = (snapshot: Snapshot, type: string): string =>
    snapshot.predictedResources.find((resource) => resource.type === type)?.name ?? '';
  const api = apps.predictedResources.find((resource) => resource.name === 'ca-agentx-stg-api');
  const host = /"name":"AGENTX_DB_HOST","value":"([^"]+)"/.exec(JSON.stringify(api?.properties))?.[1] ?? '';
  return {
    server: of(foundation, 'Microsoft.DBforPostgreSQL/flexibleServers'),
    vault: of(foundation, 'Microsoft.KeyVault/vaults'),
    host,
  };
}

describe('what Bicep names from the generation (AZ25)', () => {
  it("names today's server at generation 0, exactly as before, and the next generation's with -r1, the host with it", () => {
    const today = inCopy((dir) => names(dir));
    const suffix = suffixOfVault(today.vault, 'stg') ?? '';
    expect(suffix).toMatch(/^[a-z0-9]{6}$/);
    // The name the foundation gave before AZ25: psql-agentx-<short>-<suffix>, nothing after it.
    expect(today.server).toBe(`psql-agentx-stg-${suffix}`);
    expect(today.host).toBe(`psql-agentx-stg-${suffix}.postgres.database.azure.com`);
    const next = inCopy((dir) => {
      const file = path.join(dir, 'database-generation.json');
      const held = JSON.parse(readFileSync(file, 'utf8')) as Record<string, number>;
      writeFileSync(file, JSON.stringify({ ...held, staging: 1 }));
      return names(dir);
    });
    expect(next.vault).toBe(today.vault);
    expect(next.server).toBe(`psql-agentx-stg-${suffix}-r1`);
    expect(next.host).toBe(`psql-agentx-stg-${suffix}-r1.postgres.database.azure.com`);
    expect(serverNameOf('stg', suffix, 1)).toBe(next.server);
  }, 240_000);
});
