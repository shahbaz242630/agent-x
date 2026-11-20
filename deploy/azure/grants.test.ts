import { describe, expect, it } from 'vitest';

import type { Az, AzResult } from './deploy.ts';
import {
  checkGrants,
  giveStageGReads,
  grantDrift,
  grantLines,
  type LiveGrants,
  readLiveGrants,
  takeStageGReads,
} from './grants.ts';
import { GRANTS, STAGE_G_RUN_READS } from './policy.ts';

const SUB = '00000000-0000-0000-0000-000000000001';
const VAULT = `/subscriptions/${SUB}/resourceGroups/rg-agentx-staging/providers/Microsoft.KeyVault/vaults/kv-agentx-stg-abcdef`;
const USER = `/subscriptions/${SUB}/providers/Microsoft.Authorization/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6`;
const OTHER_ROLE = `/subscriptions/${SUB}/providers/Microsoft.Authorization/roleDefinitions/b86a8fe4-44ce-4948-aee5-eccb2c155cd7`;
const GROUP = `/subscriptions/${SUB}/resourceGroups/rg-agentx-staging`;
/** Built-in roles by ID (Microsoft's list): Reader reads no secret; Crypto Officer is one of Key Vault's data roles. */
const READER = 'acdd72a7-3385-48ef-bd42-f606fba81ae7';
const CRYPTO_OFFICER = '14b46e9e-c2b7-41b4-b07b-48a6ebf60603';
const role = (id: string): string => `/subscriptions/${SUB}/providers/Microsoft.Authorization/roleDefinitions/${id}`;
const API = '11111111-1111-1111-1111-111111111111';
const TENANT = '44444444-4444-4444-4444-444444444444';
const LOGIN = '22222222-2222-2222-2222-222222222222';
const STRANGER = '33333333-3333-3333-3333-333333333333';

const on = (secret: string, principalId: string, roleDefinitionId = USER) => ({
  scope: `${VAULT}/secrets/${secret}`,
  principalId,
  roleDefinitionId,
});

const live = (assignments: LiveGrants['assignments']): LiveGrants => ({
  vault: VAULT,
  assignments,
  identities: new Map([
    [API, 'api'],
    [LOGIN, 'login'],
  ]),
});

describe("the vault's grants against GRANTS (AZ32)", () => {
  it('reads each Secrets User grant of ours on one secret in GRANTS’ words, and anything else as what it is, never an ID', () => {
    const lines = grantLines(
      live([
        on('db-app-password', API),
        on('login-client-private-key', LOGIN),
        // Above the vault, a role that reads no secret (the group's Reader) is no grant of the vault's; one that reads
        // or manages its data (any of Key Vault's data roles), on the group or the subscription, reaches every secret.
        { scope: GROUP, principalId: STRANGER, roleDefinitionId: role(READER) },
        { scope: GROUP, principalId: STRANGER, roleDefinitionId: USER },
        { scope: `/subscriptions/${SUB}`, principalId: API, roleDefinitionId: role(CRYPTO_OFFICER.toUpperCase()) },
        // Above the subscription too: a management group (the Tenant Root Group among them, any case) and the root.
        {
          scope: `/providers/Microsoft.Management/managementGroups/${TENANT}`,
          principalId: STRANGER,
          roleDefinitionId: USER,
        },
        { scope: '/', principalId: LOGIN, roleDefinitionId: role(CRYPTO_OFFICER) },
        {
          scope: '/providers/microsoft.management/managementgroups/x',
          principalId: STRANGER,
          roleDefinitionId: role(READER),
        },
        // Another group, its name a part of this one's, is not above this vault; nor one named longer.
        { scope: GROUP.slice(0, -3), principalId: STRANGER, roleDefinitionId: USER },
        { scope: `${GROUP}2`, principalId: STRANGER, roleDefinitionId: USER },
        // A vault that merely starts with this one's name is another vault.
        { scope: `${VAULT}2/secrets/db-app-password`, principalId: STRANGER, roleDefinitionId: USER },
        { scope: VAULT, principalId: API, roleDefinitionId: USER },
        on('db-owner-password', STRANGER),
        on('db-app-password', LOGIN, OTHER_ROLE),
        { ...on('db-app-password', API), scope: `${VAULT.toUpperCase()}/secrets/db-app-password` },
      ]),
    );
    expect(lines).toEqual([
      'api reads db-app-password',
      'login reads login-client-private-key',
      'an identity not of this deployment holds Key Vault Secrets User over the whole vault, from above it (its resource group, subscription, a management group or the root)',
      'api holds Key Vault Crypto Officer over the whole vault, from above it (its resource group, subscription, a management group or the root)',
      'an identity not of this deployment holds Key Vault Secrets User over the whole vault, from above it (its resource group, subscription, a management group or the root)',
      'login holds Key Vault Crypto Officer over the whole vault, from above it (its resource group, subscription, a management group or the root)',
      'api holds Key Vault Secrets User on the whole vault',
      'an identity not of this deployment holds Key Vault Secrets User on db-owner-password',
      'login holds Key Vault Secrets Officer on db-app-password',
      'api reads db-app-password',
    ]);
    // A role no list names, on a secret, is said as another.
    expect(grantLines(live([on('db-app-password', API, role(READER))]))).toEqual([
      'api holds another role on db-app-password',
    ]);
    expect(lines.join(' ')).not.toMatch(/[0-9a-f]{8}-/);
  });

  it('fails only on a grant beyond the list, and names the ones Azure lacks', () => {
    expect(grantDrift([...GRANTS])).toEqual({ extra: [], missing: [] });
    const drift = grantDrift(['api reads db-app-password', 'api reads db-owner-password', 'api reads db-app-password']);
    expect(drift.extra).toEqual(['api reads db-owner-password']);
    expect(drift.missing).toContain('login reads login-client-private-key');
    expect(drift.missing).not.toContain('api reads db-app-password');
  });

  /** A CLI answering the vault list, the identity list and the assignments (two pages) as given. */
  const cli = (assignments: readonly LiveGrants['assignments'][number][], vaults: readonly string[] = [VAULT]) => {
    const calls: string[] = [];
    const ok = (value: unknown): AzResult => ({ status: 0, stdout: JSON.stringify(value), stderr: '' });
    const az: Az = {
      interactive: () => 0,
      run: (args) => {
        calls.push(args.slice(0, 2).join(' '));
        if (args[0] === 'keyvault') return ok(vaults);
        if (args[0] === 'identity') {
          return ok([
            { name: 'id-agentx-stg-api', principalId: API },
            { name: 'id-agentx-stg-login', principalId: LOGIN },
            { name: 'someone-else', principalId: STRANGER },
          ]);
        }
        const url = args[args.indexOf('--url') + 1] ?? '';
        const value = assignments.map((properties) => ({ properties }));
        return url.includes('$skiptoken')
          ? ok({ value: value.slice(1) })
          : ok({ value: value.slice(0, 1), nextLink: `${url}&$skiptoken=1` });
      },
    };
    return { az, calls };
  };

  it('reads the vault, our identities and every page of the assignments on it', () => {
    const { az, calls } = cli([on('db-app-password', API), on('login-client-private-key', LOGIN)]);
    const read = readLiveGrants(az, SUB);
    expect(grantLines(read)).toEqual(['api reads db-app-password', 'login reads login-client-private-key']);
    expect([...read.identities.values()]).toEqual(['api', 'login']);
    expect(calls).toEqual(['keyvault list', 'identity list', 'rest --method', 'rest --method']);
    expect(() => readLiveGrants(cli([], []).az, SUB)).toThrow(/must hold one key vault/);
  });

  it('says what broke and what next, and ends 1, on a grant beyond the list; 0 with the lacking ones named otherwise', () => {
    const said: string[] = [];
    expect(checkGrants(cli([on('db-owner-password', STRANGER)]).az, SUB, (line) => said.push(line))).toBe(1);
    expect(said.join('\n')).toMatch(
      /holds 1 grant the repository doesn't list: an identity not of this deployment holds Key Vault Secrets User on db-owner-password\./,
    );
    expect(said.at(-1)).toMatch(/^What broke: .* What next: /);
    const fine: string[] = [];
    expect(checkGrants(cli([on('db-app-password', API)]).az, SUB, (line) => fine.push(line))).toBe(0);
    expect(fine[0]).toMatch(/^The vault lacks \d+ grants the repository lists \(the next secrets run makes them\)/);
    expect(fine.at(-1)).toBe("The vault's grants: none beyond the repository's list (GRANTS, policy.ts).");
  });
});

describe("Stage G's reads, for a run alone (S204-b)", () => {
  const STAGE_G = '55555555-5555-5555-5555-555555555555';
  /** A CLI holding the given assignments (each with its own ID), recording every write sent. */
  const azure = (held: readonly ReturnType<typeof on>[], refuse = false, stageG = STAGE_G) => {
    const writes: { method: string; url: string; body?: unknown }[] = [];
    const ok = (value: unknown): AzResult => ({ status: 0, stdout: JSON.stringify(value), stderr: '' });
    const az: Az = {
      interactive: () => 0,
      run: (args) => {
        if (args[0] === 'keyvault') return ok([VAULT]);
        if (args[0] === 'identity') {
          return ok([
            { name: 'id-agentx-stg-api', principalId: API },
            { name: 'id-agentx-stg-stage-g', principalId: stageG },
          ]);
        }
        const method = args[args.indexOf('--method') + 1] ?? '';
        const url = args[args.indexOf('--url') + 1] ?? '';
        if (method === 'get') {
          return ok({
            value: held.map((properties, index) => ({
              id: `${properties.scope}/providers/Microsoft.Authorization/roleAssignments/a${String(index)}`,
              properties,
            })),
          });
        }
        const body = args.includes('--body')
          ? (JSON.parse(args[args.indexOf('--body') + 1] ?? '') as unknown)
          : undefined;
        writes.push({ method, url, body });
        return refuse ? { status: 1, stdout: '', stderr: 'Forbidden' } : ok({});
      },
    };
    return { az, writes };
  };

  it('gives the three it lacks, each on its own secret as Secrets User, and none twice', () => {
    const { az, writes } = azure([on('db-owner-password', STAGE_G), on('db-app-password', API)]);
    expect(giveStageGReads(az, SUB, () => 'n1')).toEqual(['db-app-password', 'db-backup-password']);
    expect(writes).toEqual(
      ['db-app-password', 'db-backup-password'].map((secret) => ({
        method: 'put',
        url: `https://management.azure.com${VAULT}/secrets/${secret}/providers/Microsoft.Authorization/roleAssignments/n1?api-version=2022-04-01`,
        body: { properties: { roleDefinitionId: USER, principalId: STAGE_G, principalType: 'ServicePrincipal' } },
      })),
    );
    // Exactly the run's reads, which GRANTS leaves out: none stands between runs.
    expect(STAGE_G_RUN_READS).toEqual(
      new Set(
        ['db-owner-password', 'db-app-password', 'db-backup-password'].map((secret) => `stage-g reads ${secret}`),
      ),
    );
    for (const read of STAGE_G_RUN_READS) expect(GRANTS.has(read)).toBe(false);
    expect(() => giveStageGReads(azure([], true).az, SUB)).toThrow(/Azure refused stage-g's read of db-owner-password/);
  });

  it("takes back every read of Stage G's on a secret, another's and the vault's own left alone", () => {
    const { az, writes } = azure([
      on('db-owner-password', STAGE_G),
      on('db-backup-password', STAGE_G, OTHER_ROLE),
      on('db-app-password', API),
      { scope: VAULT, principalId: STAGE_G, roleDefinitionId: USER },
      on('db-app-password', STAGE_G, role(READER)),
    ]);
    expect(takeStageGReads(az, SUB)).toBe(2);
    expect(writes.map(({ method, url }) => `${method} ${url}`)).toEqual([
      `delete https://management.azure.com${VAULT}/secrets/db-owner-password/providers/Microsoft.Authorization/roleAssignments/a0?api-version=2022-04-01`,
      `delete https://management.azure.com${VAULT}/secrets/db-backup-password/providers/Microsoft.Authorization/roleAssignments/a1?api-version=2022-04-01`,
    ]);
    expect(() => takeStageGReads(azure([on('db-owner-password', STAGE_G)], true).az, SUB)).toThrow(
      /Azure refused to take back stage-g's grant on db-owner-password: run it again/,
    );
  });

  it('refuses with no Stage G identity, changing nothing', () => {
    // Its identity listed without a principal is no identity of ours.
    const { az, writes } = azure([on('db-app-password', API)], false, '');
    expect(() => giveStageGReads(az, SUB)).toThrow(/has no identity for stage-g: nothing was changed/);
    expect(() => takeStageGReads(az, SUB)).toThrow(/has no identity for stage-g/);
    expect(writes).toEqual([]);
  });

  it('fails the plan on a read left standing, saying to revoke it', () => {
    const said: string[] = [];
    const { az } = azure([on('db-owner-password', STAGE_G)]);
    expect(checkGrants(az, SUB, (line) => said.push(line))).toBe(1);
    expect(said.at(-1)).toMatch(/^What broke: these are Stage G's run reads.*node deploy\/azure\/stage-g\.ts revoke/);
    // Beside a grant of anyone else's, the alarm is the full one: it is no run's read.
    const mixed: string[] = [];
    const both = azure([on('db-owner-password', STAGE_G), on('db-admin-password', API)]).az;
    expect(checkGrants(both, SUB, (line) => mixed.push(line))).toBe(1);
    expect(mixed.at(-1)).toMatch(/^What broke: each is a way into a secret nobody decided on/);
  });
});
