import { describe, expect, it } from 'vitest';

import type { Az, AzResult } from './deploy.ts';
import { checkGrants, grantDrift, grantLines, type LiveGrants, readLiveGrants } from './grants.ts';
import { GRANTS } from './policy.ts';

const SUB = '00000000-0000-0000-0000-000000000001';
const VAULT = `/subscriptions/${SUB}/resourceGroups/rg-agentx-staging/providers/Microsoft.KeyVault/vaults/kv-agentx-stg-abcdef`;
const USER = `/subscriptions/${SUB}/providers/Microsoft.Authorization/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6`;
const OTHER_ROLE = `/subscriptions/${SUB}/providers/Microsoft.Authorization/roleDefinitions/b86a8fe4-44ce-4948-aee5-eccb2c155cd7`;
const API = '11111111-1111-1111-1111-111111111111';
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
        // A grant above the vault (the group's Reader, say) is no grant of the vault's.
        {
          scope: `/subscriptions/${SUB}/resourceGroups/rg-agentx-staging`,
          principalId: STRANGER,
          roleDefinitionId: USER,
        },
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
      'api holds Key Vault Secrets User on the whole vault',
      'an identity not of this deployment holds Key Vault Secrets User on db-owner-password',
      'login holds another role on db-app-password',
      'api reads db-app-password',
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
