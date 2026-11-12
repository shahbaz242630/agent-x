// Holding a live container to what apps.bicep gives it (AZ2c): the reading of
// the snapshot's ARM expressions, the comparison, and the real apps.bicep as the
// pinned Bicep snapshots it. Nothing here reaches Azure.
import { describe, expect, it } from 'vitest';

import {
  type Bound,
  containersOf,
  deployable,
  differences,
  expectedOf,
  type LiveContainer,
  matches,
  partsOf,
  SHELL_MARKERS,
  templatesIn,
  type Workload,
  workloadDifferences,
} from './drift.ts';

const SUBSCRIPTION = '00000000-0000-0000-0000-00000000000e';
const GUID = '2a9017ee-b3db-4c71-99de-0edb987e0f80';

/** Whether a value reads as the snapshot's text does, with a fresh binding unless one is given. */
const reads = (snapshot: string, live: string, bound: Bound = new Map()): boolean =>
  matches(partsOf(snapshot), live, bound);

const ID = (type: string, name: string): string =>
  `/subscriptions/${SUBSCRIPTION}/resourceGroups/rg-agentx-staging/providers/${type}/${name}`;
const ENVIRONMENT = `reference('${ID('Microsoft.App/managedEnvironments', 'cae-agentx-staging')}', '2026-01-01').defaultDomain`;
const MAIL = `reference('${ID('Microsoft.Communication/communicationServices', 'acs-agentx-stg-ab12')}', '2026-03-18').hostName`;

describe("reading the snapshot's values", () => {
  it('takes plain text as it is, `[[` as a plain `[`', () => {
    expect(reads('agentx', 'agentx')).toBe(true);
    expect(reads('agentx', 'agentx2')).toBe(false);
    expect(reads('[[x]', '[x]')).toBe(true);
    expect(reads('a.b', 'aXb')).toBe(false);
  });

  it("reads format, concat and string, and Azure's deploy-time properties by what each can be", () => {
    const origin = `[format('https://{0}.internal.{1}', 'ca-agentx-stg-zitadel', ${ENVIRONMENT})]`;
    expect(reads(origin, 'https://ca-agentx-stg-zitadel.internal.ashy-1.uaenorth.azurecontainerapps.io')).toBe(true);
    // Azure's domain, never another's.
    expect(reads(origin, 'https://ca-agentx-stg-zitadel.internal.evil.example')).toBe(false);
    expect(reads(`[format('https://{0}', ${MAIL})]`, 'https://acs-agentx-stg-ab12.uae.communication.azure.com')).toBe(
      true,
    );
    expect(reads(`[format('https://{0}', ${MAIL})]`, 'https://evil.uae.communication.azure.com')).toBe(false);
    const sender = `[format('DoNotReply@{0}', reference('${ID('Microsoft.Communication/emailServices', 'e/domains/AzureManagedDomain')}', '2026-03-18').mailFromSenderDomain)]`;
    expect(reads(sender, `DoNotReply@${GUID}.azurecomm.net`)).toBe(true);
    expect(reads(sender, 'DoNotReply@evil.example')).toBe(false);
    const client = `[reference('${ID('Microsoft.ManagedIdentity/userAssignedIdentities', 'id-agentx-stg-api')}', '2024-11-30').clientId]`;
    expect(reads(client, GUID)).toBe(true);
    expect(reads(client, 'not-a-guid')).toBe(false);
    const store = "[format('https://{0}.blob.{1}/{2}', 'stagentx', environment().suffixes.storage, 'audit-anchors')]";
    expect(reads(store, 'https://stagentx.blob.core.windows.net/audit-anchors')).toBe(true);
    expect(reads(store, 'https://stagentx.blob.evil.example/audit-anchors')).toBe(false);
    expect(reads("[concat('a', string(1), 'b')]", 'a1b')).toBe(true);
    expect(reads("[format('{0}''s', 'it')]", "it's")).toBe(true);
    // A vault entry: the vault's own address, and the path under it.
    const entry = `[uri(reference('${ID('Microsoft.KeyVault/vaults', 'kv-agentx-stg-ab12')}', '2025-05-01').vaultUri, 'secrets/db-owner-password')]`;
    expect(reads(entry, 'https://kv-agentx-stg-ab12.vault.azure.net/secrets/db-owner-password')).toBe(true);
    expect(reads(entry, 'https://evil.vault.azure.net/secrets/db-owner-password')).toBe(false);
    expect(reads(entry, 'https://kv-agentx-stg-ab12.vault.azure.net/secrets/other')).toBe(false);
    // Any other deploy-time property is refused (M1): never "any host".
    expect(() => partsOf(`[reference('${ID('X/y', 'z')}', 'v').fqdn]`)).toThrow(
      'reference(...).fqdn is not one this tool reads',
    );
  });

  it('holds one resource to one value in every setting, and in one value', () => {
    const bound: Bound = new Map();
    const endpoint = `[format('https://{0}', ${MAIL})]`;
    expect(reads(endpoint, 'https://acs-agentx-stg-ab12.uae.communication.azure.com', bound)).toBe(true);
    const both = `[format('{0},{1}', 'x', format('https://{0}', ${MAIL}))]`;
    expect(reads(both, 'x,https://acs-agentx-stg-ab12.uae.communication.azure.com', bound)).toBe(true);
    expect(reads(both, 'x,https://acs-agentx-stg-ab12.eu.communication.azure.com', bound)).toBe(false);
    const twice = `[format('{0}/{0}', ${ENVIRONMENT})]`;
    expect(reads(twice, 'a.uae.azurecontainerapps.io/a.uae.azurecontainerapps.io')).toBe(true);
    expect(reads(twice, 'a.uae.azurecontainerapps.io/b.uae.azurecontainerapps.io')).toBe(false);
  });

  it("matches the shell's values by their markers, the same wherever each is used", () => {
    const { marker } = SHELL_MARKERS.AGENTX_AZURE_APP_HOST ?? { marker: '' };
    const bound: Bound = new Map();
    expect(reads(`https://${marker}`, 'https://app.example.com', bound)).toBe(true);
    expect(reads(`https://${marker}/x`, 'https://other.example.com/x', bound)).toBe(false);
    expect(reads(`https://${marker}`, 'https://not a host')).toBe(false);
  });

  it('refuses any expression it cannot read, never guessing', () => {
    for (const expression of [
      "[if(true(), 'a', 'b')]",
      "[format('{1}', 'a')]",
      "[format(concat('{0}', 'x'), 'a')]",
      "[parameters('p').x]",
      '[environment().name]',
      "[format('a' 'b')]",
      "[format('a']",
      "[format('a') x]",
      "[format('a')x]",
      '[@]',
      '[(]',
      "[reference('r', 'v').]",
      "[reference(concat('a', 'b'), 'v').clientId]",
      "[uri('https://x/', 'secrets/a')]",
      "[uri(reference('r', 'v').clientId, 'secrets/a')]",
      "[uri(reference('r', 'v').vaultUri, '/secrets/a')]",
      "[uri(reference('r', 'v').vaultUri)]",
    ]) {
      expect(() => partsOf(expression), expression).toThrow();
    }
  });
});

/** A live container as a release reads it: the migration job's, with made-up values. */
const LIVE: LiveContainer = {
  command: ['node', 'apps/migrate/src/main.ts'],
  args: [],
  env: [
    { name: 'AGENTX_ENV', value: 'staging' },
    { name: 'AGENTX_RELEASE', value: 'a'.repeat(40) },
    { name: 'AGENTX_FROM_VAULT', secretRef: 'a-secret' },
  ],
  resources: { cpu: 0.5, memory: '1Gi' },
  volumeMounts: [{ volumeName: 'secrets', mountPath: '/mnt/secrets' }],
};

/** The template's container for LIVE: another build, and its mounts written in Azure's order. */
const TEMPLATE = [
  {
    name: 'migrate',
    image: 'x',
    command: ['node', 'apps/migrate/src/main.ts'],
    args: [],
    env: [
      { name: 'AGENTX_ENV', value: 'staging' },
      { name: 'AGENTX_RELEASE', value: 'b'.repeat(40) },
      { name: 'AGENTX_FROM_VAULT', secretRef: 'a-secret' },
    ],
    resources: { cpu: 0.5, memory: '1Gi' },
    volumeMounts: [{ mountPath: '/mnt/secrets', volumeName: 'secrets' }],
  },
];

const differs = (live: Partial<LiveContainer>, template: unknown = TEMPLATE): string[] =>
  differences(expectedOf(template), { ...LIVE, ...live }, new Map());

describe('how a live container differs from its template', () => {
  it('finds none beyond the image and build', () => {
    expect(differs({})).toEqual([]);
    // An empty argument list is the template's none, as Azure leaves it out.
    const { args: _none, ...withoutArgs } = TEMPLATE[0] ?? {};
    expect(differs({}, [withoutArgs])).toEqual([]);
  });

  it('names each difference, never a value', () => {
    const cases: [Partial<LiveContainer>, string][] = [
      [{ command: ['node', '-e', 'x'] }, 'its command is not the template’s'],
      [{ command: ['node'] }, 'its command is not the template’s'],
      [{ args: ['--x'] }, 'its arguments are not the template’s'],
      [
        { env: [...LIVE.env, { name: 'NODE_OPTIONS', value: 'x' }] },
        "it has a setting the template doesn't: NODE_OPTIONS",
      ],
      [{ env: LIVE.env.slice(1) }, "it lacks the template's setting AGENTX_ENV"],
      [{ env: [...LIVE.env, { name: 'AGENTX_ENV', value: 'staging' }] }, 'it names a setting twice'],
      [
        { env: [{ name: 'AGENTX_ENV', value: 'production' }, ...LIVE.env.slice(1)] },
        'its setting AGENTX_ENV holds another value than the template gives',
      ],
      [
        { env: [{ name: 'AGENTX_ENV', secretRef: 'x' }, ...LIVE.env.slice(1)] },
        'its setting AGENTX_ENV reads a secret where the template gives a value',
      ],
      [
        { env: [...LIVE.env.slice(0, 2), { name: 'AGENTX_FROM_VAULT', value: 'x' }] },
        "its setting AGENTX_FROM_VAULT doesn't read the secret the template names",
      ],
      [
        { env: [...LIVE.env.slice(0, 2), { name: 'AGENTX_FROM_VAULT', secretRef: 'other' }] },
        "its setting AGENTX_FROM_VAULT doesn't read the secret the template names",
      ],
      [{ resources: { cpu: 1, memory: '1Gi' } }, 'its size is not the template’s'],
      [{ resources: { cpu: 0.5, memory: '2Gi' } }, 'its size is not the template’s'],
      [{ volumeMounts: [] }, 'its mounts are not the template’s'],
      [{ volumeMounts: [{ volumeName: 'secrets', mountPath: '/app' }] }, 'its mounts are not the template’s'],
      [{ env: [...LIVE.env, { name: 'A\nB', value: 'x' }] }, "it has a setting the template doesn't: A?B"],
    ];
    for (const [live, said] of cases) expect(differs(live), said).toEqual([said]);
  });

  it("refuses a template it can't read: Bicep gave another shape", () => {
    const [one] = TEMPLATE;
    for (const template of [
      [],
      [one, one],
      ['x'],
      [{ ...one, command: 'node' }],
      [{ ...one, env: [{ value: 'x' }] }],
      [
        {
          ...one,
          env: [
            { name: 'A', value: 'x' },
            { name: 'A', value: 'y' },
          ],
        },
      ],
      [{ ...one, env: [{ name: 'A' }] }],
      [{ ...one, resources: { cpu: '0.5', memory: '1Gi' } }],
      [{ ...one, resources: undefined }],
      [{ ...one, volumeMounts: [{ volumeName: 'secrets' }] }],
    ]) {
      expect(() => expectedOf(template), JSON.stringify(template)).toThrow();
    }
    // No settings and no mounts are none.
    expect(expectedOf([{ ...one, env: undefined, volumeMounts: undefined }]).env.size).toBe(0);
  });
});

describe('the container a template sends (migrate ahead of a hand deploy)', () => {
  it("is the template's, with the image and build given, in the shape a release reads", () => {
    const image = `ghcr.io/shahbaz242630/agent-x@sha256:${'2'.repeat(64)}`;
    expect(deployable('migrate', TEMPLATE, image, 'c'.repeat(40))).toEqual({
      ...LIVE,
      name: 'migrate',
      image,
      env: [LIVE.env[0], { name: 'AGENTX_RELEASE', value: 'c'.repeat(40) }, LIVE.env[2]],
    });
    expect(Object.keys(deployable('migrate', TEMPLATE, image, 'c'.repeat(40)))).toEqual([
      'name',
      'image',
      'command',
      'args',
      'env',
      'resources',
      'volumeMounts',
    ]);
  });

  it('refuses a value only Azure or the shell gives', () => {
    const [one] = TEMPLATE;
    const { marker } = SHELL_MARKERS.AGENTX_AZURE_AUTH_HOST ?? { marker: '' };
    expect(() => deployable('migrate', [{ ...one, command: ['node', marker] }], 'i', 'c')).toThrow(
      "a word of its command is given only at deploy time, so it can't be sent from the template alone",
    );
    expect(() => deployable('migrate', [{ ...one, args: [marker] }], 'i', 'c')).toThrow('an argument is given');
  });
});

describe("staging's apps.bicep, as the pinned Bicep snapshots it", () => {
  it('gives the API and the migration job one container each, which their live shape passes, and a changed one does not', () => {
    const [migrateWorkload = { identity: null, properties: null }, apiWorkload = { identity: null, properties: null }] =
      templatesIn(SUBSCRIPTION, [
        { type: 'Microsoft.App/jobs', name: 'job-agentx-stg-migrate' },
        { type: 'Microsoft.App/containerApps', name: 'ca-agentx-stg-api' },
      ]);
    const migrate = containersOf(migrateWorkload);
    const expectedApi = expectedOf(containersOf(apiWorkload));
    // What Azure and the shell would fill in: each hole a value of its shape, the same everywhere.
    const fill: Readonly<Record<string, string>> = {
      'cae-agentx-staging.defaultDomain': 'ashy-1.uaenorth.azurecontainerapps.io',
      'id-agentx-stg-api.clientId': GUID,
      'AzureManagedDomain.mailFromSenderDomain': `${GUID}.azurecomm.net`,
      'shell AGENTX_AZURE_APP_HOST': 'app.example.com',
      'shell AGENTX_AZURE_AUTH_HOST': 'auth.example.com',
      'shell AGENTX_AZURE_API_OIDC_CLIENT_ID': '338719472394810051',
    };
    const filled = (parts: Readonly<ReturnType<typeof partsOf>>): string =>
      parts
        .map((part) => {
          if ('text' in part) return part.text;
          if (part.key.endsWith('.hostName'))
            return `${part.key.slice(0, -'.hostName'.length)}.uae.communication.azure.com`;
          if (part.key.endsWith('.vaultUri'))
            return `https://${part.key.slice(0, -'.vaultUri'.length)}.vault.azure.net/`;
          const value = fill[part.key];
          if (value === undefined) throw new Error(`no stand-in for ${part.key}`);
          return value;
        })
        .join('');
    const live: LiveContainer = {
      command: expectedApi.command.map(filled),
      args: expectedApi.args.map(filled),
      env: [...expectedApi.env].map(([name, want]) =>
        'secretRef' in want ? { name, secretRef: want.secretRef } : { name, value: filled(want.parts) },
      ),
      resources: expectedApi.resources,
      volumeMounts: expectedApi.volumeMounts,
    };
    // The values only Azure or the shell gives are there to be matched.
    expect(live.env.length).toBeGreaterThan(20);
    expect(
      [...expectedApi.env.values()].some((want) => 'parts' in want && want.parts.some((part) => 'key' in part)),
    ).toBe(true);
    const bound: Bound = new Map();
    expect(differences(expectedApi, live, bound)).toEqual([]);
    expect(differences(expectedOf(migrate), deployable('migrate', migrate, 'i', 'c'), bound)).toEqual([]);
    // The API's own command, and a host the shell gives pointed elsewhere, are each found.
    expect(differences(expectedApi, { ...live, command: ['node', '-e', 'x'] }, new Map())).toEqual([
      'its command is not the template’s',
    ]);
    const issuer = live.env.map((setting) =>
      setting.name === 'AGENTX_EMAIL_ENDPOINT' ? { ...setting, value: 'https://evil.example' } : setting,
    );
    expect(differences(expectedApi, { ...live, env: issuer }, new Map())).toEqual([
      'its setting AGENTX_EMAIL_ENDPOINT holds another value than the template gives',
    ]);
    // Each workload as Azure would give it: its vault entries resolved, its identity's ID in lower case, its nulls.
    const asAzure = (workload: Workload, app = false): Workload => {
      const copy = structuredClone(workload) as {
        identity: { userAssignedIdentities: Record<string, unknown> };
        properties: { configuration: { secrets: { keyVaultUrl: string }[]; registries?: unknown } };
      };
      copy.identity.userAssignedIdentities = Object.fromEntries(
        Object.entries(copy.identity.userAssignedIdentities).map(([id, value]) => [id.toLowerCase(), value]),
      );
      for (const secret of copy.properties.configuration.secrets)
        secret.keyVaultUrl = filled(partsOf(secret.keyVaultUrl));
      copy.properties.configuration.registries = null;
      // Azure gives an app's revisions mode though the template sends none.
      if (app) {
        Object.assign(copy.properties.configuration, { activeRevisionsMode: 'Single' });
      }
      return copy;
    };
    expect(workloadDifferences('jobs', migrateWorkload, asAzure(migrateWorkload), bound)).toEqual([]);
    expect(workloadDifferences('containerApps', apiWorkload, asAzure(apiWorkload, true), bound)).toEqual([]);
    const literal = asAzure(apiWorkload, true) as {
      properties: { configuration: { secrets: Record<string, unknown>[] } };
    };
    const [first] = literal.properties.configuration.secrets;
    if (first !== undefined) first.value = 'x';
    expect(workloadDifferences('containerApps', apiWorkload, literal, new Map())).toEqual([
      `its secret ${String(first?.name)} holds value, not only a vault reference`,
    ]);
  });

  it("refuses a resource apps.bicep doesn't make exactly once", () => {
    expect(() => templatesIn(SUBSCRIPTION, [{ type: 'Microsoft.App/jobs', name: 'job-agentx-stg-none' }])).toThrow(
      'apps.bicep makes 0 of job-agentx-stg-none, not one',
    );
  });
});
