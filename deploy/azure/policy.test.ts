import { appendFileSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import { beforeAll, describe, expect, it } from 'vitest';

import {
  at,
  describeProblem,
  type Expectations,
  kqlStages,
  paramsFileProblems,
  policyProblems,
  PREVIEW_API_EXCEPTIONS,
  type RuleId,
  singleSummaryColumn,
  templateProblems,
} from './policy.ts';
import {
  type BicepRun,
  build,
  environments,
  type EnvironmentSnapshot,
  environmentSnapshot,
  inCopy,
  lint,
  paramsFiles,
  type PredictedResource,
  secureParameters,
  type Snapshot,
  templateOf,
} from './snapshot.ts';

const STAGING: Expectations = { region: 'uaenorth', environment: 'staging' };

/** A Bicep file in deploy/azure, with what the linter says of it and its compiled template. */
interface BicepFile {
  readonly lint: BicepRun;
  readonly template: unknown;
  readonly secure: readonly string[];
}

/** A parameters file, with what the linter says of it and the Bicep file it deploys. */
interface ParamsFile {
  readonly lint: BicepRun;
  readonly text: string;
  readonly deploys: string;
}

let bicepFiles: ReadonlyMap<string, BicepFile>;
let params: ReadonlyMap<string, ParamsFile>;
let deployed: ReadonlyMap<string, EnvironmentSnapshot>;
/** Staging's deployments together, as the policy checks them. */
let staging: Snapshot;

beforeAll(() => {
  inCopy((dir) => {
    bicepFiles = new Map(
      readdirSync(dir)
        .filter((file) => file.endsWith('.bicep'))
        .sort()
        .map((file) => {
          const template = build(dir, file);
          return [file, { lint: lint(dir, file), template, secure: secureParameters(template) }];
        }),
    );
    params = new Map(
      paramsFiles(dir).map((file) => {
        const text = readFileSync(path.join(dir, file), 'utf8');
        return [file, { lint: lint(dir, file), text, deploys: templateOf(text) }];
      }),
    );
    deployed = new Map(environments(dir).map((environment) => [environment, environmentSnapshot(dir, environment)]));
  });
  const found = deployed.get('staging');
  if (found === undefined) throw new Error('deploy/azure has no staging.bicepparam');
  staging = found.together;
});

/** A Bicep file of deploy/azure, or a failure naming it. */
function bicepFile(file: string): BicepFile {
  const found = bicepFiles.get(file);
  if (found === undefined) throw new Error(`deploy/azure has no ${file}`);
  return found;
}

/** One of staging's deployments alone. */
function stagingPart(paramsFile: string): Snapshot {
  const environment = deployed.get('staging');
  const part = paramsFile === 'staging.bicepparam' ? environment?.foundation : environment?.parts.get(paramsFile);
  if (part === undefined) throw new Error(`deploy/azure has no ${paramsFile}`);
  return part;
}

/** Every UAE deployment's region (ADR-009), and the environment its resource group says it is. */
function expectationsOf(snapshotted: Snapshot): Expectations {
  const group = snapshotted.predictedResources.find(
    (resource) => resource.type === 'Microsoft.Resources/resourceGroups',
  );
  const environment = group?.tags?.environment;
  if (environment !== 'staging' && environment !== 'production')
    throw new Error(`unknown environment ${String(environment)}`);
  return { region: 'uaenorth', environment };
}

type Mutable = Record<string, unknown>;

/** A copy of the staging snapshot with one change made to the resources `pick` selects. */
function changed(pick: (resource: PredictedResource) => boolean, change: (resource: Mutable) => void): Snapshot {
  const copy = structuredClone(staging) as unknown as { predictedResources: Mutable[] };
  const picked = copy.predictedResources.filter((resource) => pick(resource as unknown as PredictedResource));
  expect(picked.length).toBeGreaterThan(0);
  for (const resource of picked) change(resource);
  return copy as unknown as Snapshot;
}

/** A copy without the resources `pick` selects. */
const without = (pick: (resource: PredictedResource) => boolean): Snapshot => {
  const kept = staging.predictedResources.filter((resource) => !pick(resource));
  expect(kept.length).toBeLessThan(staging.predictedResources.length);
  return { predictedResources: structuredClone(kept), diagnostics: [] };
};

/** A copy with one more resource. */
const withExtra = (resource: Mutable): Snapshot => ({
  predictedResources: [...structuredClone(staging.predictedResources), resource as unknown as PredictedResource],
  diagnostics: [],
});

const brokenRules = (snapshotted: Snapshot, expected = STAGING): RuleId[] => [
  ...new Set(policyProblems(snapshotted, expected).map((problem) => problem.rule)),
];

/** A nested object of a resource, for changing it in place. */
const inside = (value: unknown, ...keys: readonly string[]): Mutable => at(value, ...keys) as Mutable;
const nth = (value: unknown, index: number): Mutable => (value as readonly Mutable[]).at(index) ?? {};
const first = (value: unknown): Mutable => nth(value, 0);

const type = (wanted: string) => (resource: PredictedResource) => resource.type === wanted;
const named = (pattern: RegExp) => (resource: PredictedResource) => pattern.test(resource.name);
const SERVER = type('Microsoft.DBforPostgreSQL/flexibleServers');
const VAULT = type('Microsoft.KeyVault/vaults');
const WORKSPACE = type('Microsoft.OperationalInsights/workspaces');
const RULES = type('Microsoft.Network/networkSecurityGroups');
const DATABASE_RULES = (resource: PredictedResource) => RULES(resource) && resource.name.endsWith('-database');
const APPS_RULES = (resource: PredictedResource) => RULES(resource) && resource.name.endsWith('-apps');
const NETWORK = type('Microsoft.Network/virtualNetworks');
const ENVIRONMENT = type('Microsoft.App/managedEnvironments');
const IDENTITIES = type('Microsoft.ManagedIdentity/userAssignedIdentities');
const APP_LOGS = named(/^app-logs-to-workspace$/);
const ERRORS_ALERT = named(/-app-errors$/);
const ACTION_GROUP = type('Microsoft.Insights/actionGroups');
const BUDGET = type('Microsoft.Consumption/budgets');
const ALERTS = type('Microsoft.Insights/scheduledQueryRules');
const LOGIN_ALERT = named(/-privileged-login$/);
const CAP_ALERT = named(/-log-cap-reached$/);
const QUOTA_ALERT = named(/-log-quota$/);
const setting = (name: string) => (resource: PredictedResource) => resource.name.endsWith(`/${name}`);
const SECRETS = type('Microsoft.KeyVault/vaults/secrets');
const SECRET = (name: string) => (resource: PredictedResource) =>
  SECRETS(resource) && resource.id.endsWith(`/secrets/${name}`);
const ASSIGNMENTS = type('Microsoft.Authorization/roleAssignments');
/** The role assignment that lets `who` read `what`, by the description secrets.bicep gives it. */
const READS = (who: string, what: string) => (resource: PredictedResource) =>
  ASSIGNMENTS(resource) &&
  at(resource.properties, 'description') === `${who} reads ${what} (deploy/azure/secrets.bicep)`;
const JOBS = type('Microsoft.App/jobs');
/** One job, by the work it does. */
const JOB = (workload: string) => named(new RegExp(`^job-agentx-[a-z]+-${workload}$`));
const APPS = type('Microsoft.App/containerApps');
/** One app, by the work it does. */
const APP = (workload: string) => named(new RegExp(`^ca-agentx-[a-z]+-${workload}$`));
const ingressOf = (app: Mutable): Mutable => inside(app, 'properties', 'configuration', 'ingress');
const scaleOf = (app: Mutable): Mutable => inside(app, 'properties', 'template', 'scale');
const configurationOf = (job: Mutable): Mutable => inside(job, 'properties', 'configuration');
const declaredSecrets = (job: Mutable): Mutable[] => at(configurationOf(job), 'secrets') as Mutable[];
const containerOf = (job: Mutable): Mutable => first(at(job, 'properties', 'template', 'containers'));
const settingsOf = (job: Mutable): Mutable[] => at(containerOf(job), 'env') as Mutable[];
/** One secret a job is given, by its name. */
const secretNamed = (job: Mutable, name: string): Mutable =>
  declaredSecrets(job).find((secret) => secret.name === name) ?? {};
const criterion = (alert: Mutable): Mutable => first(at(alert, 'properties', 'criteria', 'allOf'));
const rules = (group: Mutable): Mutable[] => at(group, 'properties', 'securityRules') as Mutable[];
/** One rule of a group, by name, for changing it in place. */
const ruleNamed = (group: Mutable, name: string): Mutable =>
  inside(rules(group).find((rule) => rule.name === name) ?? {}, 'properties');
/** The same group without one of its rules. */
const dropRule = (group: Mutable, name: string): void => {
  inside(group, 'properties').securityRules = rules(group).filter((rule) => rule.name !== name);
};
const subnet = (network: Mutable, name: string): Mutable =>
  (at(network, 'properties', 'subnets') as Mutable[]).find((entry) => entry.name === name) ?? {};

/** An allow rule declared as a resource of its own under the rules group `pick` selects. */
function separateRule(
  pick: (resource: PredictedResource) => boolean,
  direction: 'Inbound' | 'Outbound',
  source: string,
  destination: string,
  port: string,
): Mutable {
  const group = staging.predictedResources.find(pick);
  return {
    id: `${String(group?.id)}/securityRules/allow-extra`,
    type: 'Microsoft.Network/networkSecurityGroups/securityRules',
    name: `${String(group?.name)}/allow-extra`,
    apiVersion: '2025-01-01',
    properties: {
      priority: 120,
      direction,
      access: 'Allow',
      protocol: 'Tcp',
      sourceAddressPrefix: source,
      sourcePortRange: '*',
      destinationAddressPrefix: destination,
      destinationPortRange: port,
    },
  };
}

describe('SEC-OPS-09, SEC-OPS-11 deploy/azure', () => {
  it('has staging, its foundation and its secrets, and every file lints clean with every linter rule an error', () => {
    expect([...deployed.keys()]).toEqual(['staging']);
    expect([...params.keys()]).toEqual(['staging.apps.bicepparam', 'staging.bicepparam', 'staging.secrets.bicepparam']);
    expect([...params.values()].map((entry) => entry.deploys)).toEqual(['apps.bicep', 'main.bicep', 'secrets.bicep']);
    expect([...bicepFiles.keys()]).toEqual(['apps.bicep', 'main.bicep', 'names.bicep', 'secrets.bicep']);
    for (const [file, { lint: run }] of [...bicepFiles, ...params])
      expect({ file, ...run }).toEqual({ file, status: 0, output: '', stdout: '' });
  });

  it('breaks no rule in any environment, and no file writes down a secret', () => {
    expect(bicepFile('main.bicep').secure).toEqual(['postgresAdminPassword']);
    expect(bicepFile('secrets.bicep').secure).toEqual([
      'postgresAdminPassword',
      'dbOwnerPassword',
      'dbAppPassword',
      'dbBackupPassword',
      'dbZitadelPassword',
      'zitadelMasterKey',
      'zitadelAdminPassword',
      'loginClientPrivateKey',
      'loginClientPublicKey',
    ]);
    for (const [environment, { together }] of deployed) {
      expect({
        environment,
        problems: policyProblems(together, expectationsOf(together)).map(describeProblem),
      }).toEqual({ environment, problems: [] });
    }
    for (const [file, entry] of params) {
      expect(paramsFileProblems(file, entry.text, bicepFile(entry.deploys).secure)).toEqual([]);
    }
    for (const [file, { template }] of bicepFiles) expect(templateProblems(file, template)).toEqual([]);
  });

  it('applies bicepconfig.json: a secret in an output is an error, not a warning', () => {
    inCopy((dir) => {
      appendFileSync(path.join(dir, 'main.bicep'), '\noutput leaked string = postgresAdminPassword\n');
      const run = lint(dir, 'main.bicep');
      expect(run.status).not.toBe(0);
      expect(run.output).toMatch(/Error outputs-should-not-contain-secrets/);
    });
  });

  it('applies bicepconfig.json: a region written into a module is an error', () => {
    inCopy((dir) => {
      const file = path.join(dir, 'modules', 'keyvault.bicep');
      writeFileSync(file, readFileSync(file, 'utf8').replace('location: location', "location: 'westeurope'"));
      const run = lint(dir, 'main.bicep');
      expect(run.status).not.toBe(0);
      expect(run.output).toMatch(/Error no-hardcoded-location/);
    });
  });

  it('creates the foundation, and only it', () => {
    expect(
      stagingPart('staging.bicepparam').predictedResources.map((resource) => `${resource.type} ${resource.name}`),
    ).toEqual([
      'Microsoft.Resources/resourceGroups rg-agentx-staging',
      'Microsoft.OperationalInsights/workspaces log-agentx-stg',
      'Microsoft.Insights/actionGroups ag-agentx-stg',
      'Microsoft.Insights/scheduledQueryRules alert-agentx-stg-log-quota',
      'Microsoft.Insights/scheduledQueryRules alert-agentx-stg-log-cap-reached',
      'Microsoft.Insights/diagnosticSettings activity-log-to-workspace',
      'Microsoft.Consumption/budgets budget-agentx-staging',
      'Microsoft.Network/networkSecurityGroups nsg-agentx-staging-apps',
      'Microsoft.Network/networkSecurityGroups nsg-agentx-staging-database',
      'Microsoft.Network/virtualNetworks vnet-agentx-staging',
      'Microsoft.Network/privateDnsZones agentx-staging.private.postgres.database.azure.com',
      'Microsoft.Network/privateDnsZones/virtualNetworkLinks agentx-staging.private.postgres.database.azure.com/vnet-agentx-staging',
      expect.stringMatching(/^Microsoft\.KeyVault\/vaults kv-agentx-stg-[a-z0-9]{6}$/),
      'Microsoft.Insights/diagnosticSettings audit-to-workspace',
      expect.stringMatching(/^Microsoft\.DBforPostgreSQL\/flexibleServers psql-agentx-stg-[a-z0-9]{6}$/),
      expect.stringMatching(/\/configurations psql-agentx-stg-[a-z0-9]{6}\/require_secure_transport$/),
      expect.stringMatching(/\/configurations psql-agentx-stg-[a-z0-9]{6}\/ssl_min_protocol_version$/),
      expect.stringMatching(/\/configurations psql-agentx-stg-[a-z0-9]{6}\/log_connections$/),
      'Microsoft.Insights/diagnosticSettings logs-to-workspace',
      expect.stringMatching(
        /^Microsoft\.Insights\/scheduledQueryRules alert-psql-agentx-stg-[a-z0-9]{6}-privileged-login$/,
      ),
      'Microsoft.App/managedEnvironments cae-agentx-staging',
      'Microsoft.Insights/diagnosticSettings app-logs-to-workspace',
      ...['api', 'zitadel', 'login', 'db-setup', 'migrate', 'zitadel-init', 'zitadel-setup'].map(
        (workload) => `Microsoft.ManagedIdentity/userAssignedIdentities id-agentx-stg-${workload}`,
      ),
      'Microsoft.OperationalInsights/workspaces/savedSearches log-agentx-stg/agentx-errors-by-type',
      'Microsoft.Insights/scheduledQueryRules alert-agentx-stg-app-errors',
    ]);
  });

  it('writes the secrets, each only when given but the master key, and lets each app and job read its own', () => {
    const part = stagingPart('staging.secrets.bicepparam').predictedResources;
    const label = (resource: PredictedResource): string =>
      SECRETS(resource)
        ? `${resource.id.slice(resource.id.lastIndexOf('/') + 1)} ${resource.condition ?? 'once'}`
        : String(at(resource.properties, 'description'));
    const givenOnly = (parameter: string): string => `[not(empty(parameters('${parameter}')))]`;
    expect(part.map(label)).toEqual([
      `db-admin-password ${givenOnly('postgresAdminPassword')}`,
      `db-owner-password ${givenOnly('dbOwnerPassword')}`,
      `db-app-password ${givenOnly('dbAppPassword')}`,
      `db-backup-password ${givenOnly('dbBackupPassword')}`,
      `db-zitadel-password ${givenOnly('dbZitadelPassword')}`,
      `zitadel-admin-password ${givenOnly('zitadelAdminPassword')}`,
      `login-client-private-key ${givenOnly('loginClientPrivateKey')}`,
      `login-client-public-key ${givenOnly('loginClientPublicKey')}`,
      'zitadel-masterkey once',
      ...[
        'db-setup reads db-admin-password',
        'db-setup reads db-owner-password',
        'migrate reads db-owner-password',
        'db-setup reads db-app-password',
        'api reads db-app-password',
        'db-setup reads db-backup-password',
        'db-setup reads db-zitadel-password',
        'zitadel-init reads db-zitadel-password',
        'zitadel-setup reads db-zitadel-password',
        'zitadel reads db-zitadel-password',
        'zitadel-setup reads zitadel-admin-password',
        'login reads login-client-private-key',
        'zitadel reads login-client-public-key',
        'zitadel-setup reads zitadel-masterkey',
        'zitadel reads zitadel-masterkey',
      ].map((grant) => `${grant} (deploy/azure/secrets.bicep)`),
    ]);
  });

  it('compiles a rotation run, one secret given and every other empty, and refuses one without a master key', () => {
    const text = params.get('staging.secrets.bicepparam')?.text ?? '';
    const variables = [...text.matchAll(/readEnvironmentVariable\('([A-Z0-9_]+)'\)/g)].map((match) => match[1] ?? '');
    expect(variables).toHaveLength(9);
    // The API's login given; every other secret set but empty, so left as the vault has it; the master key a
    // fresh 32 characters, which Azure leaves alone once one exists. Empty values reach Bicep from Node, as G3's tool sends them.
    const kept = Object.fromEntries(
      variables
        .filter((name) => !['AGENTX_AZURE_DB_APP_PASSWORD', 'AGENTX_AZURE_ZITADEL_MASTERKEY'].includes(name))
        .map((name) => [name, '']),
    );
    inCopy((dir) => {
      const rotation = environmentSnapshot(dir, 'staging', kept).together;
      expect(policyProblems(rotation, STAGING).map(describeProblem)).toEqual([]);
      expect(rotation.predictedResources.filter(SECRETS)).toHaveLength(9);
      // A master key must come every run, even though only the first is kept: an empty one stops the run before Azure.
      expect(() => environmentSnapshot(dir, 'staging', { ...kept, AGENTX_AZURE_ZITADEL_MASTERKEY: '' })).toThrow(
        /minimum allowable length is 32/,
      );
    });
  });

  it('resolves every reference between modules to a resource it creates', () => {
    const server = staging.predictedResources.find(SERVER);
    const network = staging.predictedResources.find(NETWORK);
    expect(at(server?.properties, 'network', 'delegatedSubnetResourceId')).toBe(
      `${String(network?.id)}/subnets/database`,
    );
    expect(
      at(staging.predictedResources.find(ENVIRONMENT)?.properties, 'vnetConfiguration', 'infrastructureSubnetId'),
    ).toBe(`${String(network?.id)}/subnets/apps`);
    expect(
      at(
        (at(network?.properties, 'subnets') as Mutable[]).find((entry) => entry.name === 'apps'),
        'properties',
        'networkSecurityGroup',
        'id',
      ),
    ).toBe(staging.predictedResources.find(APPS_RULES)?.id);
    expect(at(server?.properties, 'administratorLoginPassword')).toBe("[parameters('postgresAdminPassword')]");
    // The secrets deployment's too: the vault and the identities the foundation creates.
    const vault = staging.predictedResources.find(VAULT);
    const apiReads = staging.predictedResources.find(READS('api', 'db-app-password'));
    const api = staging.predictedResources.find(named(/^id-agentx-stg-api$/));
    expect(apiReads?.id).toBe(
      `${String(vault?.id)}/secrets/db-app-password/providers/Microsoft.Authorization/roleAssignments/${String(apiReads?.name)}`,
    );
    expect(at(apiReads?.properties, 'principalId')).toBe(`[reference('${String(api?.id)}', '2024-11-30').principalId]`);
    expect(at(staging.predictedResources.find(SECRET('db-app-password'))?.properties, 'value')).toBe(
      "[parameters('dbAppPassword')]",
    );
    expect(staging.diagnostics).toEqual([]);
  });
});

describe('SEC-OPS-09 each rule can fail', () => {
  it('snapshot-complete: Bicep reporting what it could not work out', () => {
    expect(brokenRules({ ...staging, diagnostics: [{ level: 'Warning', message: 'skipped' }] })).toEqual([
      'snapshot-complete',
    ]);
  });

  it('required: a protection that is missing, not only switched off', () => {
    // The secrets the vault held are left in no vault of this deployment.
    // Without the vault, the secrets are in no vault of this deployment and no
    // job can be shown to read its own from one.
    expect(brokenRules(without((resource) => VAULT(resource) || named(/^audit-to-workspace$/)(resource)))).toEqual([
      'required',
      'vault-secrets',
      'workload-secrets',
    ]);
    expect(
      brokenRules(
        without(
          (resource) =>
            resource.type.startsWith('Microsoft.DBforPostgreSQL') || /psql|^logs-to-workspace$/.test(resource.name),
        ),
      ),
    ).toEqual(['required']);
    expect(brokenRules(without((resource) => NETWORK(resource) || RULES(resource)))).toContain('required');
    expect(brokenRules(without(WORKSPACE))).toContain('required');
    expect(brokenRules(without(ACTION_GROUP))).toContain('required');
    const workspace = staging.predictedResources.find(WORKSPACE);
    // A second workspace also has no quota alerts of its own.
    expect(brokenRules(withExtra({ ...structuredClone(workspace), id: `${String(workspace?.id)}-second` }))).toContain(
      'required',
    );
    // Without the environment there is nowhere of ours for the jobs to run.
    expect(brokenRules(without((resource) => ENVIRONMENT(resource) || APP_LOGS(resource)))).toEqual([
      'required',
      'jobs',
      'apps',
    ]);
    const environment = staging.predictedResources.find(ENVIRONMENT);
    // A second environment also sends no logs of its own.
    expect(
      brokenRules(withExtra({ ...structuredClone(environment), id: `${String(environment?.id)}-second` })),
    ).toContain('required');
  });

  it('in-country: a resource outside the region, or a global-only type pinned to one', () => {
    expect(brokenRules(changed(VAULT, (vault) => (vault.location = 'westeurope')))).toEqual(['in-country']);
    expect(brokenRules(changed(ACTION_GROUP, (group) => (group.location = 'uaenorth')))).toEqual(['in-country']);
    expect(brokenRules(staging, { region: 'westeurope', environment: 'staging' })).toEqual(['in-country']);
  });

  it('stable-api: a preview API version, unless its type is an exception with a reason', () => {
    expect(brokenRules(changed(VAULT, (vault) => (vault.apiVersion = '2025-05-01-preview')))).toEqual(['stable-api']);
    expect(Object.keys(PREVIEW_API_EXCEPTIONS)).toEqual(['Microsoft.Insights/diagnosticSettings']);
  });

  it('tags: a resource without its product, environment or managed-by tag', () => {
    expect(brokenRules(changed(WORKSPACE, (workspace) => delete workspace.tags))).toEqual(['tags']);
    expect(brokenRules(changed(VAULT, (vault) => (inside(vault, 'tags')['managed-by'] = 'the portal')))).toEqual([
      'tags',
    ]);
  });

  it('no-secret-literals: a password, a vault secret or an app secret written into the code', () => {
    const literal = 'written in the code';
    expect(
      brokenRules(changed(SERVER, (server) => (inside(server, 'properties').administratorLoginPassword = literal))),
    ).toEqual(['no-secret-literals']);
    expect(
      brokenRules(changed(SERVER, (server) => (inside(server, 'properties', 'network').adminPassword = literal))),
    ).toEqual(['no-secret-literals']);
    expect(
      brokenRules(changed(SECRET('db-app-password'), (secret) => (inside(secret, 'properties').value = literal))),
    ).toEqual(['no-secret-literals']);
    // An app's own secret, carrying a value rather than reading one: two rules
    // catch it, this one on any resource and workload-secrets on what an app
    // may hold.
    expect(
      brokenRules(changed(APP('api'), (app) => (first(at(configurationOf(app), 'secrets')).value = literal))),
    ).toEqual(['no-secret-literals', 'workload-secrets']);
  });

  it('no-secret-literals in a parameters file: a secure value written down, or given a default', () => {
    for (const [file, parameter, variable] of [
      ['staging.bicepparam', 'postgresAdminPassword', 'AGENTX_AZURE_POSTGRES_ADMIN_PASSWORD'],
      ['staging.secrets.bicepparam', 'zitadelMasterKey', 'AGENTX_AZURE_ZITADEL_MASTERKEY'],
    ] as const) {
      const entry = params.get(file);
      const assignment = new RegExp(`^param ${parameter} = .+$`, 'm');
      expect(entry?.text).toMatch(assignment);
      for (const written of ["'written in the code'", `readEnvironmentVariable('${variable}', 'a default')`]) {
        const problems = paramsFileProblems(
          file,
          String(entry?.text).replace(assignment, `param ${parameter} = ${written}`),
          bicepFile(String(entry?.deploys)).secure,
        );
        expect(problems.map((problem) => problem.rule)).toEqual(['no-secret-literals']);
      }
    }
  });

  it('database-private: public access, another subnet or zone, an empty one, or another major version', () => {
    const network = (server: Mutable): Mutable => inside(server, 'properties', 'network');
    for (const change of [
      (server: Mutable) => (network(server).publicNetworkAccess = 'Enabled'),
      (server: Mutable) => delete network(server).delegatedSubnetResourceId,
      (server: Mutable) => (network(server).delegatedSubnetResourceId = ''),
      (server: Mutable) =>
        (network(server).delegatedSubnetResourceId = `${String(network(server).delegatedSubnetResourceId)}2`),
      (server: Mutable) => delete network(server).privateDnsZoneArmResourceId,
      (server: Mutable) => (network(server).privateDnsZoneArmResourceId = ''),
      (server: Mutable) => (inside(server, 'properties').version = '17'),
    ]) {
      expect(brokenRules(changed(SERVER, change))).toEqual(['database-private']);
    }
    expect(brokenRules(without(type('Microsoft.Network/privateDnsZones/virtualNetworkLinks')))).toEqual([
      'database-private',
    ]);
    // A link kept while its zone isn't one this deployment creates, or a link to another network.
    expect(brokenRules(without(type('Microsoft.Network/privateDnsZones')))).toEqual(['database-private']);
    expect(
      brokenRules(
        changed(
          type('Microsoft.Network/privateDnsZones/virtualNetworkLinks'),
          (link) => (inside(link, 'properties', 'virtualNetwork').id = '/subscriptions/x/virtualNetworks/other'),
        ),
      ),
    ).toEqual(['database-private']);
  });

  it('database-logins: Entra logins, password logins off, logins unlogged, or no stateless alert on them', () => {
    expect(
      brokenRules(
        changed(SERVER, (server) => (inside(server, 'properties', 'authConfig').activeDirectoryAuth = 'Enabled')),
      ),
    ).toEqual(['database-logins']);
    expect(
      brokenRules(changed(SERVER, (server) => (inside(server, 'properties', 'authConfig').passwordAuth = 'Disabled'))),
    ).toEqual(['database-logins']);
    expect(
      brokenRules(changed(setting('log_connections'), (entry) => (inside(entry, 'properties').value = 'off'))),
    ).toEqual(['database-logins']);
    expect(brokenRules(without(LOGIN_ALERT))).toEqual(['database-logins']);
    expect(
      brokenRules(
        changed(
          LOGIN_ALERT,
          (alert) => (criterion(alert).query = String(criterion(alert).query).replace('agentx_backup', 'agentx_app')),
        ),
      ),
    ).toEqual(['database-logins']);
    expect(brokenRules(changed(LOGIN_ALERT, (alert) => (inside(alert, 'properties').severity = 2)))).toEqual(
      expect.arrayContaining(['database-logins']),
    );
    expect(brokenRules(changed(LOGIN_ALERT, (alert) => (inside(alert, 'properties').autoMitigate = true)))).toEqual([
      'database-logins',
      'alert-delivery',
    ]);
    expect(brokenRules(changed(LOGIN_ALERT, (alert) => (inside(alert, 'properties').enabled = false)))).toEqual([
      'database-logins',
      'alert-delivery',
    ]);
    expect(
      brokenRules(
        changed(LOGIN_ALERT, (alert) => (inside(alert, 'properties').scopes = ['/subscriptions/x/workspaces/y'])),
      ),
    ).toEqual(['database-logins']);
  });

  it('database-tls: TLS not required, or older than 1.3', () => {
    expect(
      brokenRules(changed(setting('require_secure_transport'), (entry) => (inside(entry, 'properties').value = 'off'))),
    ).toEqual(['database-tls']);
    expect(
      brokenRules(
        changed(setting('ssl_min_protocol_version'), (entry) => (inside(entry, 'properties').value = 'TLSv1.2')),
      ),
    ).toEqual(['database-tls']);
  });

  it('database-backup: under 7 days, or under 35 in production', () => {
    expect(
      brokenRules(changed(SERVER, (server) => (inside(server, 'properties', 'backup').backupRetentionDays = 5))),
    ).toEqual(['database-backup']);
    const production = changed(
      (resource) => resource.tags !== undefined,
      (resource) => (inside(resource, 'tags').environment = 'production'),
    );
    expect(brokenRules(production, { region: 'uaenorth', environment: 'production' })).toEqual(['database-backup']);
  });

  it('database-network: any door wider than 5432 from the apps and the subnet itself, or a Postgres subnet without its rules', () => {
    const allowApps = (group: Mutable): Mutable => ruleNamed(group, 'allow-postgres-from-apps');
    const allowItself = (group: Mutable): Mutable => ruleNamed(group, 'allow-postgres-within-subnet');
    const deny = (group: Mutable): Mutable => ruleNamed(group, 'deny-rest-of-network');
    for (const change of [
      (group: Mutable) => (allowApps(group).sourceAddressPrefix = '10.40.0.0/16'),
      (group: Mutable) => (allowApps(group).destinationPortRange = '*'),
      (group: Mutable) => (allowApps(group).protocol = '*'),
      (group: Mutable) => (allowApps(group).destinationAddressPrefix = '*'),
      (group: Mutable) => (allowItself(group).sourceAddressPrefix = '10.40.9.0/24'),
      (group: Mutable) => {
        dropRule(group, 'allow-postgres-from-apps');
      },
      (group: Mutable) => {
        dropRule(group, 'allow-postgres-within-subnet');
      },
      (group: Mutable) => {
        dropRule(group, 'deny-rest-of-network');
      },
      (group: Mutable) => (deny(group).protocol = 'Tcp'),
      (group: Mutable) => (deny(group).sourceAddressPrefix = '10.99.0.0/24'),
      (group: Mutable) => (deny(group).destinationAddressPrefix = '10.99.0.0/24'),
      (group: Mutable) => (deny(group).destinationPortRange = '22'),
      (group: Mutable) => (deny(group).priority = 105),
      (group: Mutable) => (deny(group).access = 'Allow'),
      // A third door, from a source that is neither the apps subnet nor the database's own.
      (group: Mutable) => {
        const extra = structuredClone(nth(rules(group), 0));
        extra.name = 'allow-postgres-from-elsewhere';
        inside(extra, 'properties').sourceAddressPrefix = '10.40.9.0/24';
        inside(extra, 'properties').priority = 120;
        rules(group).push(extra);
      },
    ]) {
      expect(brokenRules(changed(DATABASE_RULES, change))).toEqual(['database-network']);
    }
    // The same door as a rule of its own under the group: Azure adds it all the same.
    expect(brokenRules(withExtra(separateRule(DATABASE_RULES, 'Inbound', '10.40.9.0/24', '*', '5432')))).toEqual([
      'database-network',
    ]);
    for (const change of [
      (network: Mutable) => delete inside(subnet(network, 'apps'), 'properties').delegations,
      (network: Mutable) => delete inside(subnet(network, 'database'), 'properties').serviceEndpoints,
      (network: Mutable) => {
        const second = structuredClone(subnet(network, 'database'));
        second.name = 'database2';
        inside(second, 'properties').addressPrefix = '10.40.2.0/24';
        delete inside(second, 'properties').networkSecurityGroup;
        (at(network, 'properties', 'subnets') as Mutable[]).push(second);
      },
    ]) {
      expect(brokenRules(changed(NETWORK, change))).toEqual(['database-network']);
    }
    expect(
      brokenRules(changed(NETWORK, (network) => delete inside(subnet(network, 'database'), 'properties').delegations)),
    ).toEqual(expect.arrayContaining(['database-network', 'database-private']));
  });

  it('vault: access policies, no purge protection, or any other way in', () => {
    const properties = (vault: Mutable): Mutable => inside(vault, 'properties');
    const acls = (vault: Mutable): Mutable => inside(vault, 'properties', 'networkAcls');
    const appsRule = (vault: Mutable): Mutable => first(acls(vault).virtualNetworkRules);
    for (const change of [
      (vault: Mutable) => (properties(vault).enableRbacAuthorization = false),
      (vault: Mutable) => (properties(vault).accessPolicies = [{ objectId: 'someone' }]),
      (vault: Mutable) => (properties(vault).enablePurgeProtection = false),
      (vault: Mutable) => (properties(vault).softDeleteRetentionInDays = 7),
      (vault: Mutable) => (properties(vault).enabledForTemplateDeployment = true),
      (vault: Mutable) => (acls(vault).defaultAction = 'Allow'),
      (vault: Mutable) => (acls(vault).bypass = 'AzureServices'),
      (vault: Mutable) => (acls(vault).ipRules = [{ value: '203.0.113.7' }]),
      (vault: Mutable) =>
        (acls(vault).virtualNetworkRules = [appsRule(vault), { id: '/subscriptions/x/any/subnets/other' }]),
      (vault: Mutable) => (appsRule(vault).id = '/subscriptions/x/any/subnets/other'),
      (vault: Mutable) => (acls(vault).virtualNetworkRules = []),
    ]) {
      expect(brokenRules(changed(VAULT, change))).toEqual(['vault']);
    }
  });

  it('workspace: another retention, shared keys, or no cap', () => {
    const properties = (workspace: Mutable): Mutable => inside(workspace, 'properties');
    expect(brokenRules(changed(WORKSPACE, (workspace) => (properties(workspace).retentionInDays = 90)))).toEqual([
      'workspace',
    ]);
    expect(
      brokenRules(
        changed(WORKSPACE, (workspace) => (inside(workspace, 'properties', 'features').disableLocalAuth = false)),
      ),
    ).toEqual(['workspace']);
    expect(brokenRules(changed(WORKSPACE, (workspace) => delete properties(workspace).workspaceCapping))).toEqual([
      'workspace',
    ]);
    expect(
      brokenRules(
        changed(WORKSPACE, (workspace) => (inside(workspace, 'properties', 'workspaceCapping').dailyQuotaGb = 0)),
      ),
    ).toEqual(['workspace']);
  });

  it('SEC-AV-09 log-quota-alerts: the 80% alert off its threshold or its query, or the cap alert inverted or gone', () => {
    expect(
      brokenRules(
        changed(WORKSPACE, (workspace) => (inside(workspace, 'properties', 'workspaceCapping').dailyQuotaGb = 2)),
      ),
    ).toEqual(['log-quota-alerts']);
    expect(brokenRules(without(CAP_ALERT))).toEqual(['log-quota-alerts']);
    for (const [pick, query] of [
      [QUOTA_ALERT, 'Usage | summarize IngestedMb = sum(Quantity)'],
      [QUOTA_ALERT, 'AzureDiagnostics | where IsBillable | summarize IngestedMb = sum(Quantity)'],
      [
        CAP_ALERT,
        '_LogOperation | where Category =~ "Ingestion" | where Detail !contains "OverQuota" | summarize Events = count()',
      ],
      [CAP_ALERT, '_LogOperation | where Detail contains "OverQuota" | summarize Events = count()'],
      [QUOTA_ALERT, 'Usage | where IsBillable | where Quantity < 0 | summarize IngestedMb = sum(Quantity)'],
      [QUOTA_ALERT, 'Usage | where IsBillable | summarize IngestedMb = count()'],
    ] as const) {
      expect(brokenRules(changed(pick, (alert) => (criterion(alert).query = query)))).toEqual(['log-quota-alerts']);
    }
    expect(brokenRules(changed(QUOTA_ALERT, (alert) => (criterion(alert).operator = 'LessThan')))).toEqual([
      'log-quota-alerts',
    ]);
    expect(brokenRules(changed(CAP_ALERT, (alert) => (criterion(alert).threshold = 5)))).toEqual(['log-quota-alerts']);
    expect(brokenRules(changed(CAP_ALERT, (alert) => (criterion(alert).operator = 'LessThan')))).toEqual([
      'log-quota-alerts',
    ]);
  });

  it('alert-counts-only: rows, groups, dimensions or custom properties in an alert', () => {
    const query = (text: string) => (alert: Mutable) => (criterion(alert).query = text);
    for (const change of [
      query(
        'PGSQLServerLogs | where Message has "connection authorized" | summarize Logins = count() by LogicalServerName',
      ),
      query('PGSQLServerLogs | where Message has "connection authorized" | project Message'),
      query('PGSQLServerLogs | summarize Logins = count(), Last = max(TimeGenerated)'),
      query('PGSQLServerLogs | summarize count()'),
      (alert: Mutable) => (criterion(alert).metricMeasureColumn = 'Message'),
      (alert: Mutable) =>
        (criterion(alert).dimensions = [{ name: 'LogicalServerName', operator: 'Include', values: ['*'] }]),
      (alert: Mutable) => (criterion(alert).resourceIdColumn = '_ResourceId'),
      (alert: Mutable) => (inside(alert, 'properties', 'actions').customProperties = { server: 'name' }),
      (alert: Mutable) => (alert.kind = 'SimpleLogAlert'),
      (alert: Mutable) => (inside(alert, 'properties', 'criteria').allOf = []),
    ]) {
      // The login alert's own rule refuses a changed query too; this rule is the one under test.
      expect(brokenRules(changed(LOGIN_ALERT, change))).toContain('alert-counts-only');
    }
    expect(
      brokenRules(changed(CAP_ALERT, (alert) => (inside(alert, 'properties', 'actions').customProperties = null))),
    ).toEqual([]);
  });

  it("alert-runbook: no runbook, or a SEV its severity doesn't match", () => {
    const properties = (alert: Mutable): Mutable => inside(alert, 'properties');
    expect(brokenRules(changed(CAP_ALERT, (alert) => (properties(alert).description = 'Something happened.')))).toEqual(
      ['alert-runbook'],
    );
    expect(brokenRules(changed(CAP_ALERT, (alert) => (properties(alert).severity = 3)))).toEqual(['alert-runbook']);
  });

  it('alert-delivery: an alert switched off, sent nowhere, or to a group that is off or tells nobody', () => {
    const properties = (entry: Mutable): Mutable => inside(entry, 'properties');
    expect(brokenRules(changed(CAP_ALERT, (alert) => (properties(alert).enabled = false)))).toEqual(
      expect.arrayContaining(['alert-delivery', 'log-quota-alerts']),
    );
    expect(brokenRules(changed(ALERTS, (alert) => (properties(alert).enabled = false)))).toContain('alert-delivery');
    expect(
      brokenRules(changed(CAP_ALERT, (alert) => (inside(alert, 'properties', 'actions').actionGroups = []))),
    ).toEqual(['alert-delivery']);
    expect(
      brokenRules(
        changed(
          CAP_ALERT,
          (alert) => (inside(alert, 'properties', 'actions').actionGroups = ['/subscriptions/x/elsewhere']),
        ),
      ),
    ).toEqual(['alert-delivery']);
    expect(brokenRules(changed(ACTION_GROUP, (group) => (properties(group).enabled = false)))).toEqual([
      'alert-delivery',
    ]);
    expect(
      brokenRules(
        changed(ACTION_GROUP, (group) => {
          properties(group).emailReceivers = [];
          properties(group).azureAppPushReceivers = [];
        }),
      ),
    ).toEqual(['alert-delivery']);
  });

  it("resource-logs: a vault or server whose logs stay out of this deployment's workspace", () => {
    const elsewhere = '/subscriptions/x/resourceGroups/y/providers/Microsoft.OperationalInsights/workspaces/elsewhere';
    expect(brokenRules(without(named(/^audit-to-workspace$/)))).toEqual(['resource-logs']);
    for (const change of [
      (entry: Mutable) => (inside(entry, 'properties').logAnalyticsDestinationType = 'AzureDiagnostics'),
      (entry: Mutable) => (first(at(entry, 'properties', 'logs')).enabled = false),
      (entry: Mutable) => (first(at(entry, 'properties', 'logs')).category = 'PostgreSQLFlexSessions'),
    ]) {
      expect(brokenRules(changed(named(/^logs-to-workspace$/), change))).toEqual(['resource-logs']);
    }
    expect(
      brokenRules(
        changed(named(/^logs-to-workspace$/), (entry) => (inside(entry, 'properties').workspaceId = elsewhere)),
      ),
    ).toEqual(['resource-logs', 'log-destinations']);
  });

  it('SEC-DATA-09 log-destinations: a diagnostic setting that also sends to a storage account, an event hub or a partner', () => {
    const AUDIT = named(/^audit-to-workspace$/);
    for (const [key, value] of [
      ['storageAccountId', '/subscriptions/x/resourceGroups/y/providers/Microsoft.Storage/storageAccounts/abroad'],
      [
        'eventHubAuthorizationRuleId',
        '/subscriptions/x/resourceGroups/y/providers/Microsoft.EventHub/namespaces/n/authorizationRules/r',
      ],
      ['eventHubName', 'hub'],
      ['marketplacePartnerId', '/subscriptions/x/resourceGroups/y/providers/Microsoft.Datadog/monitors/m'],
      [
        'serviceBusRuleId',
        '/subscriptions/x/resourceGroups/y/providers/Microsoft.ServiceBus/namespaces/n/authorizationRules/r',
      ],
    ] as const) {
      expect(brokenRules(changed(AUDIT, (entry) => (inside(entry, 'properties')[key] = value)))).toEqual([
        'log-destinations',
      ]);
    }
    // Empty, it sends nowhere.
    expect(brokenRules(changed(AUDIT, (entry) => (inside(entry, 'properties').storageAccountId = '')))).toEqual([]);
    expect(brokenRules(changed(AUDIT, (entry) => (inside(entry, 'properties').storageAccountId = null)))).toEqual([]);
    // A second setting on the server sending its logs out, while the first still reaches the workspace.
    const serverLogs = staging.predictedResources.find(named(/^logs-to-workspace$/));
    expect(
      brokenRules(
        withExtra({
          ...structuredClone(serverLogs),
          id: `${String(serverLogs?.id)}-abroad`,
          name: 'logs-abroad',
          properties: {
            storageAccountId: '/subscriptions/x/resourceGroups/y/providers/Microsoft.Storage/storageAccounts/abroad',
            logs: [{ category: 'PostgreSQLLogs', enabled: true }],
          },
        }),
      ),
    ).toEqual(['log-destinations']);
  });

  it("activity-log: the subscription's changes not kept, or kept elsewhere", () => {
    const ACTIVITY = named(/^activity-log-to-workspace$/);
    expect(brokenRules(without(ACTIVITY))).toEqual(['activity-log']);
    expect(brokenRules(changed(ACTIVITY, (entry) => (first(at(entry, 'properties', 'logs')).enabled = false)))).toEqual(
      ['activity-log'],
    );
    expect(
      brokenRules(
        changed(ACTIVITY, (entry) => (inside(entry, 'properties').workspaceId = '/subscriptions/x/workspaces/y')),
      ),
    ).toEqual(['log-destinations', 'activity-log']);
  });

  it("budget: none, a notice to nobody or at another threshold, or a start that isn't a first of the month", () => {
    const notice = (entry: Mutable, name: string): Mutable => inside(entry, 'properties', 'notifications', name);
    for (const change of [
      (entry: Mutable) => delete inside(entry, 'properties', 'notifications').forecast100,
      (entry: Mutable) => (notice(entry, 'actual80').enabled = false),
      (entry: Mutable) => (notice(entry, 'actual80').contactEmails = []),
      (entry: Mutable) => (notice(entry, 'actual80').threshold = 90),
      (entry: Mutable) => (notice(entry, 'forecast100').thresholdType = 'Actual'),
      (entry: Mutable) => (inside(entry, 'properties', 'timePeriod').startDate = '2026-09-15'),
    ]) {
      expect(brokenRules(changed(BUDGET, change))).toEqual(['budget']);
    }
    expect(brokenRules(without(BUDGET))).toEqual(['budget']);
  });

  it('apps-environment: another subnet, a dedicated profile, traffic unencrypted, or logs sent with a key or not at all', () => {
    const properties = (environment: Mutable): Mutable => inside(environment, 'properties');
    const network = staging.predictedResources.find(NETWORK);
    for (const change of [
      (environment: Mutable) =>
        (inside(environment, 'properties', 'vnetConfiguration').infrastructureSubnetId =
          '/subscriptions/x/resourceGroups/y/providers/Microsoft.Network/virtualNetworks/v/subnets/apps'),
      (environment: Mutable) =>
        (inside(environment, 'properties', 'vnetConfiguration').infrastructureSubnetId =
          `${String(network?.id)}/subnets/database`),
      (environment: Mutable) => delete properties(environment).vnetConfiguration,
      (environment: Mutable) => (first(properties(environment).workloadProfiles).workloadProfileType = 'D4'),
      (environment: Mutable) =>
        (properties(environment).workloadProfiles = [
          first(properties(environment).workloadProfiles),
          { name: 'dedicated', workloadProfileType: 'D4', minimumCount: 1, maximumCount: 1 },
        ]),
      // A Consumption-only environment, the legacy kind Microsoft's network rules above don't describe.
      (environment: Mutable) => delete properties(environment).workloadProfiles,
      (environment: Mutable) =>
        (inside(environment, 'properties', 'peerTrafficConfiguration', 'encryption').enabled = false),
      (environment: Mutable) => delete properties(environment).peerTrafficConfiguration,
      (environment: Mutable) =>
        (inside(environment, 'properties', 'appLogsConfiguration').destination = 'log-analytics'),
      (environment: Mutable) => (inside(environment, 'properties', 'appLogsConfiguration').destination = 'none'),
      (environment: Mutable) => delete properties(environment).appLogsConfiguration,
      // Another way to send telemetry, to a service that may sit outside the UAE.
      (environment: Mutable) => (properties(environment).daprAIConnectionString = "[parameters('daprTelemetry')]"),
      (environment: Mutable) => (properties(environment).daprAIInstrumentationKey = 'a key'),
      (environment: Mutable) =>
        (properties(environment).openTelemetryConfiguration = {
          destinationsConfiguration: {
            otlpConfigurations: [{ name: 'abroad', endpoint: 'https://collector.example' }],
          },
        }),
      (environment: Mutable) =>
        (properties(environment).appInsightsConfiguration = { connectionString: "[parameters('insights')]" }),
    ]) {
      expect(brokenRules(changed(ENVIRONMENT, change))).toEqual(['apps-environment']);
    }
    // Present but empty, they send nothing.
    expect(
      brokenRules(
        changed(ENVIRONMENT, (environment) => {
          properties(environment).daprAIConnectionString = '';
          properties(environment).openTelemetryConfiguration = {};
          properties(environment).appInsightsConfiguration = null;
        }),
      ),
    ).toEqual([]);
  });

  it('apps-network: the apps subnet without its rules, or a door wider than the probes and the subnet itself', () => {
    const probes = (group: Mutable): Mutable => ruleNamed(group, 'allow-load-balancer-probes');
    const itself = (group: Mutable): Mutable => ruleNamed(group, 'allow-within-subnet');
    const deny = (group: Mutable): Mutable => ruleNamed(group, 'deny-rest-of-network');
    for (const change of [
      (group: Mutable) => (probes(group).sourceAddressPrefix = 'Internet'),
      (group: Mutable) => (probes(group).destinationPortRange = '*'),
      (group: Mutable) => (probes(group).protocol = '*'),
      (group: Mutable) => (probes(group).destinationAddressPrefix = '*'),
      (group: Mutable) => (itself(group).sourceAddressPrefix = '10.40.0.0/16'),
      (group: Mutable) => (itself(group).destinationAddressPrefix = '*'),
      (group: Mutable) => {
        dropRule(group, 'allow-load-balancer-probes');
      },
      (group: Mutable) => {
        dropRule(group, 'allow-within-subnet');
      },
      (group: Mutable) => {
        dropRule(group, 'deny-rest-of-network');
      },
      (group: Mutable) => (deny(group).priority = 105),
      (group: Mutable) => (deny(group).access = 'Allow'),
      (group: Mutable) => (deny(group).protocol = 'Tcp'),
      (group: Mutable) => (deny(group).sourceAddressPrefix = '10.40.1.0/24'),
      (group: Mutable) => (deny(group).destinationAddressPrefix = '10.40.1.0/24'),
      (group: Mutable) => (deny(group).destinationPortRange = '22'),
      // A third door: the database subnet let in.
      (group: Mutable) => {
        const extra = structuredClone(nth(rules(group), 1));
        extra.name = 'allow-database';
        inside(extra, 'properties').sourceAddressPrefix = '10.40.1.0/24';
        inside(extra, 'properties').priority = 120;
        rules(group).push(extra);
      },
    ]) {
      expect(brokenRules(changed(APPS_RULES, change))).toEqual(['apps-network']);
    }
    // No rules group at all takes the way out with it, so both rules speak.
    expect(
      brokenRules(
        changed(NETWORK, (network) => delete inside(subnet(network, 'apps'), 'properties').networkSecurityGroup),
      ),
    ).toEqual(['apps-network', 'apps-egress']);
    expect(brokenRules(without(APPS_RULES))).toEqual(['apps-network', 'apps-egress']);
    expect(brokenRules(withExtra(separateRule(APPS_RULES, 'Inbound', 'VirtualNetwork', '*', '*')))).toEqual([
      'apps-network',
    ]);
    // No apps subnet at all: the database's rule refuses it too, and the vault
    // and the environment point at a subnet that isn't there.
    expect(
      brokenRules(
        changed(NETWORK, (network) => {
          inside(network, 'properties').subnets = [subnet(network, 'database')];
        }),
      ),
    ).toEqual(['database-network', 'apps-network', 'apps-egress', 'vault', 'apps-environment']);
  });

  it('apps-egress: a door out that nothing needs, one the apps need missing, or the rest not denied after them', () => {
    const out = (group: Mutable, name: string): Mutable => ruleNamed(group, `allow-out-${name}`);
    const deny = (group: Mutable): Mutable => ruleNamed(group, 'deny-out-rest');
    const prefixes = (group: Mutable, name: string): string[] =>
      at(out(group, name), 'destinationAddressPrefixes') as string[];
    for (const change of [
      // A door widened is a door nothing needs, and the one it replaced gone.
      (group: Mutable) => (out(group, 'within-subnet').destinationAddressPrefix = '*'),
      (group: Mutable) => (out(group, 'within-subnet').protocol = 'Tcp'),
      (group: Mutable) => (out(group, 'azure-dns').destinationPortRange = '*'),
      (group: Mutable) => (out(group, 'database').destinationPortRange = '*'),
      (group: Mutable) => (out(group, 'database').destinationAddressPrefix = 'VirtualNetwork'),
      // The key vault of another country, which ADR-009 refuses.
      (group: Mutable) => (out(group, 'key-vault').destinationAddressPrefix = 'AzureKeyVault'),
      (group: Mutable) => (out(group, 'key-vault').destinationAddressPrefix = 'AzureKeyVault.westeurope'),
      (group: Mutable) => (out(group, 'monitor').destinationAddressPrefix = 'AzureCloud'),
      // Every door simply missing.
      (group: Mutable) => {
        dropRule(group, 'allow-out-within-subnet');
      },
      (group: Mutable) => {
        dropRule(group, 'allow-out-azure-dns');
      },
      (group: Mutable) => {
        dropRule(group, 'allow-out-database');
      },
      (group: Mutable) => {
        dropRule(group, 'allow-out-key-vault');
      },
      (group: Mutable) => {
        dropRule(group, 'allow-out-monitor');
      },
      (group: Mutable) => {
        dropRule(group, 'allow-out-entra');
      },
      (group: Mutable) => {
        dropRule(group, 'allow-out-platform-images');
      },
      (group: Mutable) => {
        dropRule(group, 'allow-out-platform-images-front-door');
      },
      (group: Mutable) => {
        dropRule(group, 'allow-out-github-registry');
      },
      (group: Mutable) => {
        dropRule(group, 'allow-out-github-downloads');
      },
      // GitHub's ranges drifting from github-ranges.json, either way.
      (group: Mutable) => prefixes(group, 'github-registry').push('203.0.113.7/32'),
      (group: Mutable) => prefixes(group, 'github-registry').pop(),
      (group: Mutable) => (out(group, 'github-downloads').destinationAddressPrefixes = ['0.0.0.0/0']),
      // A door open to something that isn't the apps subnet.
      (group: Mutable) => (out(group, 'monitor').sourceAddressPrefix = '*'),
      (group: Mutable) => (out(group, 'entra').sourceAddressPrefix = '10.40.1.0/24'),
      // The backstop weakened: any of its parts, or moved above a door it must follow.
      (group: Mutable) => (deny(group).access = 'Allow'),
      (group: Mutable) => (deny(group).protocol = 'Tcp'),
      (group: Mutable) => (deny(group).sourceAddressPrefix = '10.40.0.0/24'),
      (group: Mutable) => (deny(group).destinationAddressPrefix = 'Internet'),
      (group: Mutable) => (deny(group).destinationPortRange = '443'),
      (group: Mutable) => (deny(group).priority = 205),
      (group: Mutable) => {
        dropRule(group, 'deny-out-rest');
      },
    ]) {
      expect(brokenRules(changed(APPS_RULES, change))).toEqual(['apps-egress']);
    }
    // A door added as a resource of its own under the group counts with the group's.
    expect(brokenRules(withExtra(separateRule(APPS_RULES, 'Outbound', '10.40.0.0/24', 'Internet', '443')))).toEqual([
      'apps-egress',
    ]);
    // The order Azure is given a list of addresses in is its business, not ours.
    expect(brokenRules(changed(APPS_RULES, (group) => prefixes(group, 'github-registry').reverse()))).toEqual([]);
  });

  it('SEC-DATA-09 apps-logs: console or system logs kept out of the workspace, or the HTTP log sent anywhere', () => {
    const logs = (setting: Mutable): Mutable[] => at(setting, 'properties', 'logs') as Mutable[];
    for (const change of [
      (setting: Mutable) => (inside(setting, 'properties').logAnalyticsDestinationType = 'AzureDiagnostics'),
      (setting: Mutable) => (first(logs(setting)).enabled = false),
      (setting: Mutable) => (nth(logs(setting), 1).enabled = false),
      (setting: Mutable) => (nth(logs(setting), 1).category = 'AppEnvSessionConsoleLogs'),
      (setting: Mutable) => logs(setting).push({ category: 'ContainerAppHTTPLogs', enabled: true }),
      (setting: Mutable) => logs(setting).push({ categoryGroup: 'allLogs', enabled: true }),
      (setting: Mutable) => logs(setting).push({ categoryGroup: 'audit', enabled: true }),
      (setting: Mutable) => logs(setting).push({ category: 'AppEnvSessionConsoleLogs', enabled: true }),
    ]) {
      expect(brokenRules(changed(APP_LOGS, change))).toEqual(['apps-logs']);
    }
    expect(
      brokenRules(
        changed(
          APP_LOGS,
          (setting) =>
            (inside(setting, 'properties').workspaceId =
              '/subscriptions/x/resourceGroups/y/providers/Microsoft.OperationalInsights/workspaces/elsewhere'),
        ),
      ),
    ).toEqual(['log-destinations', 'apps-logs']);
    expect(brokenRules(without(APP_LOGS))).toEqual(['apps-logs']);
    // Listed but switched off, it sends nothing.
    expect(
      brokenRules(
        changed(APP_LOGS, (setting) => logs(setting).push({ category: 'ContainerAppHTTPLogs', enabled: false })),
      ),
    ).toEqual([]);
    // The HTTP log sent by a second setting on the environment, to the same workspace.
    const appLogs = staging.predictedResources.find(APP_LOGS);
    expect(
      brokenRules(
        withExtra({
          ...structuredClone(appLogs),
          id: `${String(appLogs?.id)}-http`,
          name: 'http-logs',
          properties: {
            ...structuredClone(appLogs?.properties as Mutable),
            logs: [{ category: 'ContainerAppHTTPLogs', enabled: true }],
          },
        }),
      ),
    ).toEqual(['apps-logs']);
  });

  it("app-errors-alert: no alert on the apps' error events, or one that can't fire", () => {
    const query = (text: string) => (alert: Mutable) => (criterion(alert).query = text);
    expect(brokenRules(without(ERRORS_ALERT))).toEqual(['app-errors-alert']);
    for (const change of [
      query('ContainerAppConsoleLogs | where tostring(parse_json(Log).level) == "error" | summarize Errors = count()'),
      // Case-sensitive: it would miss Zitadel's "ERROR" lines (code review, S14).
      query(
        'ContainerAppConsoleLogs | where tostring(parse_json(Log).level) in ("error", "fatal", "panic") | summarize Errors = count()',
      ),
      query(
        'ContainerAppSystemLogs | where tostring(parse_json(Log).level) in~ ("error", "fatal", "panic") | summarize Errors = count()',
      ),
      query(
        'ContainerAppConsoleLogs | where tostring(parse_json(Log).level) in~ ("error", "fatal", "panic") | where ContainerAppName == "api" | summarize Errors = count()',
      ),
      (alert: Mutable) => (criterion(alert).operator = 'LessThan'),
      (alert: Mutable) => (criterion(alert).threshold = -1),
      (alert: Mutable) => delete criterion(alert).threshold,
      (alert: Mutable) => (inside(alert, 'properties').scopes = ['/subscriptions/x/workspaces/y']),
    ]) {
      expect(brokenRules(changed(ERRORS_ALERT, change))).toEqual(['app-errors-alert']);
    }
    expect(brokenRules(changed(ERRORS_ALERT, (alert) => (inside(alert, 'properties').enabled = false)))).toEqual([
      'alert-delivery',
      'app-errors-alert',
    ]);
    // A higher threshold is a choice, not a break.
    expect(brokenRules(changed(ERRORS_ALERT, (alert) => (criterion(alert).threshold = 5)))).toEqual([]);
  });

  it('identities: one usable in any region', () => {
    expect(
      brokenRules(
        changed(named(/^id-agentx-stg-api$/), (identity) => (inside(identity, 'properties').isolationScope = 'None')),
      ),
    ).toEqual(['identities']);
    expect(brokenRules(changed(IDENTITIES, (identity) => delete identity.properties))).toEqual(['identities']);
  });

  it('SEC-OPS-11 vault-secrets: a secret written on every run or on another condition, missing, doubled, unread, or elsewhere', () => {
    for (const change of [
      (secret: Mutable) => delete secret.condition,
      (secret: Mutable) => (secret.condition = "[not(empty(parameters('dbOwnerPassword')))]"),
      (secret: Mutable) => (secret.condition = "[empty(parameters('dbAppPassword'))]"),
      (secret: Mutable) => (secret.condition = 'true'),
      // Not an expression at all, only text around one.
      (secret: Mutable) => (secret.condition = `x${String(secret.condition)}`),
      (secret: Mutable) => (secret.condition = `${String(secret.condition)}x`),
      // Its value from one parameter, its condition on another's.
      (secret: Mutable) => (inside(secret, 'properties').value = "[parameters('dbOwnerPassword')]"),
    ]) {
      expect(brokenRules(changed(SECRET('db-app-password'), change))).toEqual(['vault-secrets']);
    }
    // The master key written whenever a run brings one.
    expect(
      brokenRules(
        changed(
          SECRET('zitadel-masterkey'),
          (secret) => (secret.condition = "[not(empty(parameters('zitadelMasterKey')))]"),
        ),
      ),
    ).toEqual(['vault-secrets']);
    // Missing: nobody can read it either.
    expect(brokenRules(without(SECRET('db-app-password')))).toEqual(['vault-secrets', 'secret-access']);
    const appPassword = structuredClone(
      staging.predictedResources.find(SECRET('db-app-password')),
    ) as unknown as Mutable;
    const elsewhere = String(appPassword.id).replace('/vaults/kv-agentx-stg-', '/vaults/kv-abroad-');
    // Written twice into our vault, as when two deployments both write it; a second copy in another vault.
    expect(brokenRules(withExtra({ ...appPassword }))).toEqual(['vault-secrets']);
    expect(brokenRules(withExtra({ ...appPassword, id: elsewhere }))).toEqual(['vault-secrets']);
    // A value written into the code, and on every run.
    expect(
      brokenRules(
        changed(SECRET('db-app-password'), (secret) => {
          inside(secret, 'properties').value = 'written in the code';
          delete secret.condition;
        }),
      ),
    ).toEqual(['no-secret-literals', 'vault-secrets']);
    // A secret no app or job reads.
    expect(brokenRules(withExtra({ ...appPassword, id: `${String(appPassword.id)}-spare` }))).toEqual([
      'vault-secrets',
    ]);
    // Moved to another vault: its readers are let read a secret this deployment doesn't write.
    expect(brokenRules(changed(SECRET('db-app-password'), (secret) => (secret.id = elsewhere)))).toEqual([
      'vault-secrets',
      'secret-access',
    ]);
  });

  it('SEC-OPS-11 vault-secrets in a compiled template: a secret written on every run, on another condition, or both on a condition and once', () => {
    const master = "@onlyIfNotExists()\nresource created 'Microsoft.KeyVault/vaults/secrets@2025-05-01' = {";
    for (const [from, to] of [
      // The master key overwritten by every run.
      ['@onlyIfNotExists()\nresource created', 'resource created'],
      // The master key overwritten by every staging run: a condition the snapshot settles and drops (security review, S15).
      [master, "resource created 'Microsoft.KeyVault/vaults/secrets@2025-05-01' = if (environment == 'staging') {"],
      // Every other secret overwritten by every run, given or not, or whenever a secret has a name.
      ['for secret in secrets: if (!empty(secret.value)) {', 'for secret in secrets: {'],
      ['for secret in secrets: if (!empty(secret.value)) {', 'for secret in secrets: if (!empty(secret.name)) {'],
      // Rotating secrets that a run can no longer rotate.
      ["resource written 'Microsoft", "@onlyIfNotExists()\nresource written 'Microsoft"],
    ] as const) {
      inCopy((dir) => {
        const file = path.join(dir, 'secrets.bicep');
        const text = readFileSync(file, 'utf8');
        expect(text).toContain(from);
        writeFileSync(file, text.replace(from, to));
        const problems = templateProblems('secrets.bicep', build(dir, 'secrets.bicep'));
        expect(problems.map((problem) => problem.rule)).toEqual(['vault-secrets']);
      });
    }
    // A module's own template and language version 1.0's list are read the same way; a secret only looked up isn't written.
    const secret = { type: 'Microsoft.KeyVault/vaults/secrets', name: 'x' };
    expect(templateProblems('t.bicep', { resources: [secret] })).toHaveLength(1);
    expect(
      templateProblems('t.bicep', {
        resources: {
          part: { type: 'Microsoft.Resources/deployments', properties: { template: { resources: [secret] } } },
        },
      }),
    ).toHaveLength(1);
    expect(templateProblems('t.bicep', { resources: { found: { ...secret, existing: true } } })).toEqual([]);
    // Written when its own value is given; a condition on another value, or around its own, is not that.
    const given = { ...secret, condition: "[not(empty(parameters('p')))]", properties: { value: "[parameters('p')]" } };
    expect(templateProblems('t.bicep', { resources: [given] })).toEqual([]);
    for (const condition of ["[not(empty(parameters('q')))]", "[and(true(), not(empty(parameters('p'))))]"]) {
      expect(templateProblems('t.bicep', { resources: [{ ...given, condition }] })).toHaveLength(1);
    }
    for (const value of ['p', "x[parameters('p')]", "[parameters('p')]x"]) {
      expect(templateProblems('t.bicep', { resources: [{ ...given, properties: { value } }] })).toHaveLength(1);
    }
  });

  it("SEC-OPS-11 secret-access: another role, a wider scope, someone else's principal, or a reader the list doesn't name", () => {
    const API_READS = READS('api', 'db-app-password');
    const properties = (assignment: Mutable): Mutable => inside(assignment, 'properties');
    const role = (id: string) => (assignment: Mutable) =>
      (properties(assignment).roleDefinitionId = String(properties(assignment).roleDefinitionId).replace(
        '4633458b-17de-408a-b874-0445c86b69e6',
        id,
      ));
    const scoped = (scope: unknown) => (assignment: Mutable) =>
      (assignment.id = `${String(scope)}/providers/Microsoft.Authorization/roleAssignments/${String(assignment.name)}`);
    const principal = (workload: string): string =>
      `[reference('${String(staging.predictedResources.find(named(new RegExp(`^id-agentx-stg-${workload}$`)))?.id)}', '2024-11-30').principalId]`;
    for (const change of [
      // Key Vault Secrets Officer, which also writes and deletes secrets; Key Vault Administrator.
      role('b86a8fe4-44ce-4948-aee5-eccb2c155cd7'),
      role('00482a5a-887f-4fb3-b363-3b7fe8e74483'),
      // Every secret at once: the vault, the resource group, the subscription.
      scoped(staging.predictedResources.find(VAULT)?.id),
      scoped(staging.predictedResources.find(type('Microsoft.Resources/resourceGroups'))?.id),
      scoped('/subscriptions/00000000-0000-0000-0000-000000000001'),
      // Someone other than an identity this deployment creates.
      (assignment: Mutable) => (properties(assignment).principalId = '00000000-0000-0000-0000-00000000abcd'),
      (assignment: Mutable) =>
        (properties(assignment).principalId = principal('api').replace(
          '/resourceGroups/rg-agentx-staging/',
          '/resourceGroups/elsewhere/',
        )),
      (assignment: Mutable) => (properties(assignment).principalId = `x${principal('api')}`),
      (assignment: Mutable) => (properties(assignment).principalId = `${principal('api')}x`),
      (assignment: Mutable) => (properties(assignment).principalType = 'User'),
      (assignment: Mutable) => delete properties(assignment).principalType,
      // Another app's identity: the login pages reading the API's database login.
      (assignment: Mutable) => (properties(assignment).principalId = principal('login')),
    ]) {
      expect(brokenRules(changed(API_READS, change))).toEqual(['secret-access']);
    }
    // A wider scope is refused as that, not only as a reader the list doesn't name.
    for (const scope of [
      staging.predictedResources.find(VAULT)?.id,
      staging.predictedResources.find(type('Microsoft.Resources/resourceGroups'))?.id,
    ]) {
      expect(policyProblems(changed(API_READS, scoped(scope)), STAGING).map(describeProblem)).toContainEqual(
        expect.stringMatching(
          /\[secret-access\] must give Key Vault Secrets User on one secret this deployment writes/,
        ),
      );
    }
    // One more secret for the API, on top of its own.
    const extra = structuredClone(staging.predictedResources.find(API_READS)) as unknown as Mutable;
    extra.id = String(extra.id).replace('/secrets/db-app-password/', '/secrets/db-owner-password/');
    expect(brokenRules(withExtra(extra))).toEqual(['secret-access']);
    // A reader left out: the migration job can't read its login.
    expect(brokenRules(without(READS('migrate', 'db-owner-password')))).toEqual(['secret-access']);
    // A reader whose identity the foundation doesn't create.
    expect(brokenRules(without(named(/^id-agentx-stg-login$/)))).toEqual(['secret-access']);
  });

  it('jobs: one that starts itself, runs twice at once, retries, or runs an image a tag could move', () => {
    const environment = staging.predictedResources.find(ENVIRONMENT);
    expect(
      brokenRules(
        changed(JOB('migrate'), (job) => {
          inside(job, 'properties').environmentId = `${String(environment?.id)}-second`;
        }),
      ),
    ).toEqual(['jobs']);
    expect(
      brokenRules(
        changed(JOBS, (job) => {
          inside(job, 'properties').workloadProfileName = 'D4';
        }),
      ),
    ).toEqual(['jobs']);
    for (const start of [
      { triggerType: 'Schedule' },
      { scheduleTriggerConfig: { cronExpression: '0 3 * * *' } },
      { eventTriggerConfig: { scale: {} } },
      { replicaRetryLimit: 1 },
      { replicaTimeout: 0 },
      { replicaTimeout: 4000 },
      { replicaTimeout: 'soon' },
      { manualTriggerConfig: { parallelism: 2, replicaCompletionCount: 1 } },
      { manualTriggerConfig: { parallelism: 1, replicaCompletionCount: 2 } },
    ]) {
      expect({
        start,
        rules: brokenRules(
          changed(JOB('db-setup'), (job) => {
            Object.assign(configurationOf(job), start);
          }),
        ),
      }).toEqual({ start, rules: ['jobs'] });
    }
    // Two containers, or work hidden in an init container that runs before it.
    expect(
      brokenRules(
        changed(JOB('migrate'), (job) => {
          inside(job, 'properties', 'template').containers = [containerOf(job), structuredClone(containerOf(job))];
        }),
      ),
    ).toEqual(['jobs']);
    expect(
      brokenRules(
        changed(JOB('migrate'), (job) => {
          inside(job, 'properties', 'template').initContainers = [structuredClone(containerOf(job))];
        }),
      ),
    ).toEqual(['jobs']);
    // A tag in place of the digest: the same name, another image tomorrow.
    expect(
      brokenRules(
        changed(JOB('migrate'), (job) => {
          containerOf(job).image = 'ghcr.io/shahbaz242630/agent-x:v1';
        }),
      ),
    ).toEqual(['jobs']);
    // A job the deployment needs, left out.
    for (const workload of ['db-setup', 'migrate', 'zitadel-init', 'zitadel-setup']) {
      expect({ workload, rules: brokenRules(without(JOB(workload))) }).toEqual({ workload, rules: ['jobs'] });
    }
  });

  it('apps: one made a public door, left on plain http, scaled past what it may run, or missing', () => {
    const environment = staging.predictedResources.find(ENVIRONMENT);
    expect(
      brokenRules(
        changed(APP('login'), (app) => {
          inside(app, 'properties').environmentId = `${String(environment?.id)}-second`;
        }),
      ),
    ).toEqual(['apps']);
    expect(
      brokenRules(
        changed(APPS, (app) => {
          inside(app, 'properties').workloadProfileName = 'D4';
        }),
      ),
    ).toEqual(['apps']);
    // A public door nothing decided to publish: the doors are the route
    // configs (G2e), so an external ingress here is one nobody asked for.
    expect(brokenRules(changed(APP('api'), (app) => (ingressOf(app).external = true)))).toEqual(['apps']);
    expect(brokenRules(changed(APP('zitadel'), (app) => (ingressOf(app).allowInsecure = true)))).toEqual(['apps']);
    // An ingress left out entirely is one Azure decides, not us.
    expect(
      brokenRules(
        changed(APP('login'), (app) => {
          delete inside(app, 'properties', 'configuration').ingress;
        }),
      ),
    ).toEqual(['apps']);
    // The two that hold something one replica's, given a second.
    for (const workload of ['api', 'zitadel']) {
      expect({ workload, rules: brokenRules(changed(APP(workload), (app) => (scaleOf(app).maxReplicas = 2))) }).toEqual(
        {
          workload,
          rules: ['apps'],
        },
      );
    }
    // An app that may run no replica at all, and one holding more than it may run.
    for (const scale of [{ maxReplicas: 0 }, { maxReplicas: 'one' }, { minReplicas: -1 }, { minReplicas: 2 }]) {
      expect({
        scale,
        rules: brokenRules(changed(APP('login'), (app) => Object.assign(scaleOf(app), scale))),
      }).toEqual({ scale, rules: ['apps'] });
    }
    // Two containers, or work hidden in an init container that runs before it.
    expect(
      brokenRules(
        changed(APP('login'), (app) => {
          inside(app, 'properties', 'template').containers = [containerOf(app), structuredClone(containerOf(app))];
        }),
      ),
    ).toEqual(['apps']);
    expect(
      brokenRules(
        changed(APP('login'), (app) => {
          inside(app, 'properties', 'template').initContainers = [structuredClone(containerOf(app))];
        }),
      ),
    ).toEqual(['apps']);
    // A tag in place of the digest: the same name, another image tomorrow.
    expect(brokenRules(changed(APP('api'), (app) => (containerOf(app).image = 'ghcr.io/x/agent-x:v1')))).toEqual([
      'apps',
    ]);
    // An app the deployment needs, left out. Zitadel's own secrets are then
    // read by nothing, and the login pages have nothing to sign a call to.
    expect(brokenRules(without(APP('api')))).toEqual(['apps']);
    expect(brokenRules(without(APP('login')))).toEqual(['apps']);
    expect(brokenRules(without(APP('zitadel')))).toEqual(['apps']);
  });

  it('workload-secrets: a job given another job’s secret or identity, a pinned version, or a login in the environment', () => {
    const vault = staging.predictedResources.find(VAULT);
    const identity = (workload: string): string => String(staging.predictedResources.find(JOB(workload))?.identity);
    expect(identity).toBeTypeOf('function');
    // An identity that isn't its own, one too many, or one the resource shares.
    expect(
      brokenRules(
        changed(JOB('db-setup'), (job) => {
          job.identity = structuredClone(staging.predictedResources.find(JOB('migrate'))?.identity);
        }),
      ),
    ).toEqual(['workload-secrets']);
    expect(
      brokenRules(
        changed(JOB('db-setup'), (job) => {
          const ids = inside(job, 'identity', 'userAssignedIdentities');
          ids['/subscriptions/x/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-agentx-stg-api'] = {};
        }),
      ),
    ).toEqual(['workload-secrets']);
    expect(
      brokenRules(
        changed(JOBS, (job) => {
          inside(job, 'identity').type = 'SystemAssigned, UserAssigned';
        }),
      ),
    ).toEqual(['workload-secrets']);
    // A secret GRANTS doesn't give it, mounted and named like its own so that
    // nothing but the reader list can object; then a secret it needs left out,
    // with its use taken away too, so nothing but the list can object to that.
    const messages = (snapshotted: Snapshot): string[] => policyProblems(snapshotted, STAGING).map(describeProblem);
    expect(
      messages(
        changed(JOB('migrate'), (job) => {
          declaredSecrets(job).push({
            ...structuredClone(secretNamed(job, 'db-owner-password')),
            name: 'db-app-password',
            keyVaultUrl: `[uri(reference('${String(vault?.id)}', '2025-05-01').vaultUri, 'secrets/db-app-password')]`,
          });
          (at(first(at(job, 'properties', 'template', 'volumes')), 'secrets') as Mutable[]).push({
            secretRef: 'db-app-password',
            path: 'db-app-password',
          });
          settingsOf(job).push({ name: 'AGENTX_DB_APP_PASSWORD_FILE', value: '/mnt/secrets/db-app-password' });
        }),
      ),
    ).toEqual([
      "job-agentx-stg-migrate [workload-secrets] is given db-app-password, which GRANTS doesn't let migrate read",
    ]);
    expect(
      messages(
        changed(JOB('migrate'), (job) => {
          configurationOf(job).secrets = [];
          inside(job, 'properties', 'template').volumes = [];
          containerOf(job).env = settingsOf(job).filter((entry) => entry.name !== 'AGENTX_DB_MIGRATION_PASSWORD_FILE');
        }),
      ),
    ).toEqual([
      'job-agentx-stg-migrate [workload-secrets] must be given db-owner-password, which migrate reads (GRANTS)',
    ]);
    // A value carried in the deployment rather than read from the vault, a
    // version pinned into the address, another vault, and another's identity.
    for (const change of [
      { value: "[parameters('dbOwnerPassword')]" },
      { keyVaultUrl: `[uri(reference('${String(vault?.id)}', '2025-05-01').vaultUri, 'secrets/db-owner-password/9')]` },
      {
        keyVaultUrl: `[uri(reference('${String(vault?.id)}-second', '2025-05-01').vaultUri, 'secrets/db-owner-password')]`,
      },
      { keyVaultUrl: 'https://kv-agentx-stg-other.vault.azure.net/secrets/db-owner-password' },
    ]) {
      expect({
        change,
        rules: brokenRules(
          changed(JOB('migrate'), (job) => {
            Object.assign(secretNamed(job, 'db-owner-password'), change);
          }),
        ),
      }).toEqual({ change, rules: ['workload-secrets'] });
    }
    expect(
      brokenRules(
        changed(JOB('migrate'), (job) => {
          secretNamed(job, 'db-owner-password').identity = String(
            Object.keys(
              at(staging.predictedResources.find(JOB('db-setup'))?.identity, 'userAssignedIdentities') ?? {},
            )[0],
          );
        }),
      ),
    ).toEqual(['workload-secrets']);
    // A secret volume with no list mounts every secret the job has. Its own
    // message is asserted, because the five logins then also count as unread.
    expect(
      messages(
        changed(JOB('db-setup'), (job) => {
          delete first(at(job, 'properties', 'template', 'volumes')).secrets;
        }),
      ),
    ).toContainEqual(
      'job-agentx-stg-db-setup [workload-secrets] mounts secrets without naming what is in it, which mounts every secret it has',
    );
    // A secret it is given and never reads, and one it reads unasked.
    expect(
      brokenRules(
        changed(JOB('migrate'), (job) => {
          inside(job, 'properties', 'template').volumes = [];
        }),
      ),
    ).toEqual(['workload-secrets']);
    // Mounted, not in the environment, so only the reader list can object.
    expect(
      messages(
        changed(JOB('migrate'), (job) => {
          (at(first(at(job, 'properties', 'template', 'volumes')), 'secrets') as Mutable[]).push({
            secretRef: 'db-app-password',
            path: 'db-app-password',
          });
        }),
      ),
    ).toEqual(['job-agentx-stg-migrate [workload-secrets] reads db-app-password, which it is not given']);
    // Our own image taking a login from the environment, which crash output shows.
    expect(
      brokenRules(
        changed(JOB('migrate'), (job) => {
          settingsOf(job).push({ name: 'AGENTX_DB_MIGRATION_PASSWORD', secretRef: 'db-owner-password' });
        }),
      ),
    ).toEqual(['workload-secrets']);
    // Zitadel's database login may be in its environment; the same login in our
    // own image may not, and nor may its master key, which has a file form.
    expect(
      brokenRules(
        changed(JOB('zitadel-init'), (job) => {
          containerOf(job).image =
            'ghcr.io/shahbaz242630/agent-x@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
        }),
      ),
    ).toEqual(['workload-secrets']);
    expect(
      brokenRules(
        changed(JOB('zitadel-setup'), (job) => {
          settingsOf(job).push({ name: 'ZITADEL_MASTERKEY', secretRef: 'zitadel-masterkey' });
        }),
      ),
    ).toEqual(['workload-secrets']);
    // The apps are held to all of it too, not only the jobs: another app's
    // identity, another app's secret, a version pinned into the address, and a
    // key in an environment that has a file form.
    expect(
      brokenRules(
        changed(APP('api'), (app) => {
          inside(app, 'identity').userAssignedIdentities = at(
            staging.predictedResources.find(APP('login'))?.identity,
            'userAssignedIdentities',
          );
        }),
      ),
    ).toEqual(['workload-secrets']);
    expect(
      messages(
        changed(APP('login'), (app) => {
          declaredSecrets(app).push({
            name: 'db-app-password',
            keyVaultUrl: String(at(first(declaredSecrets(app)), 'keyVaultUrl')).replace(
              'login-client-private-key',
              'db-app-password',
            ),
            identity: at(first(declaredSecrets(app)), 'identity'),
          });
        }),
      ),
    ).toEqual([
      "ca-agentx-stg-login [workload-secrets] is given db-app-password, which GRANTS doesn't let login read",
      'ca-agentx-stg-login [workload-secrets] is given db-app-password and never reads it; one nobody needs is one more to leak',
    ]);
    expect(
      brokenRules(
        changed(APP('api'), (app) => {
          secretNamed(app, 'db-app-password').keyVaultUrl =
            'https://kv-agentx-stg-abcdef.vault.azure.net/secrets/db-app-password/0123456789abcdef';
        }),
      ),
    ).toEqual(['workload-secrets']);
    expect(
      brokenRules(
        changed(APP('api'), (app) => {
          settingsOf(app).push({ name: 'AGENTX_DB_PASSWORD', secretRef: 'db-app-password' });
        }),
      ),
    ).toEqual(['workload-secrets']);
    // The login pages' own key, which they read from a file, put in their
    // environment instead: their image has no listed setting for one.
    expect(
      brokenRules(
        changed(APP('login'), (app) => {
          settingsOf(app).push({ name: 'SYSTEM_USER_PRIVATE_KEY', secretRef: 'login-client-private-key' });
        }),
      ),
    ).toEqual(['workload-secrets']);
  });

  it('container-telemetry: an OpenTelemetry exporter, or Zitadel left to phone home', () => {
    for (const setting of [
      { name: 'OTEL_EXPORTER_OTLP_ENDPOINT', value: 'https://collector.example.invalid' },
      { name: 'OTEL_SDK_DISABLED', value: 'false' },
    ]) {
      for (const workload of ['migrate', 'zitadel-setup']) {
        expect({
          setting,
          workload,
          rules: brokenRules(
            changed(JOB(workload), (job) => {
              settingsOf(job).push(setting);
            }),
          ),
        }).toEqual({ setting, workload, rules: ['container-telemetry'] });
      }
    }
    // Switched off is the point, not silence: this one is allowed.
    expect(
      brokenRules(
        changed(JOB('zitadel-setup'), (job) => {
          settingsOf(job).push({ name: 'OTEL_SDK_DISABLED', value: 'true' });
        }),
      ),
    ).toEqual([]);
    // Zitadel's daily report and metrics, switched on or left to its default.
    expect(
      brokenRules(
        changed(JOB('zitadel-init'), (job) => {
          containerOf(job).env = settingsOf(job).map((entry) =>
            entry.name === 'ZITADEL_SERVICEPING_ENABLED' ? { ...entry, value: 'true' } : entry,
          );
        }),
      ),
    ).toEqual(['container-telemetry']);
    for (const name of [
      'ZITADEL_SERVICEPING_ENABLED',
      'ZITADEL_METRICS_TYPE',
      'ZITADEL_TRACING_TYPE',
      'ZITADEL_INSTRUMENTATION_TRACE_EXPORTER_TYPE',
      'ZITADEL_INSTRUMENTATION_METRIC_EXPORTER_TYPE',
      'ZITADEL_INSTRUMENTATION_LOG_EXPORTER_TYPE',
    ]) {
      expect({
        name,
        rules: brokenRules(
          changed(JOB('zitadel-setup'), (job) => {
            containerOf(job).env = settingsOf(job).filter((entry) => entry.name !== name);
          }),
        ),
      }).toEqual({ name, rules: ['container-telemetry'] });
      // The same switch on the server that serves traffic, not only the jobs.
      expect({
        name,
        rules: brokenRules(
          changed(APP('zitadel'), (app) => {
            containerOf(app).env = settingsOf(app).filter((entry) => entry.name !== name);
          }),
        ),
      }).toEqual({ name, rules: ['container-telemetry'] });
    }
    // The login pages are a different program in a different image: they read
    // none of the settings above, and the one switch they do need is their own.
    expect(
      brokenRules(
        changed(APP('login'), (app) => {
          containerOf(app).env = settingsOf(app).filter((entry) => entry.name !== 'OTEL_SDK_DISABLED');
        }),
      ),
    ).toEqual(['container-telemetry']);
    expect(
      brokenRules(
        changed(APP('login'), (app) => {
          settingsOf(app).push({ name: 'OTEL_EXPORTER_OTLP_ENDPOINT', value: 'https://collector.example.invalid' });
        }),
      ),
    ).toEqual(['container-telemetry']);
    // Asking the login pages for the server's settings would be asking for
    // something they ignore, so the server's absence from them is no problem.
    expect(
      brokenRules(
        changed(APP('login'), (app) => {
          containerOf(app).env = settingsOf(app).filter((entry) => !String(entry.name).startsWith('ZITADEL_'));
        }),
      ),
    ).toEqual([]);
  });
});

describe('what each job is told', () => {
  /** The commit the deployment was given, whatever this run's stand-in is. */
  const someCommit = expect.stringMatching(/^[0-9a-f]{40}$/) as unknown as string;

  /** Every setting a job's container is given, name to value, a secret's as `secret:<name>`. */
  const settingsGiven = (workload: string): Record<string, unknown> => {
    const job = staging.predictedResources.find(JOB(workload));
    const container = first(at(job?.properties, 'template', 'containers'));
    return Object.fromEntries(
      (at(container, 'env') as Mutable[]).map((entry) => [
        String(entry.name),
        typeof entry.secretRef === 'string' ? `secret:${entry.secretRef}` : entry.value,
      ]),
    );
  };

  it('gives our jobs the environment, the build, the database and each login as a file', () => {
    // Configuration.md: the shared four, the admin's role and first database,
    // and one login per role, each read from where the platform mounts it.
    expect(settingsGiven('db-setup')).toEqual({
      AGENTX_ENV: 'staging',
      AGENTX_RELEASE: someCommit,
      AGENTX_DB_HOST: 'psql-agentx-stg-ksacnt.agentx-staging.private.postgres.database.azure.com',
      AGENTX_DB_NAME: 'agentx',
      AGENTX_DB_ADMIN_USER: 'agentx_admin',
      AGENTX_DB_ADMIN_DATABASE: 'postgres',
      AGENTX_DB_ADMIN_PASSWORD_FILE: '/mnt/secrets/db-admin-password',
      AGENTX_DB_OWNER_PASSWORD_FILE: '/mnt/secrets/db-owner-password',
      AGENTX_DB_APP_PASSWORD_FILE: '/mnt/secrets/db-app-password',
      AGENTX_DB_BACKUP_PASSWORD_FILE: '/mnt/secrets/db-backup-password',
      AGENTX_DB_ZITADEL_PASSWORD_FILE: '/mnt/secrets/db-zitadel-password',
    });
    // The migration job holds the owner's login and nothing else.
    expect(settingsGiven('migrate')).toEqual({
      AGENTX_ENV: 'staging',
      AGENTX_RELEASE: someCommit,
      AGENTX_DB_HOST: 'psql-agentx-stg-ksacnt.agentx-staging.private.postgres.database.azure.com',
      AGENTX_DB_NAME: 'agentx',
      AGENTX_DB_MIGRATION_PASSWORD_FILE: '/mnt/secrets/db-owner-password',
    });
    // Neither is told the other's, and TLS is left at its default, verify-full.
    for (const workload of ['db-setup', 'migrate']) {
      expect(Object.keys(settingsGiven(workload))).not.toContain('AGENTX_DB_TLS');
      expect(Object.keys(settingsGiven(workload))).not.toContain('AGENTX_DB_PASSWORD');
    }
  });

  it('connects Zitadel as its own role, with TLS checked to the host', () => {
    for (const workload of ['zitadel-init', 'zitadel-setup']) {
      expect({ workload, settings: settingsGiven(workload) }).toMatchObject({
        workload,
        settings: {
          ZITADEL_DATABASE_POSTGRES_HOST: 'psql-agentx-stg-ksacnt.agentx-staging.private.postgres.database.azure.com',
          ZITADEL_DATABASE_POSTGRES_DATABASE: 'zitadel',
          // Its own role is also its "admin": it never holds the server admin's login.
          ZITADEL_DATABASE_POSTGRES_USER_USERNAME: 'zitadel',
          ZITADEL_DATABASE_POSTGRES_ADMIN_USERNAME: 'zitadel',
          ZITADEL_DATABASE_POSTGRES_USER_PASSWORD: 'secret:db-zitadel-password',
          ZITADEL_DATABASE_POSTGRES_ADMIN_PASSWORD: 'secret:db-zitadel-password',
          ZITADEL_DATABASE_POSTGRES_USER_SSL_MODE: 'verify-full',
          ZITADEL_DATABASE_POSTGRES_ADMIN_SSL_MODE: 'verify-full',
          // db-setup made the database, so init must not try to make it again.
          ZITADEL_DATABASE_POSTGRES_ADMIN_EXISTINGDATABASE: 'zitadel',
          ZITADEL_LOG_FORMATTER_FORMAT: 'json',
        },
      });
    }
    // Only setup writes an instance, so only setup is given the master key, and
    // it reads it from a file (`--masterkeyFile`), never its environment.
    for (const workload of ['zitadel-init', 'zitadel-setup']) {
      expect(Object.keys(settingsGiven(workload))).not.toContain('ZITADEL_MASTERKEY');
    }
    const mounted = (workload: string): unknown =>
      at(first(at(staging.predictedResources.find(JOB(workload))?.properties, 'template', 'volumes')), 'secrets');
    expect(mounted('zitadel-setup')).toEqual([{ secretRef: 'zitadel-masterkey', path: 'zitadel-masterkey' }]);
    expect(mounted('zitadel-init')).toBeUndefined();
  });

  it('creates the first instance with a starting password and the rules of ADR-003 and ADR-005', () => {
    expect(settingsGiven('zitadel-setup')).toMatchObject({
      // The ingress terminates TLS: https outside, plain http within.
      ZITADEL_EXTERNALDOMAIN: 'auth.example.invalid',
      ZITADEL_EXTERNALPORT: '443',
      ZITADEL_EXTERNALSECURE: 'true',
      ZITADEL_TLS_ENABLED: 'false',
      ZITADEL_FIRSTINSTANCE_ORG_HUMAN_USERNAME: 'admin',
      ZITADEL_FIRSTINSTANCE_ORG_HUMAN_PASSWORD: 'secret:zitadel-admin-password',
      // Zitadel's default, said outright: the vault's password is a starting one.
      ZITADEL_FIRSTINSTANCE_ORG_HUMAN_PASSWORDCHANGEREQUIRED: 'true',
      // No mail can be sent from the deployment, so the address is verified here.
      ZITADEL_FIRSTINSTANCE_ORG_HUMAN_EMAIL_VERIFIED: 'true',
      ZITADEL_DEFAULTINSTANCE_LOGINPOLICY_FORCEMFA: 'true',
      ZITADEL_DEFAULTINSTANCE_LOGINPOLICY_ALLOWREGISTER: 'false',
      ZITADEL_DEFAULTINSTANCE_LOGINPOLICY_ALLOWEXTERNALIDP: 'false',
      ZITADEL_DEFAULTINSTANCE_LOGINPOLICY_MFAINITSKIPLIFETIME: '0h',
      ZITADEL_DEFAULTINSTANCE_RESTRICTIONS_DISALLOWPUBLICORGREGISTRATION: 'true',
    });
    // The compose stack's test machine user and its token belong to it alone.
    expect(Object.keys(settingsGiven('zitadel-setup')).filter((name) => name.includes('MACHINE'))).toEqual([]);
    expect(Object.keys(settingsGiven('zitadel-setup')).filter((name) => name.includes('PATPATH'))).toEqual([]);
  });

  it('starts each job on the command the compose stack runs it with', () => {
    const ran = (workload: string): unknown => {
      const container = first(at(staging.predictedResources.find(JOB(workload))?.properties, 'template', 'containers'));
      return [...(at(container, 'command') as unknown[]), ...(at(container, 'args') as unknown[])];
    };
    expect(ran('db-setup')).toEqual(['node', 'apps/db-setup/src/main.ts']);
    expect(ran('migrate')).toEqual(['node', 'apps/migrate/src/main.ts']);
    // The compose stack's healthcheck proves this path on the same digest, and
    // splits `start-from-setup` into the two steps a deployment runs separately.
    expect(ran('zitadel-init')).toEqual(['/app/zitadel', 'init', 'zitadel']);
    expect(ran('zitadel-setup')).toEqual([
      '/app/zitadel',
      'setup',
      '--masterkeyFile',
      '/mnt/secrets/zitadel-masterkey',
    ]);
  });
});

describe('reading an alert query', () => {
  it('splits at top-level pipes only: not in strings, verbatim strings, comments or brackets', () => {
    expect(kqlStages('T | where M matches regex @"a|b" | summarize N = count()')).toEqual([
      'T',
      'where M matches regex @"a|b"',
      'summarize N = count()',
    ]);
    expect(kqlStages("T | where M == 'x|y' // a | comment\n| summarize N = count()")).toEqual([
      'T',
      "where M == 'x|y' // a | comment",
      'summarize N = count()',
    ]);
    expect(kqlStages('T | where M == @"say ""a|b""" | summarize N = toscalar(U | count)')).toEqual([
      'T',
      'where M == @"say ""a|b"""',
      'summarize N = toscalar(U | count)',
    ]);
    expect(kqlStages('T | where M == "escaped \\" | still" | take 1')).toEqual([
      'T',
      'where M == "escaped \\" | still"',
      'take 1',
    ]);
    expect(kqlStages('T | where M == ```a | b``` | take 1')).toEqual(['T', 'where M == ```a | b```', 'take 1']);
    // A verbatim string has no escapes: its backslash doesn't hide the closing quote.
    expect(kqlStages('T | where M == @"C:\\" | take 1')).toEqual(['T', 'where M == @"C:\\"', 'take 1']);
  });

  it('finds the one column a final summarize makes, and nothing when it makes rows', () => {
    expect(singleSummaryColumn('T | summarize N = count()')).toBe('N');
    expect(singleSummaryColumn('T | summarize Mb = sum(Quantity)')).toBe('Mb');
    expect(singleSummaryColumn('T | summarize N = countif(M has "a, b" and X in (1, 2))')).toBe('N');
    expect(singleSummaryColumn('T | summarize N = count() by Resource')).toBeUndefined();
    expect(singleSummaryColumn('T | summarize N = count(), M = max(TimeGenerated)')).toBeUndefined();
    expect(singleSummaryColumn('T | summarize count()')).toBeUndefined();
    expect(singleSummaryColumn('T | summarize N = count() | project N')).toBeUndefined();
    expect(singleSummaryColumn('T | project M')).toBeUndefined();
  });
});
