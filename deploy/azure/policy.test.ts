import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
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
} from './policy.ts';
import {
  type BicepRun,
  inCopy,
  lint,
  paramsFiles,
  type PredictedResource,
  secureParameters,
  snapshot,
  type Snapshot,
} from './snapshot.ts';

const STAGING: Expectations = { region: 'uaenorth', environment: 'staging' };

interface Checked {
  readonly lint: BicepRun;
  readonly snapshot: Snapshot;
  readonly text: string;
}

let checked: ReadonlyMap<string, Checked>;
let mainLint: BicepRun;
let secure: readonly string[];
let staging: Snapshot;

beforeAll(() => {
  inCopy((dir) => {
    mainLint = lint(dir, 'main.bicep');
    secure = secureParameters(dir);
    checked = new Map(
      paramsFiles(dir).map((file) => [
        file,
        { lint: lint(dir, file), snapshot: snapshot(dir, file), text: readFileSync(path.join(dir, file), 'utf8') },
      ]),
    );
  });
  const found = checked.get('staging.bicepparam');
  if (found === undefined) throw new Error('deploy/azure has no staging.bicepparam');
  staging = found.snapshot;
});

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
const criterion = (alert: Mutable): Mutable => first(at(alert, 'properties', 'criteria', 'allOf'));
const rules = (group: Mutable): Mutable[] => at(group, 'properties', 'securityRules') as Mutable[];
const subnet = (network: Mutable, name: string): Mutable =>
  (at(network, 'properties', 'subnets') as Mutable[]).find((entry) => entry.name === name) ?? {};

/** An inbound allow rule declared as a resource of its own under the rules group `pick` selects. */
function separateRule(pick: (resource: PredictedResource) => boolean, source: string, port: string): Mutable {
  const group = staging.predictedResources.find(pick);
  return {
    id: `${String(group?.id)}/securityRules/allow-extra`,
    type: 'Microsoft.Network/networkSecurityGroups/securityRules',
    name: `${String(group?.name)}/allow-extra`,
    apiVersion: '2025-01-01',
    properties: {
      priority: 120,
      direction: 'Inbound',
      access: 'Allow',
      protocol: 'Tcp',
      sourceAddressPrefix: source,
      sourcePortRange: '*',
      destinationAddressPrefix: '*',
      destinationPortRange: port,
    },
  };
}

describe('deploy/azure', () => {
  it('has a parameters file for staging, and every one lints clean with every linter rule an error', () => {
    expect([...checked.keys()]).toContain('staging.bicepparam');
    expect(mainLint).toEqual({ status: 0, output: '', stdout: '' });
    for (const [file, { lint: run }] of checked)
      expect({ file, ...run }).toEqual({ file, status: 0, output: '', stdout: '' });
  });

  it('breaks no rule in any environment, and no parameters file writes down a secret', () => {
    expect(secure).toEqual(['postgresAdminPassword']);
    for (const [file, entry] of checked) {
      expect({
        file,
        problems: policyProblems(entry.snapshot, expectationsOf(entry.snapshot)).map(describeProblem),
      }).toEqual({ file, problems: [] });
      expect(paramsFileProblems(file, entry.text, secure)).toEqual([]);
    }
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
    expect(staging.predictedResources.map((resource) => `${resource.type} ${resource.name}`)).toEqual([
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
    expect(staging.diagnostics).toEqual([]);
  });
});

describe('each rule can fail', () => {
  it('snapshot-complete: Bicep reporting what it could not work out', () => {
    expect(brokenRules({ ...staging, diagnostics: [{ level: 'Warning', message: 'skipped' }] })).toEqual([
      'snapshot-complete',
    ]);
  });

  it('required: a protection that is missing, not only switched off', () => {
    expect(brokenRules(without((resource) => VAULT(resource) || named(/^audit-to-workspace$/)(resource)))).toEqual([
      'required',
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
    expect(brokenRules(without((resource) => ENVIRONMENT(resource) || APP_LOGS(resource)))).toEqual(['required']);
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
    const vault = staging.predictedResources.find(VAULT);
    const secret = {
      id: `${String(vault?.id)}/secrets/leaked`,
      type: 'Microsoft.KeyVault/vaults/secrets',
      name: 'leaked',
      apiVersion: '2025-05-01',
    };
    expect(brokenRules(withExtra({ ...secret, properties: { value: literal } }))).toEqual(['no-secret-literals']);
    expect(brokenRules(withExtra({ ...secret, properties: { value: "[parameters('fromTheShell')]" } }))).toEqual([]);
    const app = {
      id: '/subscriptions/x/resourceGroups/rg-agentx-staging/providers/Microsoft.App/containerApps/api',
      type: 'Microsoft.App/containerApps',
      name: 'api',
      apiVersion: '2026-01-01',
      location: 'uaenorth',
      tags: { product: 'agent-x', environment: 'staging', 'managed-by': 'deploy/azure' },
      properties: { configuration: { secrets: [{ name: 'db-password', value: literal }] } },
    };
    expect(brokenRules(withExtra(app))).toEqual(['no-secret-literals']);
  });

  it('no-secret-literals in a parameters file: a secure value written down, or given a default', () => {
    const text = checked.get('staging.bicepparam')?.text ?? '';
    const assignment = /^param postgresAdminPassword = .+$/m;
    expect(text).toMatch(assignment);
    for (const written of [
      "'written in the code'",
      "readEnvironmentVariable('AGENTX_AZURE_POSTGRES_ADMIN_PASSWORD', 'a default')",
    ]) {
      const problems = paramsFileProblems(
        'staging.bicepparam',
        text.replace(assignment, `param postgresAdminPassword = ${written}`),
        secure,
      );
      expect(problems.map((problem) => problem.rule)).toEqual(['no-secret-literals']);
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
    const allowApps = (group: Mutable): Mutable => inside(nth(rules(group), 0), 'properties');
    const allowItself = (group: Mutable): Mutable => inside(nth(rules(group), 1), 'properties');
    const deny = (group: Mutable): Mutable => inside(nth(rules(group), 2), 'properties');
    for (const change of [
      (group: Mutable) => (allowApps(group).sourceAddressPrefix = '10.40.0.0/16'),
      (group: Mutable) => (allowApps(group).destinationPortRange = '*'),
      (group: Mutable) => (allowApps(group).protocol = '*'),
      (group: Mutable) => (allowApps(group).destinationAddressPrefix = '*'),
      (group: Mutable) => (allowItself(group).sourceAddressPrefix = '10.40.9.0/24'),
      (group: Mutable) => (inside(group, 'properties').securityRules = [nth(rules(group), 1), nth(rules(group), 2)]),
      (group: Mutable) => (inside(group, 'properties').securityRules = [nth(rules(group), 0), nth(rules(group), 2)]),
      (group: Mutable) => (inside(group, 'properties').securityRules = [nth(rules(group), 0), nth(rules(group), 1)]),
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
    expect(brokenRules(withExtra(separateRule(DATABASE_RULES, '10.40.9.0/24', '5432')))).toEqual(['database-network']);
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

  it('log-quota-alerts: the 80% alert off its threshold or its query, or the cap alert inverted or gone', () => {
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

  it('log-destinations: a diagnostic setting that also sends to a storage account, an event hub or a partner', () => {
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
    const probes = (group: Mutable): Mutable => inside(nth(rules(group), 0), 'properties');
    const itself = (group: Mutable): Mutable => inside(nth(rules(group), 1), 'properties');
    const deny = (group: Mutable): Mutable => inside(nth(rules(group), 2), 'properties');
    for (const change of [
      (group: Mutable) => (probes(group).sourceAddressPrefix = 'Internet'),
      (group: Mutable) => (probes(group).destinationPortRange = '*'),
      (group: Mutable) => (probes(group).protocol = '*'),
      (group: Mutable) => (probes(group).destinationAddressPrefix = '*'),
      (group: Mutable) => (itself(group).sourceAddressPrefix = '10.40.0.0/16'),
      (group: Mutable) => (itself(group).destinationAddressPrefix = '*'),
      (group: Mutable) => (inside(group, 'properties').securityRules = [nth(rules(group), 1), nth(rules(group), 2)]),
      (group: Mutable) => (inside(group, 'properties').securityRules = [nth(rules(group), 0), nth(rules(group), 2)]),
      (group: Mutable) => (inside(group, 'properties').securityRules = [nth(rules(group), 0), nth(rules(group), 1)]),
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
    expect(
      brokenRules(
        changed(NETWORK, (network) => delete inside(subnet(network, 'apps'), 'properties').networkSecurityGroup),
      ),
    ).toEqual(['apps-network']);
    expect(brokenRules(without(APPS_RULES))).toEqual(['apps-network']);
    expect(brokenRules(withExtra(separateRule(APPS_RULES, 'VirtualNetwork', '*')))).toEqual(['apps-network']);
    // No apps subnet at all: the database's rule refuses it too, and the vault
    // and the environment point at a subnet that isn't there.
    expect(
      brokenRules(
        changed(NETWORK, (network) => {
          inside(network, 'properties').subnets = [subnet(network, 'database')];
        }),
      ),
    ).toEqual(['database-network', 'apps-network', 'vault', 'apps-environment']);
  });

  it('apps-logs: console or system logs kept out of the workspace, or the HTTP log sent anywhere', () => {
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
      query(
        'ContainerAppSystemLogs | where tostring(parse_json(Log).level) in ("error", "fatal", "panic") | summarize Errors = count()',
      ),
      query(
        'ContainerAppConsoleLogs | where tostring(parse_json(Log).level) in ("error", "fatal", "panic") | where ContainerAppName == "api" | summarize Errors = count()',
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
