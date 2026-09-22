import { appendFileSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import { beforeAll, describe, expect, it } from 'vitest';

import { APP_KEYS } from './app-keys.ts';
import {
  at,
  bicepGuid,
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

/**
 * Staging's resources as production's would name them: their tags and CI's
 * identity (where it is and whom its role is given to), and (unless a test
 * wants it left) CI's GitHub subject.
 */
function productionLike({ subject }: { readonly subject: boolean }): Snapshot {
  const copy = changed(
    (resource) => resource.tags !== undefined,
    (resource) => (inside(resource, 'tags').environment = 'production'),
  );
  for (const resource of copy.predictedResources as unknown as Mutable[]) {
    resource.id = String(resource.id).replace('/id-agentx-stg-release', '/id-agentx-prd-release');
    resource.name = String(resource.name).replace(/^id-agentx-stg-release/, 'id-agentx-prd-release');
    if (resource.type === 'Microsoft.Authorization/roleAssignments') {
      const grant = resource.properties as Mutable;
      grant.principalId = String(grant.principalId).replace('/id-agentx-stg-release', '/id-agentx-prd-release');
    }
    if (subject && resource.type === 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials') {
      const trust = resource.properties as Mutable;
      trust.subject = String(trust.subject).replace(/:environment:staging$/, ':environment:production');
    }
  }
  return copy;
}

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
const INTEGRITY_ALERT = named(/-audit-integrity$/);
const ACTION_GROUP = type('Microsoft.Insights/actionGroups');
const BUDGET = type('Microsoft.Consumption/budgets');
const ALERTS = type('Microsoft.Insights/scheduledQueryRules');
const LOGIN_ALERT = named(/-privileged-login$/);
const OWNER_ALERT = named(/-owner-login$/);
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
const DOOR = type('Microsoft.App/managedEnvironments/httpRouteConfigs');
const CERTIFICATE = type('Microsoft.App/managedEnvironments/managedCertificates');
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
/** Changes to a SEV-1 alert's timing that leave minutes unwatched, or make it wait for more than one window. */
const LATE_OR_BLIND: readonly ((alert: Mutable) => void)[] = [
  (alert) => (inside(alert, 'properties').windowSize = 'PT5M'),
  (alert) => (inside(alert, 'properties').evaluationFrequency = 'PT30M'),
  (alert) => (inside(criterion(alert), 'failingPeriods').minFailingPeriodsToAlert = 3),
  (alert) => (inside(criterion(alert), 'failingPeriods').numberOfEvaluationPeriods = 3),
];
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

/** Azure refuses a network rule whose description is longer (preflight: SecurityRuleDescriptionTooLong). */
const RULE_DESCRIPTION_LIMIT = 140;

/** The names of every network rule in a snapshot whose description Azure would refuse. */
const overLongRuleDescriptions = (snapshotted: Snapshot): string[] =>
  snapshotted.predictedResources
    .filter(RULES)
    .flatMap((group) => (at(group.properties, 'securityRules') as Mutable[] | undefined) ?? [])
    .filter((rule) => {
      const description = at(rule, 'properties', 'description');
      return typeof description === 'string' && description.length > RULE_DESCRIPTION_LIMIT;
    })
    .map((rule) => String(rule.name));

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
  it('has staging, its foundation and its parts, and every file lints clean with every linter rule an error', () => {
    expect([...deployed.keys()]).toEqual(['staging']);
    expect([...params.keys()]).toEqual([
      'staging.apps.bicepparam',
      'staging.bicepparam',
      'staging.certificates.bicepparam',
      'staging.secrets.bicepparam',
    ]);
    expect([...params.values()].map((entry) => entry.deploys)).toEqual([
      'apps.bicep',
      'main.bicep',
      'certificates.bicep',
      'secrets.bicep',
    ]);
    expect([...bicepFiles.keys()]).toEqual([
      'apps.bicep',
      'certificates.bicep',
      'main.bicep',
      'names.bicep',
      'secrets.bicep',
    ]);
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
      'appKeyValues',
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

  it("stays within the limits Azure's own preflight enforces, which no linter checks", () => {
    // The first dry run against a real subscription (G3a) refused two rule
    // descriptions over 140 characters; no offline check had seen them.
    for (const [environment, { together }] of deployed) {
      expect({ environment, tooLong: overLongRuleDescriptions(together) }).toEqual({ environment, tooLong: [] });
    }
    const longer = changed(APPS_RULES, (group) => {
      ruleNamed(group, 'allow-within-subnet').description = 'x'.repeat(RULE_DESCRIPTION_LIMIT + 1);
    });
    expect(overLongRuleDescriptions(longer)).toEqual(['allow-within-subnet']);
    const atTheLimit = changed(APPS_RULES, (group) => {
      ruleNamed(group, 'allow-within-subnet').description = 'x'.repeat(RULE_DESCRIPTION_LIMIT);
    });
    expect(overLongRuleDescriptions(atTheLimit)).toEqual([]);
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
      expect.stringMatching(/\/configurations psql-agentx-stg-[a-z0-9]{6}\/log_line_prefix$/),
      'Microsoft.Insights/diagnosticSettings logs-to-workspace',
      expect.stringMatching(
        /^Microsoft\.Insights\/scheduledQueryRules alert-psql-agentx-stg-[a-z0-9]{6}-privileged-login$/,
      ),
      expect.stringMatching(/^Microsoft\.Insights\/scheduledQueryRules alert-psql-agentx-stg-[a-z0-9]{6}-owner-login$/),
      'Microsoft.App/managedEnvironments cae-agentx-staging',
      'Microsoft.Insights/diagnosticSettings app-logs-to-workspace',
      ...['api', 'zitadel', 'login', 'db-setup', 'migrate', 'zitadel-init', 'zitadel-setup', 'operator'].map(
        (workload) => `Microsoft.ManagedIdentity/userAssignedIdentities id-agentx-stg-${workload}`,
      ),
      'Microsoft.OperationalInsights/workspaces/savedSearches log-agentx-stg/agentx-errors-by-type',
      'Microsoft.Insights/scheduledQueryRules alert-agentx-stg-app-errors',
      'Microsoft.Insights/scheduledQueryRules alert-agentx-stg-audit-integrity',
      'Microsoft.ManagedIdentity/userAssignedIdentities id-agentx-stg-release',
      'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials id-agentx-stg-release/github',
      expect.stringMatching(
        /^Microsoft\.Authorization\/roleDefinitions [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
      ),
    ]);
  });

  it("writes the secrets, each only when given but the master key and the app's keys, and lets each app and job read its own", () => {
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
      ...APP_KEYS.map((key) => `${key} once`),
      ...[
        'db-setup reads db-admin-password',
        'db-setup reads db-owner-password',
        'migrate reads db-owner-password',
        'db-setup reads db-app-password',
        'api reads db-app-password',
        'operator reads db-app-password',
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
        // The operator's command reads the audit chains' MAC too, each version (B1c).
        ...APP_KEYS.flatMap((key) =>
          key.startsWith('key-audit-mac-v') ? [`api reads ${key}`, `operator reads ${key}`] : [`api reads ${key}`],
        ),
      ].map((grant) => `${grant} (deploy/azure/secrets.bicep)`),
    ]);
  });

  it('compiles a rotation run, one secret given and every other empty, and refuses one without a master key', () => {
    const text = params.get('staging.secrets.bicepparam')?.text ?? '';
    const variables = [...text.matchAll(/readEnvironmentVariable\('([A-Z0-9_]+)'\)/g)].map((match) => match[1] ?? '');
    expect(variables).toHaveLength(10);
    // The API's login given; every other secret set but empty, so left as the vault has it; the master key a
    // fresh 32 characters and the app's keys fresh too, which Azure leaves alone once they exist. Empty values
    // reach Bicep from Node, as G3's tool sends them.
    const everyRun = ['AGENTX_AZURE_DB_APP_PASSWORD', 'AGENTX_AZURE_ZITADEL_MASTERKEY', 'AGENTX_AZURE_APP_KEYS'];
    const kept = Object.fromEntries(variables.filter((name) => !everyRun.includes(name)).map((name) => [name, '']));
    inCopy((dir) => {
      const rotation = environmentSnapshot(dir, 'staging', kept).together;
      expect(policyProblems(rotation, STAGING).map(describeProblem)).toEqual([]);
      expect(rotation.predictedResources.filter(SECRETS)).toHaveLength(9 + APP_KEYS.length);
      // The keys must come every run too: without them the run stops before Azure.
      expect(() => environmentSnapshot(dir, 'staging', { ...kept, AGENTX_AZURE_APP_KEYS: '' })).toThrow();
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
    // Without the environment there is nowhere of ours for the jobs to run, no
    // platform lines for the owner-login alert to pair with, and the doors and
    // their certificates belong to no environment of ours.
    expect(brokenRules(without((resource) => ENVIRONMENT(resource) || APP_LOGS(resource)))).toEqual([
      'required',
      'owner-login-alert',
      'jobs',
      'apps',
      'public-doors',
      'door-certificates',
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

  it("no-secret-literals and vault-secrets: each of the app's keys holds its own value and is created once", () => {
    // Names built here, so no line pairs a secret-named call with a key's vault name (scanner bait, PR #67).
    const keyNamed = (purpose: string): string => `key-${purpose}-v1`;
    const auditMac = SECRET(keyNamed('audit-mac'));
    const member = (name: string): string => `[json(parameters('appKeyValues'))['${name}']]`;
    // Another key's value would make two keys one; a value in the code is no key at all.
    expect(
      brokenRules(
        changed(auditMac, (secret) => (inside(secret, 'properties').value = member(keyNamed('request-hash')))),
      ),
    ).toEqual(['no-secret-literals']);
    expect(
      brokenRules(changed(auditMac, (secret) => (inside(secret, 'properties').value = 'written in the code'))),
    ).toEqual(['no-secret-literals']);
    // The form is the keys' alone: a login still comes from a parameter of its own.
    expect(
      brokenRules(
        changed(
          SECRET('db-app-password'),
          (secret) => (inside(secret, 'properties').value = member('db-app-password')),
        ),
      ),
    ).toEqual(['no-secret-literals']);
    // Written whenever a value is given, as a login is, a key would change on every run.
    expect(
      brokenRules(changed(auditMac, (secret) => (secret.condition = "[not(empty(parameters('appKeyValues')))]"))),
    ).toEqual(['vault-secrets']);
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
    // A line that starts some other way is one the alert doesn't match.
    expect(
      brokenRules(changed(setting('log_line_prefix'), (entry) => (inside(entry, 'properties').value = '%m [%p] '))),
    ).toEqual(['database-logins']);
    expect(brokenRules(without(LOGIN_ALERT))).toEqual(['database-logins']);
    // The pattern without the line's start, as it was until the first real run (S19).
    expect(
      brokenRules(
        changed(
          LOGIN_ALERT,
          (alert) =>
            (criterion(alert).query = String(criterion(alert).query).replace(
              /@"\^[^"]*?connection authorized/,
              '@"^connection authorized',
            )),
        ),
      ),
    ).toEqual(['database-logins']);
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
    for (const change of LATE_OR_BLIND) {
      expect(brokenRules(changed(LOGIN_ALERT, change))).toEqual(['database-logins']);
    }
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

  it('SEC-OPS-09 the login alert matches the lines Postgres 18 on Azure writes, and no others (S19)', () => {
    const query = String(criterion(staging.predictedResources.find(LOGIN_ALERT) as unknown as Mutable).query);
    const source = /matches regex @"([^"]+)"/.exec(query)?.[1];
    expect(source).toBeDefined();
    // Kusto's regular expressions are RE2; this pattern uses nothing JavaScript reads differently.
    const pattern = new RegExp(source ?? '(?!)');
    // A line as the set-up job's login wrote it on the first real run, the session and role filled in here.
    const line = (message: string, session = '6aaae7b4.1dc3') => `2026-09-16 19:02:12 UTC-${session}-LOG:  ${message}`;
    const authorized = (role: string) =>
      `connection authorized: user=${role} database=postgres application_name=agentx-db-setup SSL enabled (protocol=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384, bits=256)`;
    for (const role of ['agentx_admin', 'agentx_backup']) {
      expect(line(authorized(role))).toMatch(pattern);
      expect(line(authorized(role), '6aaae7b4.1dc4')).toMatch(pattern);
    }
    for (const other of [
      line(authorized('agentx_app')),
      line(authorized('azuresu')),
      line(authorized('agentx_administrator')),
      line('connection authenticated: identity="agentx_admin" method=md5 (/datadrive/pg/data/pg_hba.conf:29)'),
      line(`statement: SELECT '${authorized('agentx_admin')}'`),
      authorized('agentx_admin'),
    ]) {
      expect(other).not.toMatch(pattern);
    }
  });

  it("owner-login-alert: no alert on the owner's logins, or one that can't fire, misjudges a deploy, or fires too late or too quietly", () => {
    const properties = (alert: Mutable): Mutable => inside(alert, 'properties');
    const edited = (from: string | RegExp, to: string) => (alert: Mutable) => {
      const before = String(criterion(alert).query);
      criterion(alert).query = before.replace(from, to);
      expect(criterion(alert).query).not.toBe(before);
    };
    expect(brokenRules(without(OWNER_ALERT))).toEqual(['owner-login-alert']);
    for (const change of [
      // Another role's logins, or another job's starts, or another deployment's, or any environment's.
      edited('user=agentx_owner ', 'user=agentx_app '),
      edited('user=agentx_owner ', 'user=agentx_owner'),
      edited('"job-agentx-stg-migrate"', '"job-agentx-stg-db-setup"'),
      edited('"job-agentx-stg-migrate"', '"job-agentx-prd-migrate"'),
      edited('Reason == "ContainerStarted"', 'Reason == "Completed"'),
      edited(
        /_ResourceId =~ "[^"]+"/,
        '_ResourceId =~ "/subscriptions/x/resourceGroups/y/providers/Microsoft.App/managedEnvironments/z"',
      ),
      edited(/_ResourceId =~ "[^"]+" and /, ''),
      // A looser pairing: a wider "near", a second login beside one start let
      // through, or a start with no login (which is also how login lines the
      // pattern stopped matching would show) let through.
      edited('let near = 2m;', 'let near = 15m;'),
      edited('| where Gap > near or Claims > 1', '| where Gap > near'),
      edited('join kind=leftouter claims', 'join kind=inner claims'),
      edited('union strays, unclaimed', 'union strays'),
      edited('join kind=leftanti claims', 'join kind=leftsemi claims'),
      // A band judged too soon (before Azure's lines for the job arrive), or one a run can miss.
      edited('ago(20m)', 'ago(5m)'),
      edited('ago(50m)', 'ago(30m)'),
      (alert: Mutable) => (criterion(alert).threshold = 1),
      (alert: Mutable) => (criterion(alert).operator = 'LessThan'),
      ...LATE_OR_BLIND,
      // Reading less than the hour, or running less often than the band needs.
      (alert: Mutable) => (properties(alert).overrideQueryTimeRange = 'PT30M'),
      (alert: Mutable) => delete properties(alert).overrideQueryTimeRange,
      (alert: Mutable) => {
        properties(alert).evaluationFrequency = 'PT30M';
        properties(alert).windowSize = 'PT30M';
      },
      (alert: Mutable) => (properties(alert).scopes = ['/subscriptions/x/workspaces/y']),
    ]) {
      expect(brokenRules(changed(OWNER_ALERT, change))).toEqual(['owner-login-alert']);
    }
    // Quieter than SEV-1, or stateful, or off: the general alert rules object too.
    expect(brokenRules(changed(OWNER_ALERT, (alert) => (properties(alert).severity = 2)))).toEqual([
      'alert-runbook',
      'owner-login-alert',
    ]);
    expect(brokenRules(changed(OWNER_ALERT, (alert) => (properties(alert).autoMitigate = true)))).toEqual([
      'alert-delivery',
      'owner-login-alert',
    ]);
    expect(brokenRules(changed(OWNER_ALERT, (alert) => (properties(alert).enabled = false)))).toEqual([
      'alert-delivery',
      'owner-login-alert',
    ]);
    // The job it pairs with must be this deployment's, and only one.
    expect(brokenRules(without(JOB('migrate')))).toContain('owner-login-alert');
    // A second job by the same name, in another resource group: which one's starts would count?
    const twice = structuredClone(staging.predictedResources.find(JOB('migrate'))) as unknown as Mutable;
    twice.id = String(twice.id).replace('/resourceGroups/rg-agentx-staging/', '/resourceGroups/rg-other/');
    expect(twice.id).not.toBe(staging.predictedResources.find(JOB('migrate'))?.id);
    expect(brokenRules(withExtra(twice))).toContain('owner-login-alert');
    // The same for the environment whose platform lines it reads.
    const second = structuredClone(staging.predictedResources.find(ENVIRONMENT)) as unknown as Mutable;
    second.id = String(second.id).replace(/cae-agentx-staging$/, 'cae-agentx-other');
    second.name = 'cae-agentx-other';
    expect(brokenRules(withExtra(second))).toContain('owner-login-alert');
  });

  it('SEC-DB-04 the owner-login alert matches the lines Postgres 18 on Azure writes for the owner, and no others (S33)', () => {
    const query = String(criterion(staging.predictedResources.find(OWNER_ALERT) as unknown as Mutable).query);
    const source = /matches regex @"([^"]+)"/.exec(query)?.[1];
    expect(source).toBeDefined();
    // Kusto's regular expressions are RE2; this pattern uses nothing JavaScript reads differently.
    const pattern = new RegExp(source ?? '(?!)');
    // A line as the migration job's login wrote it on staging (20 Sep, S33), the session and role filled in here.
    const line = (message: string, session = '6ab011c5.8f4ee') => `2026-09-20 17:03:01 UTC-${session}-LOG:  ${message}`;
    const authorized = (role: string, database = 'agentx') =>
      `connection authorized: user=${role} database=${database} application_name=agentx-migrate SSL enabled (protocol=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384, bits=256)`;
    expect(line(authorized('agentx_owner'))).toMatch(pattern);
    // Whatever the session, the database or the name the client gives itself.
    expect(line(authorized('agentx_owner', 'postgres'), '6ab01234.1')).toMatch(pattern);
    expect(line(authorized('agentx_owner').replace('agentx-migrate', 'psql'))).toMatch(pattern);
    for (const other of [
      line(authorized('agentx_app')),
      line(authorized('agentx_admin')),
      line(authorized('agentx_backup')),
      line(authorized('agentx_owner2')),
      line('connection authenticated: identity="agentx_owner" method=md5 (/datadrive/pg/data/pg_hba.conf:29)'),
      line('disconnection: session time: 0:00:00.077 user=agentx_owner database=agentx host=10.40.0.16 port=10007'),
      line(`statement: SELECT '${authorized('agentx_owner')}'`),
      authorized('agentx_owner'),
    ]) {
      expect(other).not.toMatch(pattern);
    }
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
    const production = productionLike({ subject: true });
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
    // The playbook's sections run from A to J.
    const inSection = (section: string) => (alert: Mutable) => {
      const before = String(properties(alert).description);
      properties(alert).description = before.replace(/section [A-Z]\.$/, `section ${section}.`);
      expect(properties(alert).description).not.toBe(before);
    };
    expect(brokenRules(changed(CAP_ALERT, inSection('A')))).toEqual([]);
    expect(brokenRules(changed(CAP_ALERT, inSection('K')))).toEqual(['alert-runbook']);
    // The log cap's own section (T1c): section D is about dependencies.
    for (const pick of [CAP_ALERT, QUOTA_ALERT]) {
      const description = String(at(staging.predictedResources.find(pick)?.properties, 'description'));
      expect(description).toMatch(/ Runbook: Incident-Response-Playbook\.md section J\.$/);
    }
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
    // A SEV-1 alert muted after it fires tells nobody of the next window; a
    // SEV-2 one may be.
    for (const sev1 of [LOGIN_ALERT, OWNER_ALERT, INTEGRITY_ALERT]) {
      expect(brokenRules(changed(sev1, (alert) => (properties(alert).muteActionsDuration = 'PT1H')))).toEqual([
        'alert-delivery',
      ]);
    }
    expect(brokenRules(changed(CAP_ALERT, (alert) => (properties(alert).muteActionsDuration = 'PT1H')))).toEqual([]);
    // A second condition that never holds keeps the whole alert from firing.
    for (const alert of [LOGIN_ALERT, OWNER_ALERT, CAP_ALERT]) {
      expect(
        brokenRules(
          changed(alert, (entry) => {
            const conditions = at(entry, 'properties', 'criteria', 'allOf') as Mutable[];
            conditions.push({ ...structuredClone(first(conditions)), threshold: 1_000_000 });
          }),
        ),
      ).toEqual(['alert-delivery']);
    }
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

  it("audit-integrity-alert: no alert on the integrity alarm, or one that can't fire, or fires too late or too quietly", () => {
    const properties = (alert: Mutable): Mutable => inside(alert, 'properties');
    const query = (text: string) => (alert: Mutable) => (criterion(alert).query = text);
    const counted = (filter: string) => query(`ContainerAppConsoleLogs | ${filter} | summarize Events = count()`);
    expect(brokenRules(without(INTEGRITY_ALERT))).toEqual(['audit-integrity-alert']);
    for (const change of [
      // A check that broke is the alarm too, not just a chain that failed.
      counted('where tostring(parse_json(Log).event) == "audit.integrity_failed"'),
      counted('where tostring(parse_json(Log).event) in ("audit.anchor_check_crashed")'),
      counted(
        'where tostring(parse_json(Log).event) in ("audit.integrity_failed", "audit.anchor_check_crashed") | where ContainerAppName == "api"',
      ),
      query(
        'ContainerAppSystemLogs | where tostring(parse_json(Log).event) in ("audit.integrity_failed", "audit.anchor_check_crashed") | summarize Events = count()',
      ),
      // One line is enough, seen in any minute.
      (alert: Mutable) => (criterion(alert).threshold = 1),
      ...LATE_OR_BLIND,
      (alert: Mutable) => (criterion(alert).operator = 'LessThan'),
      (alert: Mutable) => (properties(alert).scopes = ['/subscriptions/x/workspaces/y']),
    ]) {
      expect(brokenRules(changed(INTEGRITY_ALERT, change))).toEqual(['audit-integrity-alert']);
    }
    // Quieter than SEV-1, or stateful, or off: the general alert rules object too.
    expect(brokenRules(changed(INTEGRITY_ALERT, (alert) => (properties(alert).severity = 2)))).toEqual([
      'alert-runbook',
      'audit-integrity-alert',
    ]);
    expect(brokenRules(changed(INTEGRITY_ALERT, (alert) => (properties(alert).autoMitigate = true)))).toEqual([
      'alert-delivery',
      'audit-integrity-alert',
    ]);
    expect(brokenRules(changed(INTEGRITY_ALERT, (alert) => (properties(alert).enabled = false)))).toEqual([
      'alert-delivery',
      'audit-integrity-alert',
    ]);
  });

  it('identities: one usable in any region', () => {
    expect(
      brokenRules(
        changed(named(/^id-agentx-stg-api$/), (identity) => (inside(identity, 'properties').isolationScope = 'None')),
      ),
    ).toEqual(['identities']);
    expect(brokenRules(changed(IDENTITIES, (identity) => delete identity.properties))).toEqual(['identities']);
  });

  it('release-identity: CI trusted for another subject, on another identity, or given a role wider than an image update', () => {
    // The rule's own messages, so a condition another one also catches can't hide.
    const releaseProblems = (snapshotted: Snapshot, expected = STAGING): string[] =>
      policyProblems(snapshotted, expected)
        .filter((problem) => problem.rule === 'release-identity')
        .map((problem) => `${problem.resource}: ${problem.message}`);
    const TRUST = type('Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials');
    const ROLE = type('Microsoft.Authorization/roleDefinitions');
    const RELEASE = named(/^id-agentx-stg-release$/);
    const subject = 'repo:shahbaz242630@205810405/agent-x@1368211207:environment:staging';
    const trust = 'id-agentx-stg-release/github';
    const trustIn = (resource: Mutable): Mutable => inside(resource, 'properties');
    const permissionsOf = (role: Mutable): Mutable => first(at(role, 'properties', 'permissions'));
    const role = String(staging.predictedResources.find(ROLE)?.name);
    const group = String(staging.predictedResources.find(type('Microsoft.Resources/resourceGroups'))?.id);

    expect(staging.predictedResources.filter(TRUST).map((found) => [found.name, found.properties])).toEqual([
      [
        trust,
        {
          issuer: 'https://token.actions.githubusercontent.com',
          subject,
          audiences: ['api://AzureADTokenExchange'],
        },
      ],
    ]);
    expect(staging.predictedResources.filter(RELEASE).map((found) => found.properties)).toEqual([
      { isolationScope: 'Regional' },
    ]);
    expect(at(staging.predictedResources.find(ROLE)?.properties, 'assignableScopes')).toEqual([group]);
    expect(releaseProblems(staging)).toEqual([]);

    // Another subject: the old form without IDs, a branch, a pull request, or another environment's.
    for (const other of [
      'repo:shahbaz242630/agent-x:environment:staging',
      'repo:shahbaz242630@205810405/agent-x@1368211207:ref:refs/heads/main',
      'repo:shahbaz242630@205810405/agent-x@1368211207:pull_request',
      'repo:shahbaz242630@205810405/agent-x@1368211207:environment:production',
    ]) {
      expect(releaseProblems(changed(TRUST, (found) => (trustIn(found).subject = other)))).toEqual([
        `${trust}: must trust ${subject} alone (a job in this environment's GitHub environment); it trusts ${JSON.stringify(other)}`,
      ]);
    }
    // Production's deployment must name production's GitHub environment, and staging's identity isn't production's.
    const production = { region: 'uaenorth', environment: 'production' } as const;
    expect(releaseProblems(productionLike({ subject: false }), production)).toEqual([
      `id-agentx-prd-release/github: must trust ${subject.replace(/staging$/, 'production')} alone (a job in this environment's GitHub environment); it trusts ${JSON.stringify(subject)}`,
    ]);
    expect(releaseProblems(productionLike({ subject: true }), production)).toEqual([]);
    expect(releaseProblems(staging, production)).toEqual([
      'the deployment: needs an identity for CI (id-agentx-prd-release)',
      `${trust}: must be on CI's identity: no other identity is signed in to from outside Azure`,
      `${trust}: must trust ${subject.replace(/staging$/, 'production')} alone (a job in this environment's GitHub environment); it trusts ${JSON.stringify(subject)}`,
    ]);
    // Another issuer, or an audience besides the token exchange.
    expect(
      releaseProblems(changed(TRUST, (found) => (trustIn(found).issuer = 'https://token.actions.example.invalid'))),
    ).toEqual([
      `${trust}: must trust https://token.actions.githubusercontent.com alone; it trusts "https://token.actions.example.invalid"`,
    ]);
    for (const audiences of [['api://AzureADTokenExchange', 'api://other'], ['api://other'], []]) {
      expect(releaseProblems(changed(TRUST, (found) => (trustIn(found).audiences = audiences)))).toEqual([
        `${trust}: must accept the audience api://AzureADTokenExchange alone; it accepts ${JSON.stringify(audiences)}`,
      ]);
    }
    // A trust on an app's identity, whose secrets it would hand to GitHub, or on one whose name only starts like CI's.
    const api = staging.predictedResources.find(named(/^id-agentx-stg-api$/));
    const release = staging.predictedResources.find(RELEASE);
    for (const identity of [String(api?.id), `${String(release?.id)}2`]) {
      expect(
        releaseProblems(
          changed(TRUST, (found) => {
            found.id = `${identity}/federatedIdentityCredentials/github`;
          }),
        ),
      ).toEqual([`${trust}: must be on CI's identity: no other identity is signed in to from outside Azure`]);
    }
    // Nor on CI's identity's namesake in another resource group.
    const namesake = String(release?.id).replace('/resourceGroups/rg-agentx-staging/', '/resourceGroups/elsewhere/');
    const onNamesake = withExtra({ ...structuredClone(release), id: namesake });
    for (const found of onNamesake.predictedResources.filter(TRUST)) {
      (found as unknown as Mutable).id = `${namesake}/federatedIdentityCredentials/github`;
    }
    expect(releaseProblems(onNamesake)).toEqual([
      `${trust}: must be on CI's identity: no other identity is signed in to from outside Azure`,
    ]);
    // No trust, two, or no identity for CI.
    expect(releaseProblems(without(TRUST))).toEqual([
      "the deployment: needs one trust, for CI's identity; the snapshot has 0",
    ]);
    const second = structuredClone(staging.predictedResources.find(TRUST)) as unknown as Mutable;
    expect(releaseProblems(withExtra(second))).toEqual([
      "the deployment: needs one trust, for CI's identity; the snapshot has 2",
    ]);
    expect(releaseProblems(without(RELEASE))).toEqual([
      'the deployment: needs an identity for CI (id-agentx-stg-release)',
      `${trust}: must be on CI's identity: no other identity is signed in to from outside Azure`,
    ]);
    // Only this environment's name counts: production's CI identity, or one named plainly, is not staging's.
    for (const other of ['id-agentx-prd-release', 'release']) {
      const moved = changed(RELEASE, (identity) => {
        identity.name = other;
        identity.id = String(identity.id).replace(/id-agentx-stg-release$/, other);
      });
      for (const found of moved.predictedResources.filter(TRUST)) {
        (found as unknown as Mutable).id = found.id.replace('/id-agentx-stg-release/', `/${other}/`);
      }
      expect(releaseProblems(moved)).toEqual([
        'the deployment: needs an identity for CI (id-agentx-stg-release)',
        `${trust}: must be on CI's identity: no other identity is signed in to from outside Azure`,
      ]);
    }
    // An app or a job running as CI's identity would hold CI's role, whatever case its id is written in.
    for (const pick of [JOB('migrate'), APP('api'), APP('zitadel')]) {
      for (const id of [String(release?.id), String(release?.id).toUpperCase()]) {
        const running = changed(pick, (workload) => {
          const assigned = inside(workload, 'identity', 'userAssignedIdentities');
          assigned[id] = {};
        });
        const name = String(staging.predictedResources.find(pick)?.name);
        expect(releaseProblems(running)).toEqual([`${name}: must not run as CI's identity, whose role is CI's alone`]);
      }
    }

    // The role: an action more (a secret's list, a shell, a door), one less, or every action.
    const wanted = at(
      permissionsOf(staging.predictedResources.find(ROLE) as unknown as Mutable),
      'actions',
    ) as string[];
    for (const actions of [
      [...wanted, 'Microsoft.App/containerApps/listSecrets/action'],
      [...wanted, 'Microsoft.App/containerApps/exec/action'],
      [...wanted, 'Microsoft.App/managedEnvironments/httpRouteConfigs/write'],
      [...wanted, 'Microsoft.Authorization/roleAssignments/write'],
      // The two linked actions, which CI's partial update doesn't ask for.
      [...wanted, 'Microsoft.App/managedEnvironments/join/action'],
      [...wanted, 'Microsoft.ManagedIdentity/userAssignedIdentities/assign/action'],
      wanted.slice(1),
      ['*'],
      ['Microsoft.App/*', 'Microsoft.ManagedIdentity/userAssignedIdentities/assign/action'],
    ]) {
      expect(releaseProblems(changed(ROLE, (found) => (permissionsOf(found).actions = actions)))).toEqual([
        `${role}: must allow exactly ${wanted.join(', ')}; it allows ${actions.join(', ')}`,
      ]);
    }
    // A second block of permissions counts too.
    expect(
      releaseProblems(
        changed(ROLE, (found) => {
          (at(found, 'properties', 'permissions') as Mutable[]).push({ actions: ['Microsoft.App/jobs/delete'] });
        }),
      ),
    ).toEqual([
      `${role}: must allow exactly ${wanted.join(', ')}; it allows ${[...wanted, 'Microsoft.App/jobs/delete'].join(', ')}`,
    ]);
    // Azure compares actions without case or order, so another case, order or a repeat is the same role.
    for (const actions of [[...wanted.map((action) => action.toLowerCase()), wanted[0]], [...wanted].reverse()]) {
      expect(releaseProblems(changed(ROLE, (found) => (permissionsOf(found).actions = actions)))).toEqual([]);
    }
    // A data action, which reaches into a resource's data (a secret's value).
    const secretValue = 'Microsoft.KeyVault/vaults/secrets/getSecret/action';
    expect(releaseProblems(changed(ROLE, (found) => (permissionsOf(found).dataActions = [secretValue])))).toEqual([
      `${role}: must allow no data action, which could read a secret's value; it allows ${secretValue}`,
    ]);
    // Assignable anywhere but this resource group.
    const subscriptionScope = group.slice(0, group.indexOf('/resourceGroups/'));
    for (const scopes of [[subscriptionScope], [group, subscriptionScope], [`${group}-other`], []]) {
      expect(
        releaseProblems(changed(ROLE, (found) => (inside(found, 'properties').assignableScopes = scopes))),
      ).toEqual([
        `${role}: must be assignable in this deployment's resource group alone; it says ${JSON.stringify(scopes)}`,
      ]);
    }
    // No custom role, or two.
    expect(releaseProblems(without(ROLE))).toEqual(["the deployment: needs one custom role, CI's; the snapshot has 0"]);
    const another = structuredClone(staging.predictedResources.find(ROLE)) as unknown as Mutable;
    expect(releaseProblems(withExtra(another))).toEqual([
      "the deployment: needs one custom role, CI's; the snapshot has 2",
    ]);
    // An identity for CI that any region may use is the generic rule's to refuse.
    expect(brokenRules(changed(RELEASE, (found) => (inside(found, 'properties').isolationScope = 'None')))).toEqual([
      'identities',
    ]);
  });

  it('release-access: CI given its role on anything but the API app and the migration job, to anyone else, or not once', () => {
    // The rule's own messages, so a condition another one also catches can't hide.
    const accessProblems = (snapshotted: Snapshot): string[] =>
      policyProblems(snapshotted, STAGING)
        .filter((problem) => problem.rule === 'release-access')
        .map((problem) => `${problem.resource}: ${problem.message}`);
    // A lookup that finds nothing fails here, so no case below passes on a scope or principal that isn't there.
    const idOf = (pick: (resource: PredictedResource) => boolean): string => {
      const found = staging.predictedResources.find(pick);
      if (found === undefined) throw new Error('the snapshot has no such resource');
      return found.id;
    };
    const group = idOf(type('Microsoft.Resources/resourceGroups'));
    const subscription = group.slice(0, group.indexOf('/resourceGroups/'));
    const role = String(staging.predictedResources.find(type('Microsoft.Authorization/roleDefinitions'))?.name);
    const roleId = `${subscription}/providers/Microsoft.Authorization/roleDefinitions/${role}`;
    const marker = '/providers/Microsoft.Authorization/roleAssignments/';
    const scopeOf = (assignment: PredictedResource): string => assignment.id.slice(0, assignment.id.indexOf(marker));
    const GIVES_ROLE = (resource: PredictedResource) =>
      ASSIGNMENTS(resource) && at(resource.properties, 'roleDefinitionId') === roleId;
    const GRANT_ON = (pick: (resource: PredictedResource) => boolean) => (resource: PredictedResource) =>
      GIVES_ROLE(resource) && scopeOf(resource) === idOf(pick);
    const API_GRANT = GRANT_ON(APP('api'));
    const MIGRATE_GRANT = GRANT_ON(JOB('migrate'));
    const properties = (assignment: Mutable): Mutable => inside(assignment, 'properties');
    const principal = (identity: string): string =>
      `[reference('${idOf(named(new RegExp(`^${identity}$`)))}', '2024-11-30').principalId]`;
    const scoped = (scope: string) => (assignment: Mutable) =>
      (assignment.id = `${scope}${marker}${String(assignment.name)}`);
    const grantName = String(staging.predictedResources.find(API_GRANT)?.name);
    const alone = (name: string): string =>
      `${name}: must give CI's role to CI's identity (principalType ServicePrincipal) on the API app or the migration job alone`;
    const given = (name: string, times: number): string =>
      `the deployment: must give CI's role on ${name} once; it gives it ${String(times)} times`;

    // On the API app and the migration job, to CI's identity, by the role's subscription-level id.
    expect(
      Object.fromEntries(
        staging.predictedResources.filter(GIVES_ROLE).map((found) => [scopeOf(found), found.properties]),
      ),
    ).toEqual({
      [idOf(APP('api'))]: {
        description: 'CI updates the API to a new image (deploy/azure/apps.bicep)',
        roleDefinitionId: roleId,
        principalId: principal('id-agentx-stg-release'),
        principalType: 'ServicePrincipal',
      },
      [idOf(JOB('migrate'))]: {
        description: 'CI updates the migration job to a new image and runs it (deploy/azure/apps.bicep)',
        roleDefinitionId: roleId,
        principalId: principal('id-agentx-stg-release'),
        principalType: 'ServicePrincipal',
      },
    });
    expect(accessProblems(staging)).toEqual([]);

    // Given anywhere else: Zitadel, its login pages, the set-up job (the server
    // admin's login), Zitadel's setup, the environment, a door, the vault, a
    // secret, an identity, the resource group, the subscription.
    for (const scope of [
      idOf(APP('zitadel')),
      idOf(APP('login')),
      idOf(JOB('db-setup')),
      idOf(JOB('zitadel-setup')),
      idOf(ENVIRONMENT),
      idOf(DOOR),
      idOf(VAULT),
      idOf(SECRET('db-owner-password')),
      idOf(named(/^id-agentx-stg-api$/)),
      group,
      subscription,
    ]) {
      expect(accessProblems(changed(API_GRANT, scoped(scope)))).toEqual([
        alone(grantName),
        given('ca-agentx-stg-api', 0),
      ]);
    }
    // To anyone but CI: the API's own identity (which would then update itself),
    // the migration job's, someone outside, or as a user.
    for (const change of [
      (grant: Mutable) => (properties(grant).principalId = principal('id-agentx-stg-api')),
      (grant: Mutable) => (properties(grant).principalId = principal('id-agentx-stg-migrate')),
      (grant: Mutable) => (properties(grant).principalId = '00000000-0000-0000-0000-00000000abcd'),
      (grant: Mutable) => (properties(grant).principalType = 'User'),
      (grant: Mutable) => delete properties(grant).principalType,
    ]) {
      expect(accessProblems(changed(API_GRANT, change))).toEqual([alone(grantName), given('ca-agentx-stg-api', 0)]);
    }
    // An app named like the migration job isn't it: the grant belongs on the job.
    const lookalike = changed(APP('zitadel'), (app) => {
      app.name = 'ca-agentx-stg-migrate';
      app.id = String(app.id).replace(/ca-agentx-stg-zitadel$/, 'ca-agentx-stg-migrate');
    });
    const migrateGrant = lookalike.predictedResources.find(MIGRATE_GRANT) as unknown as Mutable;
    scoped(String(lookalike.predictedResources.find(APP('migrate'))?.id))(migrateGrant);
    expect(accessProblems(lookalike)).toEqual([alone(String(migrateGrant.name)), given('job-agentx-stg-migrate', 0)]);
    // Not given, or given twice.
    expect(accessProblems(without(MIGRATE_GRANT))).toEqual([given('job-agentx-stg-migrate', 0)]);
    const twice = structuredClone(staging.predictedResources.find(API_GRANT)) as unknown as Mutable;
    twice.name = 'a-second-grant';
    scoped(idOf(APP('api')))(twice);
    expect(accessProblems(withExtra(twice))).toEqual([given('ca-agentx-stg-api', 2)]);
    // The role by the id its resource group would give it, which isn't the one
    // Azure keeps it under: then it's no role of ours, and `secret-access` refuses it.
    const groupForm = changed(API_GRANT, (grant) => {
      properties(grant).roleDefinitionId = `${group}/providers/Microsoft.Authorization/roleDefinitions/${role}`;
    });
    expect(accessProblems(groupForm)).toEqual([given('ca-agentx-stg-api', 0)]);
    expect(brokenRules(groupForm)).toEqual(['release-access', 'secret-access']);
    // Azure compares ids without case.
    expect(
      brokenRules(changed(API_GRANT, (grant) => (properties(grant).roleDefinitionId = roleId.toUpperCase()))),
    ).toEqual([]);

    // The policy works out the role's name as Bicep's guid() does: the role's
    // one argument after the group, and each grant's three (scope, identity, role).
    const release = idOf(named(/^id-agentx-stg-release$/));
    expect(role).toBe(bicepGuid(group, 'release'));
    expect(grantName).toBe(bicepGuid(idOf(APP('api')), release, roleId));
    // A built-in role passed off as CI's: the role defined under Owner's id, and given by it.
    const owner = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635';
    const asOwner = changed(
      (resource) => resource.type === 'Microsoft.Authorization/roleDefinitions' || GIVES_ROLE(resource),
      (resource) => {
        if (resource.type === 'Microsoft.Authorization/roleDefinitions') {
          resource.name = owner;
          resource.id = String(resource.id).replace(role, owner);
        } else properties(resource).roleDefinitionId = roleId.replace(role, owner);
      },
    );
    expect(policyProblems(asOwner, STAGING).map(describeProblem)).toEqual(
      expect.arrayContaining([
        `${owner} [release-identity] must be named ${role} (names.bicep's releaseRoleName), so that no other role, a built-in one among them, passes as CI's`,
        `the deployment [release-access] ${given('ca-agentx-stg-api', 0).replace('the deployment: ', '')}`,
      ]),
    );
    expect(brokenRules(asOwner)).toEqual(['release-identity', 'release-access', 'secret-access']);
    // A second custom role, wider, given to CI on the API in place of CI's own.
    const wider = structuredClone(staging.predictedResources.find(type('Microsoft.Authorization/roleDefinitions')));
    const other = bicepGuid(group, 'wider');
    const widened = withExtra({
      ...wider,
      name: other,
      id: String(wider?.id).replace(role, other),
      properties: { ...(wider?.properties as Mutable), permissions: [{ actions: ['*'] }] },
    });
    const apiGrant = widened.predictedResources.find(API_GRANT) as unknown as Mutable;
    properties(apiGrant).roleDefinitionId = roleId.replace(role, other);
    expect(accessProblems(widened)).toEqual([given('ca-agentx-stg-api', 0)]);
    expect(brokenRules(widened)).toEqual(['release-identity', 'release-access', 'secret-access']);
    // CI's identity's namesake in another resource group isn't CI's identity.
    const namesake = release.replace('/resourceGroups/rg-agentx-staging/', '/resourceGroups/elsewhere/');
    const toNamesake = withExtra({
      ...structuredClone(staging.predictedResources.find(named(/^id-agentx-stg-release$/))),
      id: namesake,
    });
    properties(toNamesake.predictedResources.find(API_GRANT) as unknown as Mutable).principalId =
      `[reference('${namesake}', '2024-11-30').principalId]`;
    expect(accessProblems(toNamesake)).toEqual([alone(grantName), given('ca-agentx-stg-api', 0)]);
    // Nor is the API's namesake in another resource group the API.
    const elsewhere = idOf(APP('api')).replace('/resourceGroups/rg-agentx-staging/', '/resourceGroups/elsewhere/');
    const onNamesake = withExtra({ ...structuredClone(staging.predictedResources.find(APP('api'))), id: elsewhere });
    scoped(elsewhere)(onNamesake.predictedResources.find(API_GRANT) as unknown as Mutable);
    expect(accessProblems(onNamesake)).toEqual([alone(grantName), given('ca-agentx-stg-api', 0)]);
    // Access given in a form the rules don't read: the type in another case, the
    // older form under a resource, or a PIM request. `secret-access` refuses it.
    for (const kind of [
      'microsoft.authorization/roleAssignments',
      'Microsoft.App/containerApps/providers/roleAssignments',
    ]) {
      const unread = changed(API_GRANT, (grant) => (grant.type = kind));
      expect(policyProblems(unread, STAGING).map(describeProblem)).toEqual(
        expect.arrayContaining([
          `${grantName} [secret-access] is a ${kind}, which no rule reads: access is given only as Microsoft.Authorization/roleAssignments, written exactly so`,
        ]),
      );
      expect(brokenRules(unread)).toEqual(['release-access', 'secret-access']);
    }
    const pim = {
      type: 'Microsoft.Authorization/roleAssignmentScheduleRequests',
      name: 'pim',
      id: `${group}/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/pim`,
      apiVersion: '2022-04-01',
    };
    expect(brokenRules(withExtra(pim))).toEqual(['secret-access']);
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
      // The app's keys overwritten by every run, or whenever a run brings values for them.
      ['@onlyIfNotExists()\nresource keys', 'resource keys'],
      ['  for key in appKeys: {', '  for key in appKeys: if (!empty(appKeyValues)) {'],
      // Every other secret overwritten by every run, given or not, or whenever a secret has a name.
      ['for secret in secrets: if (!empty(secret.value)) {', 'for secret in secrets: {'],
      ['for secret in secrets: if (!empty(secret.value)) {', 'for secret in secrets: if (!empty(secret.name)) {'],
      // Rotating secrets that a run can no longer rotate.
      ["resource written 'Microsoft", "@onlyIfNotExists()\nresource written 'Microsoft"],
      // A secret looked up where secrets are written, which Azure refuses at deployment (S19).
      [
        '// Who reads what, in a template of its own',
        "resource found 'Microsoft.KeyVault/vaults/secrets@2025-05-01' existing = {\n  parent: vault\n  name: 'db-admin-password'\n}\n\noutput found string = found.id\n\n// Who reads what, in a template of its own",
      ],
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
    // Looked up beside one it writes, in a module too: each lookup named.
    const found = { ...secret, existing: true };
    const created = { ...secret, '@options': { onlyIfNotExists: [] } };
    const part = {
      type: 'Microsoft.Resources/deployments',
      properties: { template: { resources: { found, again: found, created } } },
    };
    expect(templateProblems('t.bicep', { resources: { part } }).map((problem) => problem.resource)).toEqual([
      't.bicep: found',
      't.bicep: again',
    ]);
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
    // CI's identity, which reads no secret: refused as a reader GRANTS doesn't name, not as someone unknown.
    expect(
      policyProblems(
        changed(API_READS, (assignment) => (properties(assignment).principalId = principal('release'))),
        STAGING,
      )
        .filter((problem) => problem.rule === 'secret-access')
        .map((problem) => problem.message),
    ).toEqual([
      "lets release read db-app-password, which isn't one of its secrets (GRANTS)",
      'must let api read db-app-password, which it needs (GRANTS)',
    ]);
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
    // A job the deployment needs, left out. CI's role would then be given on
    // a migration job this deployment doesn't make, and the owner-login alert
    // would pair logins with its starts.
    for (const workload of ['db-setup', 'migrate', 'zitadel-init', 'zitadel-setup']) {
      expect({ workload, rules: brokenRules(without(JOB(workload))) }).toEqual({
        workload,
        rules: workload === 'migrate' ? ['owner-login-alert', 'release-access', 'jobs'] : ['jobs'],
      });
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
    // read by nothing, and the login pages have nothing to sign a call to. A
    // door would reach an app this deployment doesn't make, and so would CI's role.
    for (const workload of ['api', 'login', 'zitadel']) {
      expect({ workload, rules: brokenRules(without(APP(workload))) }).toEqual({
        workload,
        rules: workload === 'api' ? ['release-access', 'apps', 'public-doors'] : ['apps', 'public-doors'],
      });
    }
  });

  it('public-doors: a door nothing lists or elsewhere, on plain http, routing any other way, or missing', () => {
    // The rule's own messages, so a condition another one also catches can't hide.
    const doorProblems = (snapshotted: Snapshot): string[] =>
      policyProblems(snapshotted, STAGING)
        .filter((problem) => problem.rule === 'public-doors')
        .map((problem) => `${problem.resource}: ${problem.message}`);
    const APP_DOOR = named(/\/rtagentxstgapp$/);
    const AUTH_DOOR = named(/\/rtagentxstgauth$/);
    const appDoor = staging.predictedResources.find(APP_DOOR);
    const environment = staging.predictedResources.find(ENVIRONMENT);
    const app = 'cae-agentx-staging/rtagentxstgapp';
    const auth = 'cae-agentx-staging/rtagentxstgauth';
    expect(staging.predictedResources.filter(DOOR).map((door) => door.name)).toEqual([app, auth]);
    expect(doorProblems(staging)).toEqual([]);
    // A door PUBLIC_DOORS doesn't name, beside the ones it does.
    expect(
      doorProblems(withExtra({ ...structuredClone(appDoor), id: `${String(appDoor?.id)}x`, name: `${app}x` })),
    ).toEqual([`${app}x: isn't a door PUBLIC_DOORS names (app, auth), so it may route nothing`]);
    // The same door, but another environment's.
    expect(
      doorProblems(
        changed(APP_DOOR, (door) => {
          door.id = `${String(environment?.id)}-second/httpRouteConfigs/rtagentxstgapp`;
        }),
      ),
    ).toEqual([`${app}: must be a door of this deployment's Container Apps environment`]);
    // No host, or two.
    expect(doorProblems(changed(AUTH_DOOR, (door) => (inside(door, 'properties').customDomains = [])))).toEqual([
      `${auth}: must serve exactly one host; it names 0`,
    ]);
    expect(
      doorProblems(
        changed(APP_DOOR, (door) => {
          (at(door, 'properties', 'customDomains') as Mutable[]).push({
            name: 'other.example.invalid',
            bindingType: 'Auto',
          });
        }),
      ),
    ).toEqual([`${app}: must serve exactly one host; it names 2`]);
    // Plain http alone, said outright or left to Azure; a certificate it names is as good as a managed one.
    const hostOf = (door: Mutable): Mutable => first(at(door, 'properties', 'customDomains'));
    for (const change of [
      (host: Mutable) => (host.bindingType = 'Disabled'),
      (host: Mutable) => delete host.bindingType,
    ]) {
      expect(doorProblems(changed(AUTH_DOOR, (door) => change(hostOf(door))))).toEqual([
        `${auth}: must bind a certificate to auth.example.invalid (Auto or SniEnabled), never plain http alone`,
      ]);
    }
    expect(doorProblems(changed(APP_DOOR, (door) => (hostOf(door).bindingType = 'SniEnabled')))).toEqual([]);
    // The routing, which must be exactly the listed lines in order.
    const listed = {
      app: 'prefix "/" to api',
      auth: 'prefix "/debug" in any case to api; prefix "/ui/v2/login" to login; prefix "/" to zitadel',
    };
    const routed = (name: string, lines: string): string =>
      `${name}: must route exactly as PUBLIC_DOORS says, in order: ${name === app ? listed.app : listed.auth}. It routes: ${lines}`;
    const rulesOf = (door: Mutable): Mutable[] => at(door, 'properties', 'rules') as Mutable[];
    const routeOf = (door: Mutable, index = 0): Mutable => first(nth(rulesOf(door), index).routes);
    const targetOf = (door: Mutable, index = 0): Mutable => first(nth(rulesOf(door), index).targets);
    const authRouting = (change: (door: Mutable) => void): string[] => doorProblems(changed(AUTH_DOOR, change));
    const appRouting = (change: (door: Mutable) => void): string[] => doorProblems(changed(APP_DOOR, change));
    // The login pages after `/`, where Zitadel would take them first.
    expect(authRouting((door) => rulesOf(door).reverse())).toEqual([
      routed(auth, 'prefix "/" to zitadel; prefix "/ui/v2/login" to login; prefix "/debug" in any case to api'),
    ]);
    // The debug pages matched in one case only, or with case left to Azure; `/` in any case.
    expect(authRouting((door) => (inside(routeOf(door), 'match').caseSensitive = true))).toEqual([
      routed(auth, 'prefix "/debug" to api; prefix "/ui/v2/login" to login; prefix "/" to zitadel'),
    ]);
    expect(authRouting((door) => delete inside(routeOf(door), 'match').caseSensitive)).toEqual([
      routed(
        auth,
        'prefix "/debug" with case left to Azure to api; prefix "/ui/v2/login" to login; prefix "/" to zitadel',
      ),
    ]);
    expect(appRouting((door) => (inside(routeOf(door), 'match').caseSensitive = false))).toEqual([
      routed(app, 'prefix "/" in any case to api'),
    ]);
    // Another way of matching, two at once, none, or a rule with no route at all.
    expect(appRouting((door) => (routeOf(door).match = { path: '/', caseSensitive: true }))).toEqual([
      routed(app, 'path "/" to api'),
    ]);
    expect(
      appRouting((door) => (routeOf(door).match = { prefix: '/', pathSeparatedPrefix: '/', caseSensitive: true })),
    ).toEqual([routed(app, 'prefix "/" and pathSeparatedPrefix "/" to api')]);
    expect(appRouting((door) => (routeOf(door).match = { caseSensitive: true }))).toEqual([
      routed(app, 'no path to api'),
    ]);
    expect(appRouting((door) => (first(rulesOf(door)).routes = []))).toEqual([
      routed(app, 'no path with case left to Azure to api'),
    ]);
    // A rewrite, which can take a request where no rule sends it.
    expect(appRouting((door) => (routeOf(door).action = { prefixRewrite: '/debug' }))).toEqual([
      routed(app, 'prefix "/" rewritten by {"prefixRewrite":"/debug"} to api'),
    ]);
    // Another app of ours, one this deployment doesn't make (production's API
    // is an api, but not this deployment's), and none at all.
    expect(authRouting((door) => (targetOf(door).containerApp = 'ca-agentx-stg-zitadel'))).toEqual([
      routed(auth, 'prefix "/debug" in any case to zitadel; prefix "/ui/v2/login" to login; prefix "/" to zitadel'),
    ]);
    expect(appRouting((door) => (targetOf(door).containerApp = 'ca-agentx-prd-api'))).toEqual([
      routed(app, `prefix "/" to "ca-agentx-prd-api", which this deployment doesn't make`),
    ]);
    expect(appRouting((door) => (first(rulesOf(door)).targets = []))).toEqual([routed(app, 'prefix "/" to no app')]);
    // The right app, pinned to a revision or label.
    expect(appRouting((door) => (targetOf(door).revision = 'ca-agentx-stg-api--0000001'))).toEqual([
      routed(app, 'prefix "/" to api pinned to revision "ca-agentx-stg-api--0000001"'),
    ]);
    expect(authRouting((door) => (targetOf(door, 2).label = 'blue'))).toEqual([
      routed(
        auth,
        'prefix "/debug" in any case to api; prefix "/ui/v2/login" to login; prefix "/" to zitadel pinned to label "blue"',
      ),
    ]);
    // A second target on a rule, a rule too many, and no rules at all.
    expect(
      appRouting((door) => (first(rulesOf(door)).targets as Mutable[]).push({ containerApp: 'ca-agentx-stg-login' })),
    ).toEqual([routed(app, 'prefix "/" to api; prefix "/" to login')]);
    expect(authRouting((door) => rulesOf(door).push(structuredClone(first(rulesOf(door)))))).toEqual([
      routed(
        auth,
        'prefix "/debug" in any case to api; prefix "/ui/v2/login" to login; prefix "/" to zitadel; prefix "/debug" in any case to api',
      ),
    ]);
    expect(appRouting((door) => (inside(door, 'properties').rules = []))).toEqual([routed(app, 'nothing')]);
    // A door missing, or there twice.
    expect(doorProblems(without(AUTH_DOOR))).toEqual(['the deployment: needs the auth door once; the snapshot has 0']);
    expect(doorProblems(without(DOOR))).toEqual([
      'the deployment: needs the app door once; the snapshot has 0',
      'the deployment: needs the auth door once; the snapshot has 0',
    ]);
    expect(doorProblems(withExtra(structuredClone(appDoor) as unknown as Mutable))).toEqual([
      'the deployment: needs the app door once; the snapshot has 2',
    ]);
  });

  it('door-certificates: a door host without its one certificate, one elsewhere, for no door, or not validated by HTTP', () => {
    // The rule's own messages, so a condition another one also catches can't hide.
    const certificateProblems = (snapshotted: Snapshot): string[] =>
      policyProblems(snapshotted, STAGING)
        .filter((problem) => problem.rule === 'door-certificates')
        .map((problem) => `${problem.resource}: ${problem.message}`);
    const APP_CERTIFICATE = named(/\/mc-agentx-stg-app$/);
    const appCertificate = staging.predictedResources.find(APP_CERTIFICATE);
    const environment = staging.predictedResources.find(ENVIRONMENT);
    const app = 'cae-agentx-staging/mc-agentx-stg-app';
    expect(staging.predictedResources.filter(CERTIFICATE).map((certificate) => certificate.name)).toEqual([
      app,
      'cae-agentx-staging/mc-agentx-stg-auth',
    ]);
    expect(
      staging.predictedResources.filter(CERTIFICATE).map((certificate) => at(certificate.properties, 'subjectName')),
    ).toEqual(['app.example.invalid', 'auth.example.invalid']);
    expect(certificateProblems(staging)).toEqual([]);
    const propertiesOf = (certificate: Mutable): Mutable => inside(certificate, 'properties');
    // Another environment's certificate.
    expect(
      certificateProblems(
        changed(APP_CERTIFICATE, (certificate) => {
          certificate.id = `${String(environment?.id)}-second/managedCertificates/mc-agentx-stg-app`;
        }),
      ),
    ).toEqual([`${app}: must be a certificate of this deployment's Container Apps environment`]);
    // A certificate for a host no door serves, which leaves the app door's host without one.
    expect(
      certificateProblems(
        changed(APP_CERTIFICATE, (certificate) => (propertiesOf(certificate).subjectName = 'other.example.invalid')),
      ),
    ).toEqual([
      `${app}: is for "other.example.invalid", a host no door serves`,
      'the deployment: needs one certificate for "app.example.invalid"; the snapshot has 0',
    ]);
    // The door moved to another host, its certificate left behind.
    expect(
      certificateProblems(
        changed(named(/\/rtagentxstgapp$/), (door) => {
          first(at(door, 'properties', 'customDomains')).name = 'new.example.invalid';
        }),
      ),
    ).toEqual([
      `${app}: is for "app.example.invalid", a host no door serves`,
      'the deployment: needs one certificate for "new.example.invalid"; the snapshot has 0',
    ]);
    // Any validation but HTTP, or none said.
    for (const validation of ['TXT', 'CNAME']) {
      expect(
        certificateProblems(
          changed(APP_CERTIFICATE, (certificate) => (propertiesOf(certificate).domainControlValidation = validation)),
        ),
      ).toEqual([
        `${app}: must be validated by HTTP, as a door's host with an A record is; it says ${JSON.stringify(validation)}`,
      ]);
    }
    expect(
      certificateProblems(
        changed(APP_CERTIFICATE, (certificate) => delete propertiesOf(certificate).domainControlValidation),
      ),
    ).toEqual([`${app}: must be validated by HTTP, as a door's host with an A record is; it says undefined`]);
    // A door's certificate missing, or made twice.
    expect(certificateProblems(without(APP_CERTIFICATE))).toEqual([
      'the deployment: needs one certificate for "app.example.invalid"; the snapshot has 0',
    ]);
    expect(certificateProblems(withExtra(structuredClone(appCertificate) as unknown as Mutable))).toEqual([
      'the deployment: needs one certificate for "app.example.invalid"; the snapshot has 2',
    ]);
    // Certificates outside the UAE or untagged are the generic rules' to refuse.
    expect(brokenRules(changed(APP_CERTIFICATE, (certificate) => (certificate.location = 'westeurope')))).toEqual([
      'in-country',
    ]);
    expect(brokenRules(changed(CERTIFICATE, (certificate) => delete certificate.tags))).toEqual(['tags']);
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

  it("workload-secrets and no-secret-literals: the operator's job holds its request once, as none, as a file, and no other job holds one (B1c-2a)", () => {
    const messages = (snapshotted: Snapshot): string[] => policyProblems(snapshotted, STAGING).map(describeProblem);
    const operator = JOB('operator');
    const request = (job: Mutable): Mutable => secretNamed(job, 'operator-request');
    const mounted = (job: Mutable): Mutable[] =>
      at(first(at(job, 'properties', 'template', 'volumes')), 'secrets') as Mutable[];
    const holdOnce =
      'job-agentx-stg-operator [workload-secrets] must hold operator-request once, as [] and nothing else: a person writes it before a run';
    // A request written into the deployment: a value in the code, and not none.
    expect(
      messages(
        changed(operator, (job) => {
          request(job).value = '["create-organization","--name","Quartzite Other Co"]';
        }),
      ),
    ).toEqual([
      'job-agentx-stg-operator [no-secret-literals] configuration.secrets[2].value must come from a @secure() parameter, never a value in the code',
      holdOnce,
    ]);
    // Held twice, held as a vault secret too, or not held at all (with its file gone, so nothing else objects).
    expect(
      messages(
        changed(operator, (job) => {
          declaredSecrets(job).push(structuredClone(request(job)));
        }),
      ),
    ).toEqual([holdOnce]);
    for (const field of ['keyVaultUrl', 'identity']) {
      expect(
        messages(
          changed(operator, (job) => {
            request(job)[field] = String(secretNamed(job, 'db-app-password')[field]);
          }),
        ),
      ).toEqual([holdOnce]);
    }
    expect(
      messages(
        changed(operator, (job) => {
          configurationOf(job).secrets = declaredSecrets(job).filter((secret) => secret.name !== 'operator-request');
          first(at(job, 'properties', 'template', 'volumes')).secrets = mounted(job).filter(
            (item) => item.secretRef !== 'operator-request',
          );
        }),
      ),
    ).toEqual([holdOnce]);
    // Held but never read, or read from the environment, where crash output shows it.
    expect(
      messages(
        changed(operator, (job) => {
          first(at(job, 'properties', 'template', 'volumes')).secrets = mounted(job).filter(
            (item) => item.secretRef !== 'operator-request',
          );
        }),
      ),
    ).toEqual([
      'job-agentx-stg-operator [workload-secrets] is given operator-request and never reads it; one nobody needs is one more to leak',
    ]);
    expect(
      brokenRules(
        changed(operator, (job) => {
          first(at(job, 'properties', 'template', 'volumes')).secrets = mounted(job).filter(
            (item) => item.secretRef !== 'operator-request',
          );
          settingsOf(job).push({ name: 'AGENTX_OPERATOR_REQUEST', secretRef: 'operator-request' });
        }),
      ),
    ).toEqual(['workload-secrets']);
    // The operator's job holding something else of its own, even as none: only its request.
    expect(
      brokenRules(
        changed(operator, (job) => {
          declaredSecrets(job).push({ name: 'operator-note', value: '[]' });
          mounted(job).push({ secretRef: 'operator-note', path: 'operator-note' });
        }),
      ),
    ).toEqual(['no-secret-literals', 'workload-secrets']);
    // Another job holding one, even as none: only the operator's may.
    expect(
      brokenRules(
        changed(JOB('migrate'), (job) => {
          declaredSecrets(job).push({ name: 'operator-request', value: '[]' });
          mounted(job).push({ secretRef: 'operator-request', path: 'operator-request' });
        }),
      ),
    ).toEqual(['no-secret-literals', 'workload-secrets']);
    // A request in the job's own arguments, in place of the file or after it, or the file alone with its flag lost.
    const runAs =
      "job-agentx-stg-operator [workload-secrets] must be run as --request /mnt/secrets/operator-request and nothing else: a request in its arguments would sit in the deployment and every run's record";
    for (const args of [
      ['create-organization', '--name', 'Quartzite Other Co'],
      ['--request', '/mnt/secrets/operator-request', 'create-organization'],
      ['/mnt/secrets/operator-request'],
      [],
    ]) {
      expect({
        args,
        problems: messages(
          changed(operator, (job) => {
            containerOf(job).args = args;
          }),
        ),
      }).toEqual({ args, problems: [runAs] });
    }
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
      // Google Cloud's metadata server, which Zitadel asks for a machine ID by default (S19).
      'ZITADEL_MACHINE_IDENTIFICATION_WEBHOOK_ENABLED',
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

  /** Every setting a job's or an app's container is given, name to value, a secret's as `secret:<name>`. */
  const settingsGiven = (workload: string): Record<string, unknown> => {
    const job = staging.predictedResources.find((resource) => JOB(workload)(resource) || APP(workload)(resource));
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
      AGENTX_DB_HOST: 'psql-agentx-stg-ksacnt.postgres.database.azure.com',
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
      AGENTX_DB_HOST: 'psql-agentx-stg-ksacnt.postgres.database.azure.com',
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
    for (const workload of ['zitadel-init', 'zitadel-setup', 'zitadel']) {
      expect({ workload, settings: settingsGiven(workload) }).toMatchObject({
        workload,
        settings: {
          ZITADEL_DATABASE_POSTGRES_HOST: 'psql-agentx-stg-ksacnt.postgres.database.azure.com',
          ZITADEL_DATABASE_POSTGRES_DATABASE: 'zitadel',
          // Its own role is also its "admin": it never holds the server admin's login.
          ZITADEL_DATABASE_POSTGRES_USER_USERNAME: 'zitadel',
          ZITADEL_DATABASE_POSTGRES_ADMIN_USERNAME: 'zitadel',
          ZITADEL_DATABASE_POSTGRES_USER_PASSWORD: 'secret:db-zitadel-password',
          ZITADEL_DATABASE_POSTGRES_ADMIN_PASSWORD: 'secret:db-zitadel-password',
          ZITADEL_DATABASE_POSTGRES_USER_SSL_MODE: 'verify-full',
          ZITADEL_DATABASE_POSTGRES_ADMIN_SSL_MODE: 'verify-full',
          // Checked against the image's own roots: Zitadel refuses verify-full without a root setting (S19).
          ZITADEL_DATABASE_POSTGRES_USER_SSL_ROOTCERT: 'system',
          ZITADEL_DATABASE_POSTGRES_ADMIN_SSL_ROOTCERT: 'system',
          // db-setup made the database, so init must not try to make it again.
          ZITADEL_DATABASE_POSTGRES_ADMIN_EXISTINGDATABASE: 'zitadel',
          ZITADEL_LOG_FORMATTER_FORMAT: 'json',
        },
      });
    }
    // Each Zitadel process is told apart by its hostname: the private-address
    // default finds none on Container Apps, and setup panicked without one (S19).
    for (const workload of ['zitadel-init', 'zitadel-setup', 'zitadel']) {
      expect({ workload, settings: settingsGiven(workload) }).toMatchObject({
        workload,
        settings: {
          ZITADEL_MACHINE_IDENTIFICATION_PRIVATEIP_ENABLED: 'false',
          ZITADEL_MACHINE_IDENTIFICATION_HOSTNAME_ENABLED: 'true',
          ZITADEL_MACHINE_IDENTIFICATION_WEBHOOK_ENABLED: 'false',
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
    expect(
      Object.keys(settingsGiven('zitadel-setup')).filter((name) =>
        name.startsWith('ZITADEL_FIRSTINSTANCE_ORG_MACHINE'),
      ),
    ).toEqual([]);
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
