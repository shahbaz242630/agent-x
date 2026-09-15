import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import { beforeAll, describe, expect, it } from 'vitest';

import {
  at,
  describeProblem,
  type Expectations,
  kqlStages,
  policyProblems,
  PREVIEW_API_EXCEPTIONS,
  type RuleId,
  singleSummaryColumn,
} from './policy.ts';
import { inCopy, lint, type PredictedResource, snapshot, type Snapshot } from './snapshot.ts';

const STAGING: Expectations = { region: 'uaenorth', environment: 'staging' };

let staging: Snapshot;
beforeAll(() => {
  staging = inCopy((dir) => snapshot(dir, 'staging.bicepparam'));
});

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
  return { predictedResources: structuredClone(kept) };
};

const brokenRules = (snapshotted: Snapshot, expected = STAGING): RuleId[] => [
  ...new Set(policyProblems(snapshotted, expected).map((problem) => problem.rule)),
];

/** A nested object of a resource, for changing it in place. */
const inside = (value: unknown, ...keys: readonly string[]): Mutable => at(value, ...keys) as Mutable;
const first = (value: unknown): Mutable => (value as readonly Mutable[]).at(0) ?? {};

const type = (wanted: string) => (resource: PredictedResource) => resource.type === wanted;
const named = (pattern: RegExp) => (resource: PredictedResource) => pattern.test(resource.name);
const SERVER = type('Microsoft.DBforPostgreSQL/flexibleServers');
const VAULT = type('Microsoft.KeyVault/vaults');
const WORKSPACE = type('Microsoft.OperationalInsights/workspaces');
const RULES = type('Microsoft.Network/networkSecurityGroups');
const NETWORK = type('Microsoft.Network/virtualNetworks');
const LOGIN_ALERT = named(/-privileged-login$/);
const CAP_ALERT = named(/-log-cap-reached$/);
const setting = (name: string) => (resource: PredictedResource) => resource.name.endsWith(`/${name}`);

describe('deploy/azure', () => {
  it('builds and lints clean, the linter rules in bicepconfig.json included', () => {
    inCopy((dir) => {
      for (const file of ['main.bicep', 'staging.bicepparam'])
        expect(lint(dir, file)).toEqual({ status: 0, output: '' });
    });
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
    ]);
  });

  it('breaks no rule on staging', () => {
    expect(policyProblems(staging, STAGING).map(describeProblem)).toEqual([]);
  });

  it('keeps the server admin password out of the snapshot: it stays a parameter', () => {
    expect(at(staging.predictedResources.find(SERVER)?.properties, 'administratorLoginPassword')).toBe(
      "[parameters('postgresAdminPassword')]",
    );
  });
});

describe('each rule can fail', () => {
  it('in-country: a resource outside the region, or a global-only type pinned to one', () => {
    expect(brokenRules(changed(VAULT, (vault) => (vault.location = 'westeurope')))).toEqual(['in-country']);
    expect(
      brokenRules(changed(type('Microsoft.Insights/actionGroups'), (group) => (group.location = 'uaenorth'))),
    ).toEqual(['in-country']);
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

  it('no-secret-literals: a password written into the code', () => {
    const literal = changed(
      SERVER,
      (server) => (inside(server, 'properties').administratorLoginPassword = 'written in the code'),
    );
    expect(brokenRules(literal)).toEqual(['no-secret-literals']);
    const nested = changed(
      SERVER,
      (server) => (inside(server, 'properties', 'network').adminPassword = 'written in the code'),
    );
    expect(brokenRules(nested)).toEqual(['no-secret-literals']);
  });

  it('database-private: public access, no delegated subnet or private zone, or another major version', () => {
    expect(
      brokenRules(
        changed(SERVER, (server) => delete inside(server, 'properties', 'network').privateDnsZoneArmResourceId),
      ),
    ).toEqual(['database-private']);
    expect(
      brokenRules(
        changed(SERVER, (server) => (inside(server, 'properties', 'network').publicNetworkAccess = 'Enabled')),
      ),
    ).toEqual(['database-private']);
    expect(
      brokenRules(
        changed(SERVER, (server) => delete inside(server, 'properties', 'network').delegatedSubnetResourceId),
      ),
    ).toEqual(['database-private']);
    expect(brokenRules(changed(SERVER, (server) => (inside(server, 'properties').version = '17')))).toEqual([
      'database-private',
    ]);
  });

  it('database-logins: Microsoft Entra logins, or logins left unlogged', () => {
    expect(
      brokenRules(
        changed(SERVER, (server) => (inside(server, 'properties', 'authConfig').activeDirectoryAuth = 'Enabled')),
      ),
    ).toEqual(['database-logins']);
    expect(
      brokenRules(changed(setting('log_connections'), (entry) => (inside(entry, 'properties').value = 'off'))),
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

  it('database-network: the port open wider, the rest of the network let in, or a subnet not delegated', () => {
    const allow = (group: Mutable): Mutable => inside(first(at(group, 'properties', 'securityRules')), 'properties');
    expect(brokenRules(changed(RULES, (group) => (allow(group).sourceAddressPrefix = '10.40.0.0/16')))).toEqual([
      'database-network',
    ]);
    expect(brokenRules(changed(RULES, (group) => (allow(group).destinationPortRange = '*')))).toEqual([
      'database-network',
    ]);
    expect(
      brokenRules(
        changed(
          RULES,
          (group) => (inside(group, 'properties').securityRules = [first(at(group, 'properties', 'securityRules'))]),
        ),
      ),
    ).toEqual(['database-network']);
    expect(
      brokenRules(
        changed(RULES, (group) => {
          const rules = at(group, 'properties', 'securityRules') as unknown[];
          rules.push(structuredClone(rules[0]));
        }),
      ),
    ).toEqual(['database-network']);
    expect(
      brokenRules(
        changed(
          NETWORK,
          (network) => delete inside(first(at(network, 'properties', 'subnets')), 'properties').delegations,
        ),
      ),
    ).toEqual(['database-network']);
  });

  it('vault: access policies, no purge protection, or the network door left open', () => {
    const properties = (vault: Mutable): Mutable => inside(vault, 'properties');
    for (const change of [
      (vault: Mutable) => (properties(vault).enableRbacAuthorization = false),
      (vault: Mutable) => (properties(vault).accessPolicies = [{ objectId: 'someone' }]),
      (vault: Mutable) => (properties(vault).enablePurgeProtection = false),
      (vault: Mutable) => (properties(vault).softDeleteRetentionInDays = 7),
      (vault: Mutable) => (properties(vault).enabledForTemplateDeployment = true),
      (vault: Mutable) => (inside(vault, 'properties', 'networkAcls').defaultAction = 'Allow'),
      (vault: Mutable) => (inside(vault, 'properties', 'networkAcls').bypass = 'AzureServices'),
      (vault: Mutable) => (inside(vault, 'properties', 'networkAcls').ipRules = [{ value: '203.0.113.7' }]),
    ]) {
      expect(brokenRules(changed(VAULT, change))).toEqual(['vault']);
    }
  });

  it('workspace: another retention, shared keys, or no cap', () => {
    expect(
      brokenRules(changed(WORKSPACE, (workspace) => (inside(workspace, 'properties').retentionInDays = 90))),
    ).toEqual(['workspace']);
    expect(
      brokenRules(
        changed(WORKSPACE, (workspace) => (inside(workspace, 'properties', 'features').disableLocalAuth = false)),
      ),
    ).toEqual(['workspace']);
    expect(
      brokenRules(changed(WORKSPACE, (workspace) => delete inside(workspace, 'properties').workspaceCapping)),
    ).toEqual(['workspace']);
  });

  it('log-quota-alerts: an 80% alert that no longer matches the cap, or no alert when the cap is reached', () => {
    expect(
      brokenRules(
        changed(WORKSPACE, (workspace) => (inside(workspace, 'properties', 'workspaceCapping').dailyQuotaGb = 2)),
      ),
    ).toEqual(['log-quota-alerts']);
    expect(brokenRules(without(CAP_ALERT))).toEqual(['log-quota-alerts']);
  });

  it('alert-counts-only: rows, groups, dimensions or custom properties in an alert', () => {
    const criterion = (alert: Mutable): Mutable => first(at(alert, 'properties', 'criteria', 'allOf'));
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
      (alert: Mutable) => (inside(alert, 'properties', 'actions').customProperties = { server: 'name' }),
      (alert: Mutable) => (alert.kind = 'SimpleLogAlert'),
    ]) {
      expect(brokenRules(changed(LOGIN_ALERT, change))).toEqual(['alert-counts-only']);
    }
  });

  it("alert-runbook: no runbook, a severity its SEV doesn't match, or nowhere to send it", () => {
    const properties = (alert: Mutable): Mutable => inside(alert, 'properties');
    for (const change of [
      (alert: Mutable) => (properties(alert).description = 'Something happened.'),
      (alert: Mutable) => (properties(alert).severity = 2),
      (alert: Mutable) => (properties(alert).severity = 3),
      (alert: Mutable) => (inside(alert, 'properties', 'actions').actionGroups = []),
    ]) {
      expect(brokenRules(changed(LOGIN_ALERT, change))).toEqual(['alert-runbook']);
    }
  });

  it('resource-logs: a vault or server whose logs stay out of the workspace', () => {
    expect(brokenRules(without(named(/^audit-to-workspace$/)))).toEqual(['resource-logs']);
    expect(
      brokenRules(
        changed(
          named(/^logs-to-workspace$/),
          (entry) => (inside(entry, 'properties').logAnalyticsDestinationType = 'AzureDiagnostics'),
        ),
      ),
    ).toEqual(['resource-logs']);
    expect(
      brokenRules(
        changed(named(/^logs-to-workspace$/), (entry) => (first(at(entry, 'properties', 'logs')).enabled = false)),
      ),
    ).toEqual(['resource-logs']);
  });

  it("activity-log: the subscription's changes not kept", () => {
    expect(brokenRules(without(named(/^activity-log-to-workspace$/)))).toEqual(['activity-log']);
  });

  it('budget: no 80% email, or no forecast email', () => {
    const notices = (entry: Mutable): Mutable => inside(entry, 'properties', 'notifications');
    expect(
      brokenRules(changed(type('Microsoft.Consumption/budgets'), (entry) => delete notices(entry).forecast100)),
    ).toEqual(['budget']);
    expect(
      brokenRules(
        changed(type('Microsoft.Consumption/budgets'), (entry) => (inside(notices(entry), 'actual80').enabled = false)),
      ),
    ).toEqual(['budget']);
    expect(brokenRules(without(type('Microsoft.Consumption/budgets')))).toEqual(['budget']);
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

describe('each condition of a rule can fail on its own', () => {
  const rules = (group: Mutable): Mutable[] => at(group, 'properties', 'securityRules') as Mutable[];
  const allowRule = (group: Mutable): Mutable => inside(rules(group)[0], 'properties');
  const denyRule = (group: Mutable): Mutable => inside(rules(group)[1], 'properties');
  const criterion = (alert: Mutable): Mutable => first(at(alert, 'properties', 'criteria', 'allOf'));
  const QUOTA_ALERT = named(/-log-quota$/);

  it('database: password logins switched off', () => {
    expect(
      brokenRules(changed(SERVER, (server) => (inside(server, 'properties', 'authConfig').passwordAuth = 'Disabled'))),
    ).toEqual(['database-logins']);
  });

  it('database-network: the allowed protocol, the deny rule and the database subnet, each on its own', () => {
    for (const change of [
      (group: Mutable) => (allowRule(group).protocol = '*'),
      (group: Mutable) => (denyRule(group).protocol = 'Tcp'),
      (group: Mutable) => (denyRule(group).sourceAddressPrefix = '10.99.0.0/24'),
      (group: Mutable) => (denyRule(group).destinationAddressPrefix = '10.99.0.0/24'),
      (group: Mutable) => (denyRule(group).destinationPortRange = '22'),
      (group: Mutable) => (denyRule(group).priority = 50),
      (group: Mutable) => (denyRule(group).access = 'Allow'),
    ]) {
      expect(brokenRules(changed(RULES, change))).toEqual(['database-network']);
    }
    expect(
      brokenRules(
        changed(
          NETWORK,
          (network) => delete inside((at(network, 'properties', 'subnets') as Mutable[])[1], 'properties').delegations,
        ),
      ),
    ).toEqual(['database-network']);
  });

  it('workspace: a cap of nothing', () => {
    expect(
      brokenRules(
        changed(WORKSPACE, (workspace) => (inside(workspace, 'properties', 'workspaceCapping').dailyQuotaGb = 0)),
      ),
    ).toEqual(['workspace']);
  });

  it('log-quota-alerts: the 80% alert on another table, or firing below its threshold', () => {
    expect(
      brokenRules(
        changed(QUOTA_ALERT, (alert) => (criterion(alert).query = 'AzureDiagnostics | summarize IngestedMb = count()')),
      ),
    ).toEqual(['log-quota-alerts']);
    expect(brokenRules(changed(QUOTA_ALERT, (alert) => (criterion(alert).operator = 'LessThan')))).toEqual([
      'log-quota-alerts',
    ]);
  });

  it('alert-counts-only: no condition at all, or a resource ID column', () => {
    expect(brokenRules(changed(LOGIN_ALERT, (alert) => (inside(alert, 'properties', 'criteria').allOf = [])))).toEqual([
      'alert-counts-only',
    ]);
    expect(brokenRules(changed(LOGIN_ALERT, (alert) => (criterion(alert).resourceIdColumn = '_ResourceId')))).toEqual([
      'alert-counts-only',
    ]);
  });

  it('resource-logs and activity-log: logs sent somewhere else, or the wrong category', () => {
    const elsewhere = '/subscriptions/x/resourceGroups/y/providers/Microsoft.OperationalInsights/workspaces/elsewhere';
    expect(
      brokenRules(
        changed(named(/^audit-to-workspace$/), (entry) => (inside(entry, 'properties').workspaceId = elsewhere)),
      ),
    ).toEqual(['resource-logs']);
    expect(
      brokenRules(
        changed(
          named(/^logs-to-workspace$/),
          (entry) => (first(at(entry, 'properties', 'logs')).category = 'PostgreSQLFlexSessions'),
        ),
      ),
    ).toEqual(['resource-logs']);
    expect(
      brokenRules(
        changed(
          named(/^activity-log-to-workspace$/),
          (entry) => (first(at(entry, 'properties', 'logs')).enabled = false),
        ),
      ),
    ).toEqual(['activity-log']);
    expect(
      brokenRules(
        changed(named(/^activity-log-to-workspace$/), (entry) => (inside(entry, 'properties').workspaceId = elsewhere)),
      ),
    ).toEqual(['activity-log']);
  });

  it('budget: a notice to nobody, at another threshold, or of another type', () => {
    const notice = (entry: Mutable, name: string): Mutable => inside(entry, 'properties', 'notifications', name);
    const BUDGET = type('Microsoft.Consumption/budgets');
    for (const change of [
      (entry: Mutable) => (notice(entry, 'actual80').contactEmails = []),
      (entry: Mutable) => (notice(entry, 'actual80').threshold = 90),
      (entry: Mutable) => (notice(entry, 'forecast100').thresholdType = 'Actual'),
    ]) {
      expect(brokenRules(changed(BUDGET, change))).toEqual(['budget']);
    }
  });
});
