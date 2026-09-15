// What every Azure deployment of Agent X must be, checked on the resources its
// snapshot predicts (snapshot.ts), so a change to deploy/azure that breaks a
// rule fails CI before it reaches Azure. Each rule names the decision it
// enforces; each is proven able to fail (policy.test.ts).
import type { PredictedResource, Snapshot } from './snapshot.ts';

export type RuleId =
  | 'in-country'
  | 'stable-api'
  | 'tags'
  | 'no-secret-literals'
  | 'database-private'
  | 'database-network'
  | 'database-logins'
  | 'database-tls'
  | 'database-backup'
  | 'vault'
  | 'workspace'
  | 'log-quota-alerts'
  | 'alert-counts-only'
  | 'alert-runbook'
  | 'resource-logs'
  | 'activity-log'
  | 'budget';

export interface Problem {
  readonly rule: RuleId;
  /** The resource's name, or "the subscription" for a rule about what is missing. */
  readonly resource: string;
  readonly message: string;
}

export interface Expectations {
  /** Where every resource with a location must be, but the few Azure only offers globally (ADR-009). */
  readonly region: string;
  readonly environment: 'staging' | 'production';
}

const TYPES = {
  actionGroup: 'Microsoft.Insights/actionGroups',
  alert: 'Microsoft.Insights/scheduledQueryRules',
  budget: 'Microsoft.Consumption/budgets',
  diagnostics: 'Microsoft.Insights/diagnosticSettings',
  dnsLink: 'Microsoft.Network/privateDnsZones/virtualNetworkLinks',
  dnsZone: 'Microsoft.Network/privateDnsZones',
  network: 'Microsoft.Network/virtualNetworks',
  rules: 'Microsoft.Network/networkSecurityGroups',
  server: 'Microsoft.DBforPostgreSQL/flexibleServers',
  setting: 'Microsoft.DBforPostgreSQL/flexibleServers/configurations',
  vault: 'Microsoft.KeyVault/vaults',
  workspace: 'Microsoft.OperationalInsights/workspaces',
} as const;

/** Types Azure offers only as global resources. None holds customer data or logs. */
const GLOBAL_TYPES: ReadonlySet<string> = new Set([TYPES.actionGroup, TYPES.dnsZone, TYPES.dnsLink]);

/** Types whose newest API version is a preview, with why the preview is used. */
export const PREVIEW_API_EXCEPTIONS: Readonly<Record<string, string>> = {
  [TYPES.diagnostics]:
    'Azure publishes diagnostic settings only in preview API versions after 2016-09-01, which predates category groups and resource-specific tables',
};

const requiredTags = (environment: string): Readonly<Record<string, string>> => ({
  product: 'agent-x',
  environment,
  'managed-by': 'deploy/azure',
});

/** One nested value, or undefined when any step of the path is missing. */
export function at(value: unknown, ...keys: readonly string[]): unknown {
  let current = value;
  for (const key of keys) {
    if (typeof current !== 'object' || current === null) return undefined;
    current = (current as Record<string, unknown>)[key];
  }
  return current;
}

const list = (value: unknown): readonly unknown[] => (Array.isArray(value) ? value : []);

/** Where a KQL string or comment starting at `index` ends (one past it), or undefined if none starts there. */
function skipQuoted(query: string, index: number): number | undefined {
  const rest = query.slice(index);
  const endOf = (marker: string, from: number): number => {
    const end = query.indexOf(marker, from);
    return end === -1 ? query.length : end + marker.length;
  };
  if (rest.startsWith('```')) return endOf('```', index + 3);
  if (rest.startsWith('//')) return endOf('\n', index + 2);
  if (/^@["']/.test(rest)) {
    // Verbatim: no escapes but a doubled quote.
    const quote = rest.charAt(1);
    let end = index + 2;
    while (end < query.length) {
      if (query.charAt(end) === quote) {
        if (query.charAt(end + 1) !== quote) return end + 1;
        end += 2;
      } else {
        end += 1;
      }
    }
    return query.length;
  }
  if (rest.startsWith('"') || rest.startsWith("'")) {
    const quote = rest.charAt(0);
    let end = index + 1;
    while (end < query.length && query.charAt(end) !== quote) end += query.charAt(end) === '\\' ? 2 : 1;
    return Math.min(end + 1, query.length);
  }
  return undefined;
}

/**
 * Walks a query's top level: `visit` sees each character outside strings,
 * comments and brackets, with the text before it since the last cut. A pipe in
 * a regex's alternation or in a subquery's brackets is never at the top level.
 */
function topLevel(query: string, visit: (character: string) => void, keep: (text: string) => void): void {
  let depth = 0;
  let index = 0;
  while (index < query.length) {
    const quotedEnd = skipQuoted(query, index);
    if (quotedEnd !== undefined) {
      keep(query.slice(index, quotedEnd));
      index = quotedEnd;
      continue;
    }
    const character = query.charAt(index);
    if (character === '(' || character === '[') depth += 1;
    if (character === ')' || character === ']') depth -= 1;
    if (depth === 0 && character !== ')' && character !== ']') visit(character);
    else keep(character);
    index += 1;
  }
}

/** A query split at its top-level pipes, each stage trimmed. */
export function kqlStages(query: string): string[] {
  const stages: string[] = [];
  let current = '';
  topLevel(
    query,
    (character) => {
      if (character === '|') {
        stages.push(current.trim());
        current = '';
      } else {
        current += character;
      }
    },
    (text) => {
      current += text;
    },
  );
  stages.push(current.trim());
  return stages;
}

/**
 * The one column a query's final `summarize Name = aggregation(…)` produces, or
 * undefined if the query ends otherwise, makes more than one column, or groups
 * `by` anything: then it would return rows, not one number.
 */
export function singleSummaryColumn(query: string): string | undefined {
  const last = kqlStages(query).at(-1) ?? '';
  const summarize = /^summarize\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([\s\S]+)$/.exec(last);
  if (summarize === null) return undefined;
  let outside = '';
  topLevel(
    summarize[2] ?? '',
    (character) => {
      outside += character;
    },
    () => {
      outside += ' ';
    },
  );
  if (outside.includes(',') || /\bby\b/i.test(outside)) return undefined;
  return summarize[1];
}

/** Settings attached to a resource: their ids sit under the resource's own. */
const settingsOf = (snapshot: Snapshot, resource: PredictedResource): readonly PredictedResource[] =>
  snapshot.predictedResources.filter(
    (candidate) =>
      candidate.type === TYPES.diagnostics &&
      candidate.id.toLowerCase().startsWith(`${resource.id}/providers/${TYPES.diagnostics}/`.toLowerCase()),
  );

/** A workspace reference: the workspace's own id, or this deployment's monitoring module handing it on. */
const pointsAtWorkspace = (value: unknown, workspaces: readonly PredictedResource[]): boolean =>
  workspaces.some((workspace) => value === workspace.id) ||
  (typeof value === 'string' && value.endsWith('.outputs.workspaceId.value]'));

type Check = (snapshot: Snapshot, expected: Expectations, add: (problem: Problem) => void) => void;

const ofType = (snapshot: Snapshot, type: string): readonly PredictedResource[] =>
  snapshot.predictedResources.filter((resource) => resource.type === type);

const inCountry: Check = (snapshot, expected, add) => {
  for (const resource of snapshot.predictedResources) {
    if (resource.location === undefined) continue;
    const wanted = GLOBAL_TYPES.has(resource.type) ? 'global' : expected.region;
    if (resource.location.toLowerCase() !== wanted) {
      add({
        rule: 'in-country',
        resource: resource.name,
        message: `is in ${resource.location}; it must be in ${wanted} (ADR-009: customer data and monitoring stay in the UAE)`,
      });
    }
  }
};

const stableApi: Check = (snapshot, _expected, add) => {
  for (const resource of snapshot.predictedResources) {
    if (resource.apiVersion.includes('preview') && PREVIEW_API_EXCEPTIONS[resource.type] === undefined) {
      add({
        rule: 'stable-api',
        resource: resource.name,
        message: `uses preview API ${resource.apiVersion}; use a stable version, or list the type in PREVIEW_API_EXCEPTIONS with its reason`,
      });
    }
  }
};

const tagged: Check = (snapshot, expected, add) => {
  for (const resource of snapshot.predictedResources) {
    if (resource.location === undefined) continue;
    for (const [key, value] of Object.entries(requiredTags(expected.environment))) {
      if (resource.tags?.[key] !== value) {
        add({ rule: 'tags', resource: resource.name, message: `needs the tag ${key}: ${value}` });
      }
    }
  }
};

/**
 * Any property that holds a password or secret (its name ends in either) holds
 * a parameter reference, never a value written in the code. A switch named
 * after one, like `passwordAuth`, doesn't end in it.
 */
const noSecretLiterals: Check = (snapshot, _expected, add) => {
  const walk = (resource: PredictedResource, value: unknown, trail: string): void => {
    if (typeof value !== 'object' || value === null) return;
    for (const [key, child] of Object.entries(value)) {
      const where = trail === '' ? key : `${trail}.${key}`;
      if (
        /(?:password|secret)$/i.test(key) &&
        typeof child === 'string' &&
        !/^\[parameters\('[^']+'\)\]$/.test(child)
      ) {
        add({
          rule: 'no-secret-literals',
          resource: resource.name,
          message: `${where} must come from a @secure() parameter, never a value in the code`,
        });
      }
      walk(resource, child, where);
    }
  };
  for (const resource of snapshot.predictedResources) walk(resource, resource.properties, '');
};

const database: Check = (snapshot, expected, add) => {
  for (const server of ofType(snapshot, TYPES.server)) {
    const problem = (rule: RuleId, message: string): void => {
      add({ rule, resource: server.name, message });
    };
    const properties = server.properties;
    // In a delegated subnet, with its private DNS zone: Azure then refuses public access outright.
    if (
      typeof at(properties, 'network', 'delegatedSubnetResourceId') !== 'string' ||
      typeof at(properties, 'network', 'privateDnsZoneArmResourceId') !== 'string' ||
      at(properties, 'network', 'publicNetworkAccess') === 'Enabled' ||
      at(properties, 'version') !== '18'
    ) {
      problem(
        'database-private',
        'runs PostgreSQL 18 in a delegated subnet with its private DNS zone, never public (ADR-002)',
      );
    }
    if (
      at(properties, 'authConfig', 'passwordAuth') !== 'Enabled' ||
      at(properties, 'authConfig', 'activeDirectoryAuth') !== 'Disabled'
    ) {
      problem('database-logins', 'takes password logins only, never Microsoft Entra ones (ADR-002, ADR-010)');
    }
    const retention = at(properties, 'backup', 'backupRetentionDays');
    const minimum = expected.environment === 'production' ? 35 : 7;
    if (typeof retention !== 'number' || retention < minimum) {
      problem('database-backup', `keeps at least ${String(minimum)} days of point-in-time restore (ADR-002)`);
    }
    const settings = new Map(
      ofType(snapshot, TYPES.setting)
        .filter((setting) => setting.id.startsWith(`${server.id}/`))
        .map((setting) => [setting.name.split('/').at(-1), at(setting.properties, 'value')]),
    );
    if (settings.get('require_secure_transport') !== 'on' || settings.get('ssl_min_protocol_version') !== 'TLSv1.3') {
      problem('database-tls', 'requires TLS on every connection, 1.3 at least');
    }
    if (settings.get('log_connections') !== 'on') {
      problem(
        'database-logins',
        'logs every login, so one by the admin or the backup role raises an alert (ADR-012 §2)',
      );
    }
  }
};

/** The database subnet lets in Postgres from the apps subnet and nothing else from the network. */
const databaseNetwork: Check = (snapshot, _expected, add) => {
  for (const network of ofType(snapshot, TYPES.network)) {
    const subnets = list(at(network.properties, 'subnets'));
    const named = (name: string): unknown => subnets.find((subnet) => at(subnet, 'name') === name);
    const delegatedTo = (subnet: unknown): unknown =>
      at(list(at(subnet, 'properties', 'delegations'))[0], 'properties', 'serviceName');
    const apps = named('apps');
    const databaseSubnet = named('database');
    const rulesId = at(databaseSubnet, 'properties', 'networkSecurityGroup', 'id');
    const inbound = list(
      at(ofType(snapshot, TYPES.rules).find((group) => group.id === rulesId)?.properties, 'securityRules'),
    )
      .map((rule) => at(rule, 'properties'))
      .filter((rule) => at(rule, 'direction') === 'Inbound');
    const allows = inbound.filter((rule) => at(rule, 'access') === 'Allow');
    const allow = allows[0];
    const onlyPostgresFromApps =
      allows.length === 1 &&
      at(allow, 'sourceAddressPrefix') === at(apps, 'properties', 'addressPrefix') &&
      at(allow, 'destinationPortRange') === '5432' &&
      at(allow, 'protocol') === 'Tcp';
    // Kept explicit, though the one-allow rule above already refuses any other
    // rule that matches this one without denying (the one mutant tests can't tell apart).
    const deniesRest = inbound.some(
      (rule) =>
        at(rule, 'access') === 'Deny' &&
        at(rule, 'protocol') === '*' &&
        at(rule, 'sourceAddressPrefix') === 'VirtualNetwork' &&
        at(rule, 'destinationAddressPrefix') === '*' &&
        at(rule, 'destinationPortRange') === '*' &&
        Number(at(rule, 'priority')) > Number(at(allow, 'priority')),
    );
    if (
      delegatedTo(apps) !== 'Microsoft.App/environments' ||
      delegatedTo(databaseSubnet) !== TYPES.server ||
      !onlyPostgresFromApps ||
      !deniesRest
    ) {
      add({
        rule: 'database-network',
        resource: network.name,
        message:
          'needs an apps subnet for Container Apps and a database subnet for Postgres that lets in port 5432 from the apps subnet only and denies the rest of the network',
      });
    }
  }
};

const vault: Check = (snapshot, _expected, add) => {
  for (const store of ofType(snapshot, TYPES.vault)) {
    const properties = store.properties;
    const acls = at(properties, 'networkAcls');
    const required: readonly (readonly [string, boolean])[] = [
      ['Azure roles only (enableRbacAuthorization)', at(properties, 'enableRbacAuthorization') === true],
      ['no access policies', list(at(properties, 'accessPolicies')).length === 0],
      ['purge protection', at(properties, 'enablePurgeProtection') === true],
      ['90 days of soft delete', at(properties, 'softDeleteRetentionInDays') === 90],
      [
        'no other Azure service fetching its secrets',
        ['enabledForDeployment', 'enabledForDiskEncryption', 'enabledForTemplateDeployment'].every(
          (key) => at(properties, key) === false,
        ),
      ],
      [
        'requests refused by default, with no exceptions for Azure services or addresses',
        at(acls, 'defaultAction') === 'Deny' && at(acls, 'bypass') === 'None' && list(at(acls, 'ipRules')).length === 0,
      ],
    ];
    for (const [what, holds] of required) {
      if (!holds) add({ rule: 'vault', resource: store.name, message: `must have ${what}` });
    }
  }
};

const workspaceAndQuota: Check = (snapshot, _expected, add) => {
  const alerts = ofType(snapshot, TYPES.alert);
  for (const workspace of ofType(snapshot, TYPES.workspace)) {
    const problem = (rule: RuleId, message: string): void => {
      add({ rule, resource: workspace.name, message });
    };
    if (at(workspace.properties, 'retentionInDays') !== 31) problem('workspace', 'keeps logs 31 days (ADR-013 rule 7)');
    if (at(workspace.properties, 'features', 'disableLocalAuth') !== true) {
      problem('workspace', 'takes no shared-key logins (disableLocalAuth)');
    }
    const cap = at(workspace.properties, 'workspaceCapping', 'dailyQuotaGb');
    if (typeof cap !== 'number' || cap <= 0) {
      problem('workspace', 'needs a daily cap (ADR-013 rule 6)');
      continue;
    }
    const criteria = alerts
      .filter((alert) => list(at(alert.properties, 'scopes')).includes(workspace.id))
      .flatMap((alert) => list(at(alert.properties, 'criteria', 'allOf')));
    const query = (criterion: unknown): string => String(at(criterion, 'query'));
    const warnsAt80 = criteria.some(
      (criterion) =>
        /^Usage\b/.test(query(criterion)) &&
        at(criterion, 'operator') === 'GreaterThan' &&
        at(criterion, 'threshold') === cap * 800,
    );
    const warnsAtCap = criteria.some((criterion) => query(criterion).includes('"OverQuota"'));
    if (!warnsAt80 || !warnsAtCap) {
      problem(
        'log-quota-alerts',
        `needs an alert above 80% of its ${String(cap)} GB cap (${String(cap * 800)} MB) and one when the cap is reached (SEC-AV-09)`,
      );
    }
  }
};

const alertRules: Check = (snapshot, _expected, add) => {
  for (const alert of ofType(snapshot, TYPES.alert)) {
    const criteria = list(at(alert.properties, 'criteria', 'allOf'));
    const customProperties = at(alert.properties, 'actions', 'customProperties');
    const countsOnly =
      alert.kind === 'LogAlert' &&
      criteria.length > 0 &&
      criteria.every((criterion) => {
        const column = singleSummaryColumn(String(at(criterion, 'query')));
        return (
          column !== undefined &&
          at(criterion, 'metricMeasureColumn') === column &&
          list(at(criterion, 'dimensions')).length === 0 &&
          at(criterion, 'resourceIdColumn') === undefined
        );
      }) &&
      (customProperties === undefined || Object.keys(customProperties as object).length === 0);
    if (!countsOnly) {
      add({
        rule: 'alert-counts-only',
        resource: alert.name,
        message:
          'must end in one summarize with no `by`, measured on that column, with no dimensions or custom properties: notifications leave the UAE (ADR-013 rule 3)',
      });
    }
    const runbook = /^SEV-([12])\. .+ Runbook: Incident-Response-Playbook\.md section [A-F]\.$/.exec(
      String(at(alert.properties, 'description')),
    );
    if (
      runbook === null ||
      Number(runbook[1]) !== at(alert.properties, 'severity') ||
      list(at(alert.properties, 'actions', 'actionGroups')).length === 0
    ) {
      add({
        rule: 'alert-runbook',
        resource: alert.name,
        message:
          'must reach the action group, and its description must start with its SEV (1 or 2, matching its severity) and end with its runbook section',
      });
    }
  }
};

const resourceLogs: Check = (snapshot, _expected, add) => {
  const workspaces = ofType(snapshot, TYPES.workspace);
  const wanted: readonly (readonly [string, (log: unknown) => boolean])[] = [
    [TYPES.vault, (log) => at(log, 'categoryGroup') === 'audit' || at(log, 'categoryGroup') === 'allLogs'],
    [TYPES.server, (log) => at(log, 'category') === 'PostgreSQLLogs'],
  ];
  for (const [type, isTheLog] of wanted) {
    for (const resource of ofType(snapshot, type)) {
      const sent = settingsOf(snapshot, resource).some(
        (setting) =>
          pointsAtWorkspace(at(setting.properties, 'workspaceId'), workspaces) &&
          at(setting.properties, 'logAnalyticsDestinationType') === 'Dedicated' &&
          list(at(setting.properties, 'logs')).some((log) => isTheLog(log) && at(log, 'enabled') === true),
      );
      if (!sent) {
        add({
          rule: 'resource-logs',
          resource: resource.name,
          message: 'must send its logs to the workspace, in resource-specific tables',
        });
      }
    }
  }
};

const activityLog: Check = (snapshot, _expected, add) => {
  const workspaces = ofType(snapshot, TYPES.workspace);
  const kept = ofType(snapshot, TYPES.diagnostics)
    .filter((setting) =>
      /^\/subscriptions\/[^/]+\/providers\/Microsoft\.Insights\/diagnosticSettings\//i.test(setting.id),
    )
    .some(
      (setting) =>
        pointsAtWorkspace(at(setting.properties, 'workspaceId'), workspaces) &&
        list(at(setting.properties, 'logs')).some(
          (log) => at(log, 'category') === 'Administrative' && at(log, 'enabled') === true,
        ),
    );
  if (!kept) {
    add({
      rule: 'activity-log',
      resource: 'the subscription',
      message: "must keep its activity log's Administrative events in the workspace (ADR-012 §6)",
    });
  }
};

const budget: Check = (snapshot, _expected, add) => {
  const notices = ofType(snapshot, TYPES.budget).flatMap((entry) =>
    Object.values((at(entry.properties, 'notifications') ?? {}) as Record<string, unknown>),
  );
  const has = (type: string, threshold: number): boolean =>
    notices.some(
      (notice) =>
        at(notice, 'enabled') === true &&
        at(notice, 'thresholdType') === type &&
        at(notice, 'threshold') === threshold &&
        list(at(notice, 'contactEmails')).length > 0,
    );
  if (!has('Actual', 80) || !has('Forecasted', 100)) {
    add({
      rule: 'budget',
      resource: 'the subscription',
      message: "needs a budget that emails at 80% of it and when the month's forecast passes it",
    });
  }
};

const CHECKS: readonly Check[] = [
  inCountry,
  stableApi,
  tagged,
  noSecretLiterals,
  database,
  databaseNetwork,
  vault,
  workspaceAndQuota,
  alertRules,
  resourceLogs,
  activityLog,
  budget,
];

/** Every rule a snapshot breaks; none for a deployment we can ship. */
export function policyProblems(snapshot: Snapshot, expected: Expectations): Problem[] {
  const problems: Problem[] = [];
  for (const check of CHECKS) {
    check(snapshot, expected, (problem) => {
      problems.push(problem);
    });
  }
  return problems;
}

/** One line per problem: `resource [rule] message`. */
export const describeProblem = ({ rule, resource, message }: Problem): string => `${resource} [${rule}] ${message}`;
