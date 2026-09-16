// What every Azure deployment of Agent X must be, checked on the resources its
// snapshot predicts (snapshot.ts), so a change to deploy/azure that breaks a
// rule fails CI before it reaches Azure. Each rule names the decision it
// enforces; each is proven able to fail (policy.test.ts).
//
// main.bicep builds every id one module hands another from its list of names,
// so a snapshot resolves them all. The rules compare those ids with the ids of
// the resources this deployment creates: a reference to anything else (a
// workspace abroad, another subnet) is refused, and so is a protection that is
// simply missing, not only one that is switched off. An environment's parts
// (secrets.bicep) are checked together with its foundation, so they too may
// point only at what the foundation creates.
import type { PredictedResource, Snapshot } from './snapshot.ts';

export type RuleId =
  | 'snapshot-complete'
  | 'required'
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
  | 'alert-delivery'
  | 'resource-logs'
  | 'log-destinations'
  | 'activity-log'
  | 'budget'
  | 'apps-environment'
  | 'apps-network'
  | 'apps-logs'
  | 'app-errors-alert'
  | 'identities'
  | 'vault-secrets'
  | 'secret-access'
  | 'jobs'
  | 'workload-secrets'
  | 'container-telemetry';

export interface Problem {
  readonly rule: RuleId;
  /** The resource's name, or "the deployment" for a rule about what is missing. */
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
  environment: 'Microsoft.App/managedEnvironments',
  identity: 'Microsoft.ManagedIdentity/userAssignedIdentities',
  job: 'Microsoft.App/jobs',
  network: 'Microsoft.Network/virtualNetworks',
  roleAssignment: 'Microsoft.Authorization/roleAssignments',
  rules: 'Microsoft.Network/networkSecurityGroups',
  rule: 'Microsoft.Network/networkSecurityGroups/securityRules',
  server: 'Microsoft.DBforPostgreSQL/flexibleServers',
  setting: 'Microsoft.DBforPostgreSQL/flexibleServers/configurations',
  vault: 'Microsoft.KeyVault/vaults',
  vaultSecret: 'Microsoft.KeyVault/vaults/secrets',
  workspace: 'Microsoft.OperationalInsights/workspaces',
} as const;

/** Types Azure offers only as global resources. None holds customer data or logs. */
const GLOBAL_TYPES: ReadonlySet<string> = new Set([TYPES.actionGroup, TYPES.dnsZone, TYPES.dnsLink]);

/** Types whose newest API version is a preview, with why the preview is used. */
export const PREVIEW_API_EXCEPTIONS: Readonly<Record<string, string>> = {
  [TYPES.diagnostics]:
    'Azure publishes diagnostic settings only in preview API versions after 2016-09-01, which predates category groups and resource-specific tables',
};

/** The one role besides the server admin whose login raises the alert (ADR-012 §2). */
const BACKUP_ROLE = 'agentx_backup';

/**
 * What counts as an error event: our logger's level and Zitadel's three, in
 * any case, since Zitadel's newer lines write "ERROR" (`in~` ignores case).
 */
const ERROR_LINES = 'where tostring(parse_json(Log).level) in~ ("error", "fatal", "panic")';

/**
 * Where a diagnostic setting could send logs other than a workspace: a storage
 * account, an event hub, a partner solution or a Service Bus rule, any of which
 * may sit outside the UAE.
 */
const OTHER_DESTINATIONS = [
  'storageAccountId',
  'eventHubAuthorizationRuleId',
  'eventHubName',
  'marketplacePartnerId',
  'serviceBusRuleId',
] as const;

/** The environment's logs that reach the workspace: every container's console, and the platform's own events. */
const APP_LOG_CATEGORIES: readonly unknown[] = ['ContainerAppConsoleLogs', 'ContainerAppSystemLogs'];

/**
 * The environment's other ways to send telemetry, each to a service that may
 * sit outside the UAE: Dapr's Application Insights, and (in preview API
 * versions only) the OpenTelemetry agent and Application Insights.
 */
const TELEMETRY_SETTINGS = [
  'daprAIConnectionString',
  'daprAIInstrumentationKey',
  'openTelemetryConfiguration',
  'appInsightsConfiguration',
] as const;

/**
 * Who reads which secret, one grant a line as "<app or job> reads <secret>"
 * (ADR-002 Amendment G2c): the description secrets.bicep gives each role
 * assignment. secrets.bicep holds the same list, by secret; it is written
 * again here so that changing who reads what takes both. A sentence each,
 * because GitGuardian read an app's name beside a secret's name as a password,
 * whichever held which (PRs #27 and #28). The set-up job reads every database
 * login, since each of its runs sets them all.
 */
const GRANTS: ReadonlySet<string> = new Set([
  'api reads db-app-password',
  'db-setup reads db-admin-password',
  'db-setup reads db-owner-password',
  'db-setup reads db-app-password',
  'db-setup reads db-backup-password',
  'db-setup reads db-zitadel-password',
  'migrate reads db-owner-password',
  'zitadel reads db-zitadel-password',
  'zitadel reads zitadel-masterkey',
  'zitadel reads login-client-public-key',
  'zitadel-init reads db-zitadel-password',
  'zitadel-setup reads db-zitadel-password',
  'zitadel-setup reads zitadel-masterkey',
  'zitadel-setup reads zitadel-admin-password',
  'login reads login-client-private-key',
]);

const GRANT = / reads /;

/** Every secret an app or job reads: the vault holds these and no other. */
const VAULT_SECRETS: ReadonlySet<string> = new Set([...GRANTS].map((grant) => grant.split(GRANT)[1] ?? ''));

/** The secrets one app or job reads, from GRANTS: what it is given, and nothing besides. */
const secretsRead = (workload: string): ReadonlySet<string> =>
  new Set(
    [...GRANTS].flatMap((grant) => {
      const [reader, secret] = grant.split(GRANT);
      return reader === workload && secret !== undefined ? [secret] : [];
    }),
  );

/**
 * Every job the deployment runs, each started by hand (ADR-002 Amendment G2d):
 * a server's roles and databases, the app's migrations, and Zitadel's own init
 * and setup. The apps that serve traffic are checked the same way when G2d-2
 * adds them; this list is what must be there.
 */
const JOB_WORKLOADS: readonly string[] = ['db-setup', 'migrate', 'zitadel-init', 'zitadel-setup'];

/** Where Zitadel's images come from: its server and its login pages (ADR-003 Amendment S10). */
const ZITADEL_IMAGES = 'ghcr.io/zitadel/';

/**
 * The only settings a container may take a secret in, by image, with why: an
 * environment is copied into crash output and inherited by every child process,
 * so anything a program can read from a file is mounted as one. Ours takes every
 * login as a file (`AGENTX_DB_*_PASSWORD_FILE`) and Zitadel's master key has a
 * file form it uses (`--masterkeyFile`, checked against the pinned image). These
 * are what is left: Zitadel reads them from its settings or a config file, and a
 * config file would have to hold the value itself.
 */
const SECRETS_IN_ENVIRONMENT: readonly {
  readonly images: string;
  readonly settings: RegExp;
  readonly reason: string;
}[] = [
  {
    images: ZITADEL_IMAGES,
    settings: /^ZITADEL_(?:DATABASE_POSTGRES_(?:USER|ADMIN)_PASSWORD|FIRSTINSTANCE_ORG_HUMAN_PASSWORD)$/,
    reason: 'Zitadel offers no file form for a database login or its first admin’s password',
  },
];

/**
 * What a Zitadel container must say outright, so no default of a later version
 * sends anything out of the UAE (ADR-013, SEC-DATA-08): no daily report to
 * zitadel.com, no metrics endpoint. Tracing is a setting of the server it starts,
 * not of these jobs (proven against the image: `init` never reads it), and joins
 * this list with the apps in G2d-2.
 */
const TELEMETRY_OFF: Readonly<Record<string, string>> = {
  ZITADEL_SERVICEPING_ENABLED: 'false',
  ZITADEL_METRICS_TYPE: 'none',
};

/** The one workload profile the environment offers (ADR-002 Amendment G2b). */
const WORKLOAD_PROFILE = 'Consumption';

/** The longest a job's one run may take, so a stuck run can't hold a replica for a day. */
const LONGEST_RUN_SECONDS = 3600;

/** Secrets created once and never written again: Zitadel can't read what it encrypted with another master key. */
const CREATED_ONCE: ReadonlySet<string> = new Set(['zitadel-masterkey']);

/** Key Vault Secrets User, by its id: reads a secret's value and nothing else (Microsoft's built-in role). */
const VAULT_READER_ROLE = '4633458b-17de-408a-b874-0445c86b69e6';

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

/** A value as the string it must be, or an empty string for anything else, which no rule accepts. */
const text = (value: unknown): string => (typeof value === 'string' ? value : '');

/** An object with no keys, or nothing at all. */
const isEmpty = (value: unknown): boolean =>
  value === undefined || value === null || (typeof value === 'object' && Object.keys(value).length === 0);

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
 * comments and brackets, and `keep` gets everything else. A pipe in a regex's
 * alternation or in a subquery's brackets is never at the top level.
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

/**
 * Whether a query is exactly `table | stage | … | summarize Name = aggregation`:
 * the same stages, in order, whatever the spacing around its pipes.
 */
const queryIs = (query: unknown, table: string, filters: readonly string[], aggregation: string): boolean => {
  const stages = kqlStages(String(query));
  const last = stages.at(-1) ?? '';
  return (
    stages.length === filters.length + 2 &&
    stages[0] === table &&
    filters.every((filter, index) => stages[index + 1] === filter) &&
    last.replace(/^summarize\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*/, '') === aggregation
  );
};

type Check = (snapshot: Snapshot, expected: Expectations, add: (problem: Problem) => void) => void;

const ofType = (snapshot: Snapshot, type: string): readonly PredictedResource[] =>
  snapshot.predictedResources.filter((resource) => resource.type === type);

/** Settings attached to a resource: their ids sit under the resource's own. */
const settingsOf = (snapshot: Snapshot, resource: PredictedResource): readonly PredictedResource[] =>
  ofType(snapshot, TYPES.diagnostics).filter((setting) =>
    setting.id.toLowerCase().startsWith(`${resource.id}/providers/${TYPES.diagnostics}/`.toLowerCase()),
  );

/** The ids of the workspaces this deployment creates: a reference to any other id is refused. */
const workspaceIds = (snapshot: Snapshot): ReadonlySet<unknown> =>
  new Set(ofType(snapshot, TYPES.workspace).map((workspace) => workspace.id));

/** An action group of this deployment that is switched on and reaches someone. */
const deliversAlerts = (snapshot: Snapshot, id: unknown): boolean =>
  ofType(snapshot, TYPES.actionGroup).some(
    (group) =>
      group.id === id &&
      at(group.properties, 'enabled') === true &&
      list(at(group.properties, 'emailReceivers')).length + list(at(group.properties, 'azureAppPushReceivers')).length >
        0,
  );

const complete: Check = (snapshot, _expected, add) => {
  if (list(snapshot.diagnostics).length > 0) {
    add({
      rule: 'snapshot-complete',
      resource: 'the deployment',
      message: `bicep snapshot reported ${String(list(snapshot.diagnostics).length)} diagnostic(s), so what it predicts may be partial: fix them first`,
    });
  }
};

/** The protections exist at all: a rule that checks each resource of a type passes when there are none. */
const required: Check = (snapshot, _expected, add) => {
  const counts: readonly (readonly [string, string, number, number])[] = [
    ['the log workspace', TYPES.workspace, 1, 1],
    ['an action group', TYPES.actionGroup, 1, Infinity],
    ['the network', TYPES.network, 1, 1],
    ['the key vault', TYPES.vault, 1, Infinity],
    ['the Postgres server', TYPES.server, 1, Infinity],
    ['the Container Apps environment', TYPES.environment, 1, 1],
  ];
  for (const [what, type, least, most] of counts) {
    const found = ofType(snapshot, type).length;
    if (found < least || found > most) {
      add({
        rule: 'required',
        resource: 'the deployment',
        message: `needs ${least === most ? 'exactly one' : 'at least one'} ${what} (${type}); the snapshot has ${String(found)}`,
      });
    }
  }
};

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

const PARAMETER_REFERENCE = /^\[parameters\('([^']+)'\)\]$/;

/** The parameter a value is, or undefined for anything else. */
const parameterOf = (value: unknown): string | undefined =>
  typeof value === 'string' ? PARAMETER_REFERENCE.exec(value)?.[1] : undefined;

/**
 * A secret holds a parameter reference, never a value written in the code:
 * any property whose name ends in "password" or "secret" (a switch named after
 * one, like `passwordAuth`, doesn't), a key vault secret's value, and the value
 * of every entry in a `secrets` list (Container Apps' own secrets).
 */
const noSecretLiterals: Check = (snapshot, _expected, add) => {
  const refuse = (resource: PredictedResource, where: string): void => {
    add({
      rule: 'no-secret-literals',
      resource: resource.name,
      message: `${where} must come from a @secure() parameter, never a value in the code`,
    });
  };
  const literal = (value: unknown): boolean => typeof value === 'string' && !PARAMETER_REFERENCE.test(value);
  const walk = (resource: PredictedResource, value: unknown, trail: string): void => {
    if (typeof value !== 'object' || value === null) return;
    for (const [key, child] of Object.entries(value)) {
      const where = trail === '' ? key : `${trail}.${key}`;
      if (/(?:password|secret)$/i.test(key) && literal(child)) refuse(resource, where);
      if (key === 'secrets') {
        list(child).forEach((entry, index) => {
          if (literal(at(entry, 'value'))) refuse(resource, `${where}[${String(index)}].value`);
        });
      }
      walk(resource, child, where);
    }
  };
  for (const resource of snapshot.predictedResources) {
    if (resource.type === TYPES.vaultSecret && literal(at(resource.properties, 'value'))) refuse(resource, 'value');
    walk(resource, resource.properties, '');
  }
};

/**
 * The same for a parameters file, which the snapshot can't show: a secure
 * parameter's value comes from the deploying shell, with no default written
 * down, or from a key vault.
 */
export function paramsFileProblems(file: string, text: string, secureParameters: readonly string[]): Problem[] {
  return secureParameters.flatMap((name) => {
    const assignment = new RegExp(`^param\\s+${name}\\s*=\\s*(.+)$`, 'm').exec(text)?.[1]?.trim();
    const fromShell = assignment !== undefined && /^readEnvironmentVariable\('[A-Z0-9_]+'\)$/.test(assignment);
    const fromVault = assignment?.startsWith('az.getSecret(') === true;
    return assignment === undefined || fromShell || fromVault
      ? []
      : [
          {
            rule: 'no-secret-literals' as const,
            resource: file,
            message: `${name} is secure: read it with readEnvironmentVariable('NAME') and no default, or az.getSecret, never a value in the file`,
          },
        ];
  });
}

/**
 * What only a compiled template shows, since a snapshot drops a resource's
 * options and any condition Bicep can settle offline: every key vault secret
 * it writes is written either only when its own value is given (a condition
 * exactly `not(empty(<its value>))`) or only if it doesn't exist yet
 * (`@onlyIfNotExists()`), never both and never on every run. With
 * `vault-secrets`, that leaves Zitadel's master key created once, even under a
 * condition that would vanish from the snapshot (security review, S15), and
 * every other secret written only when given. A module's own template is read
 * the same way.
 */
export function templateProblems(file: string, template: unknown): Problem[] {
  const resources = at(template, 'resources');
  // Language version 2.0 keys resources by their symbolic names; 1.0 lists them.
  const entries: readonly (readonly [string, unknown])[] = Array.isArray(resources)
    ? resources.map((resource: unknown, index) => {
        const name = at(resource, 'name');
        return [typeof name === 'string' ? name : `resource ${String(index)}`, resource] as const;
      })
    : Object.entries((resources ?? {}) as Record<string, unknown>);
  return entries.flatMap(([name, resource]): Problem[] => {
    if (at(resource, 'type') === 'Microsoft.Resources/deployments') {
      return templateProblems(file, at(resource, 'properties', 'template'));
    }
    if (at(resource, 'type') !== TYPES.vaultSecret || at(resource, 'existing') === true) return [];
    const condition = at(resource, 'condition');
    const once = at(resource, '@options', 'onlyIfNotExists') !== undefined;
    const value = at(resource, 'properties', 'value');
    const expression = typeof value === 'string' ? /^\[(.+)\]$/.exec(value)?.[1] : undefined;
    const whenGiven = expression !== undefined && condition === `[not(empty(${expression}))]`;
    const problem = (message: string): Problem[] => [{ rule: 'vault-secrets', resource: `${file}: ${name}`, message }];
    if (once && condition !== undefined) {
      return problem(
        "is written on a condition and only if it doesn't exist: a secret that rotates takes the condition alone, the master key @onlyIfNotExists() alone",
      );
    }
    if (!once && !whenGiven) {
      return problem(
        condition === undefined
          ? 'is written on every run: write it only when its value is given (if (!empty(value))), or create it once (@onlyIfNotExists())'
          : 'is written on a condition other than its own value being given, which a snapshot may settle and drop: write it only if (!empty(value)), or create it once (@onlyIfNotExists())',
      );
    }
    return [];
  });
}

const delegatedTo = (subnet: unknown): unknown =>
  at(list(at(subnet, 'properties', 'delegations'))[0], 'properties', 'serviceName');

/** Where a server must sit: a Postgres-delegated subnet of this deployment's network. */
const postgresSubnets = (snapshot: Snapshot): readonly { id: string; subnet: unknown; network: PredictedResource }[] =>
  ofType(snapshot, TYPES.network).flatMap((network) =>
    list(at(network.properties, 'subnets'))
      .filter((subnet) => delegatedTo(subnet) === TYPES.server)
      .map((subnet) => ({ id: `${network.id}/subnets/${String(at(subnet, 'name'))}`, subnet, network })),
  );

const database: Check = (snapshot, expected, add) => {
  const workspaces = workspaceIds(snapshot);
  for (const server of ofType(snapshot, TYPES.server)) {
    const problem = (rule: RuleId, message: string): void => {
      add({ rule, resource: server.name, message });
    };
    const properties = server.properties;
    // In a Postgres subnet of this deployment's network, its DNS zone one this
    // deployment creates and links to that network: Azure then refuses public access outright.
    const home = postgresSubnets(snapshot).find(
      ({ id }) => id === at(properties, 'network', 'delegatedSubnetResourceId'),
    );
    const zone = at(properties, 'network', 'privateDnsZoneArmResourceId');
    // Only a server in a subnet of ours has a network for its zone to be linked to.
    const zoneLinked =
      home !== undefined &&
      ofType(snapshot, TYPES.dnsLink).some(
        (link) =>
          link.id.startsWith(`${String(zone)}/virtualNetworkLinks/`) &&
          at(link.properties, 'virtualNetwork', 'id') === home.network.id,
      );
    if (
      !ofType(snapshot, TYPES.dnsZone).some((candidate) => candidate.id === zone) ||
      !zoneLinked ||
      at(properties, 'network', 'publicNetworkAccess') === 'Enabled' ||
      at(properties, 'version') !== '18'
    ) {
      problem(
        'database-private',
        "runs PostgreSQL 18 in this deployment's Postgres subnet, with a private DNS zone linked to that network, never public (ADR-002)",
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
    // ADR-012 §2: every login is logged, and one by the admin or the backup
    // role raises a SEV-1 alert that notifies on every window it happens in.
    const admin = String(at(properties, 'administratorLogin'));
    const pattern = `@"^connection authorized: user=(${admin}|${BACKUP_ROLE}) "`;
    const alerted = ofType(snapshot, TYPES.alert).some(
      (alert) =>
        at(alert.properties, 'enabled') === true &&
        at(alert.properties, 'severity') === 1 &&
        at(alert.properties, 'autoMitigate') === false &&
        list(at(alert.properties, 'scopes')).some((scope) => workspaces.has(scope)) &&
        list(at(alert.properties, 'criteria', 'allOf')).some((criterion) =>
          queryIs(at(criterion, 'query'), 'PGSQLServerLogs', [`where Message matches regex ${pattern}`], 'count()'),
        ),
    );
    if (settings.get('log_connections') !== 'on' || !alerted) {
      problem(
        'database-logins',
        `logs every login, and an enabled, stateless SEV-1 alert on the workspace fires when ${admin} or ${BACKUP_ROLE} logs in (ADR-012 §2)`,
      );
    }
  }
};

/**
 * A subnet's inbound rules, from the rules group of this deployment attached to
 * it: those declared inside the group, and any declared as resources of their
 * own under it, which Azure adds to the same group.
 */
const inboundRules = (snapshot: Snapshot, subnet: unknown): readonly unknown[] => {
  const rulesId = at(subnet, 'properties', 'networkSecurityGroup', 'id');
  const inside = list(
    at(ofType(snapshot, TYPES.rules).find((group) => group.id === rulesId)?.properties, 'securityRules'),
  );
  const apart = ofType(snapshot, TYPES.rule).filter((rule) => rule.id.startsWith(`${String(rulesId)}/securityRules/`));
  return [...inside, ...apart]
    .map((rule) => at(rule, 'properties'))
    .filter((rule) => at(rule, 'direction') === 'Inbound');
};

const allowing = (inbound: readonly unknown[]): readonly unknown[] =>
  inbound.filter((rule) => at(rule, 'access') === 'Allow');

/**
 * A rule that denies the rest of the network, after every rule that allows:
 * it overrides Azure's default one that lets the whole network in. Kept
 * explicit, though each caller's own list of allowed rules already refuses any
 * rule matching this one without denying (the one mutant tests can't tell apart).
 */
const deniesRestOfNetwork = (inbound: readonly unknown[]): boolean => {
  const lastAllow = Math.max(...allowing(inbound).map((rule) => Number(at(rule, 'priority'))));
  return inbound.some(
    (rule) =>
      at(rule, 'access') === 'Deny' &&
      at(rule, 'protocol') === '*' &&
      at(rule, 'sourceAddressPrefix') === 'VirtualNetwork' &&
      at(rule, 'destinationAddressPrefix') === '*' &&
      at(rule, 'destinationPortRange') === '*' &&
      Number(at(rule, 'priority')) > lastAllow,
  );
};

const appsSubnetOf = (network: PredictedResource): unknown =>
  list(at(network.properties, 'subnets')).find((subnet) => at(subnet, 'name') === 'apps');

/**
 * Every Postgres subnet lets in port 5432 from the apps subnet and from itself
 * (Microsoft: the server's own features need 5432 inside its subnet), and
 * nothing else from the network; it keeps the Storage endpoint that carries the
 * server's write-ahead log.
 */
const databaseNetwork: Check = (snapshot, _expected, add) => {
  for (const network of ofType(snapshot, TYPES.network)) {
    const apps = appsSubnetOf(network);
    const appsPrefix = at(apps, 'properties', 'addressPrefix');
    const own = postgresSubnets(snapshot).filter((entry) => entry.network.id === network.id);
    const safe = (subnet: unknown): boolean => {
      const prefix = at(subnet, 'properties', 'addressPrefix');
      const inbound = inboundRules(snapshot, subnet);
      const allows = allowing(inbound);
      const onlyPostgres = allows.every(
        (rule) =>
          at(rule, 'protocol') === 'Tcp' &&
          at(rule, 'destinationPortRange') === '5432' &&
          at(rule, 'destinationAddressPrefix') === prefix &&
          [appsPrefix, prefix].includes(at(rule, 'sourceAddressPrefix')),
      );
      const fromApps = allows.some((rule) => at(rule, 'sourceAddressPrefix') === appsPrefix);
      const fromItself = allows.some((rule) => at(rule, 'sourceAddressPrefix') === prefix);
      const keepsStorage = list(at(subnet, 'properties', 'serviceEndpoints')).some(
        (endpoint) => at(endpoint, 'service') === 'Microsoft.Storage',
      );
      return onlyPostgres && fromApps && fromItself && deniesRestOfNetwork(inbound) && keepsStorage;
    };
    if (
      delegatedTo(apps) !== 'Microsoft.App/environments' ||
      own.length === 0 ||
      !own.every(({ subnet }) => safe(subnet))
    ) {
      add({
        rule: 'database-network',
        resource: network.name,
        message:
          'needs an apps subnet for Container Apps, and Postgres subnets that let in port 5432 only from the apps subnet and themselves, deny the rest of the network, and keep their Storage endpoint',
      });
    }
  }
};

/**
 * The apps subnet has rules of its own, from Microsoft's list for a workload
 * profiles environment: the load balancer's probes and the subnet's own
 * traffic let in, and the rest of the network denied after them. Public
 * traffic reaches the apps through the environment's public IP, not through
 * the subnet (Microsoft), so these rules keep the rest of the network out.
 */
const appsNetwork: Check = (snapshot, _expected, add) => {
  for (const network of ofType(snapshot, TYPES.network)) {
    const apps = appsSubnetOf(network);
    const prefix = at(apps, 'properties', 'addressPrefix');
    const inbound = inboundRules(snapshot, apps);
    const allows = allowing(inbound);
    const probes = (rule: unknown): boolean =>
      at(rule, 'protocol') === 'Tcp' &&
      at(rule, 'sourceAddressPrefix') === 'AzureLoadBalancer' &&
      at(rule, 'destinationAddressPrefix') === prefix &&
      at(rule, 'destinationPortRange') === '30000-32767';
    const itself = (rule: unknown): boolean =>
      at(rule, 'sourceAddressPrefix') === prefix && at(rule, 'destinationAddressPrefix') === prefix;
    if (
      !allows.every((rule) => probes(rule) || itself(rule)) ||
      !allows.some(probes) ||
      !allows.some(itself) ||
      !deniesRestOfNetwork(inbound)
    ) {
      add({
        rule: 'apps-network',
        resource: network.name,
        message:
          "needs rules on its apps subnet that let in only the load balancer's probes (TCP 30000-32767) and the subnet itself, then deny the rest of the network",
      });
    }
  }
};

/** Where the apps may run, and the only subnet the database and the key vault let in. */
const appsSubnetIds = (snapshot: Snapshot): ReadonlySet<unknown> =>
  new Set(
    ofType(snapshot, TYPES.network)
      .filter((network) => appsSubnetOf(network) !== undefined)
      .map((network) => `${network.id}/subnets/apps`),
  );

const vault: Check = (snapshot, _expected, add) => {
  const appsSubnets = appsSubnetIds(snapshot);
  for (const store of ofType(snapshot, TYPES.vault)) {
    const properties = store.properties;
    const acls = at(properties, 'networkAcls');
    const subnetRules = list(at(acls, 'virtualNetworkRules'));
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
      [
        "this deployment's apps subnet as the only subnet let in",
        subnetRules.length === 1 && appsSubnets.has(at(subnetRules[0], 'id')),
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
    // Enabled rules on this workspace, their queries exactly the ones the logging standard names.
    const criteria = alerts
      .filter(
        (alert) =>
          at(alert.properties, 'enabled') === true && list(at(alert.properties, 'scopes')).includes(workspace.id),
      )
      .flatMap((alert) => list(at(alert.properties, 'criteria', 'allOf')));
    const warnsAt80 = criteria.some(
      (criterion) =>
        queryIs(at(criterion, 'query'), 'Usage', ['where IsBillable'], 'sum(Quantity)') &&
        at(criterion, 'operator') === 'GreaterThan' &&
        at(criterion, 'threshold') === cap * 800,
    );
    const warnsAtCap = criteria.some(
      (criterion) =>
        queryIs(
          at(criterion, 'query'),
          '_LogOperation',
          ['where Category =~ "Ingestion"', 'where Detail contains "OverQuota"'],
          'count()',
        ) &&
        at(criterion, 'operator') === 'GreaterThan' &&
        at(criterion, 'threshold') === 0,
    );
    if (!warnsAt80 || !warnsAtCap) {
      problem(
        'log-quota-alerts',
        `needs an enabled alert above 80% of its ${String(cap)} GB cap (${String(cap * 800)} MB) and one when the cap is reached (SEC-AV-09)`,
      );
    }
  }
};

const alertRules: Check = (snapshot, _expected, add) => {
  for (const alert of ofType(snapshot, TYPES.alert)) {
    const criteria = list(at(alert.properties, 'criteria', 'allOf'));
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
      isEmpty(at(alert.properties, 'actions', 'customProperties'));
    if (!countsOnly) {
      add({
        rule: 'alert-counts-only',
        resource: alert.name,
        message:
          'must end in one summarize with no `by`, measured on that column, with no dimensions or custom properties: notifications leave the UAE (ADR-013 rule 3)',
      });
    }
    const severity = at(alert.properties, 'severity');
    const runbook = /^SEV-([12])\. .+ Runbook: Incident-Response-Playbook\.md section [A-F]\.$/.exec(
      String(at(alert.properties, 'description')),
    );
    if (runbook === null || Number(runbook[1]) !== severity) {
      add({
        rule: 'alert-runbook',
        resource: alert.name,
        message:
          'its description must start with its SEV (1 or 2, matching its severity) and end with its runbook section',
      });
    }
    const groups = list(at(alert.properties, 'actions', 'actionGroups'));
    if (
      at(alert.properties, 'enabled') !== true ||
      groups.length === 0 ||
      !groups.every((group) => deliversAlerts(snapshot, group)) ||
      (severity === 1 && at(alert.properties, 'autoMitigate') !== false)
    ) {
      add({
        rule: 'alert-delivery',
        resource: alert.name,
        message:
          "must be enabled and reach this deployment's action groups, each switched on with someone to tell; a SEV-1 alert is stateless, so it notifies every time",
      });
    }
  }
};

const resourceLogs: Check = (snapshot, _expected, add) => {
  const workspaces = workspaceIds(snapshot);
  const wanted: readonly (readonly [string, (log: unknown) => boolean])[] = [
    [TYPES.vault, (log) => at(log, 'categoryGroup') === 'audit' || at(log, 'categoryGroup') === 'allLogs'],
    [TYPES.server, (log) => at(log, 'category') === 'PostgreSQLLogs'],
  ];
  for (const [type, isTheLog] of wanted) {
    for (const resource of ofType(snapshot, type)) {
      const sent = settingsOf(snapshot, resource).some(
        (setting) =>
          workspaces.has(at(setting.properties, 'workspaceId')) &&
          at(setting.properties, 'logAnalyticsDestinationType') === 'Dedicated' &&
          list(at(setting.properties, 'logs')).some((log) => isTheLog(log) && at(log, 'enabled') === true),
      );
      if (!sent) {
        add({
          rule: 'resource-logs',
          resource: resource.name,
          message: "must send its logs to this deployment's workspace, in resource-specific tables",
        });
      }
    }
  }
};

/** Every diagnostic setting sends to this deployment's workspace, and nowhere else (ADR-013). */
const logDestinations: Check = (snapshot, _expected, add) => {
  const workspaces = workspaceIds(snapshot);
  for (const setting of ofType(snapshot, TYPES.diagnostics)) {
    const elsewhere = OTHER_DESTINATIONS.filter(
      (key) => !isEmpty(at(setting.properties, key)) && at(setting.properties, key) !== '',
    );
    if (!workspaces.has(at(setting.properties, 'workspaceId')) || elsewhere.length > 0) {
      add({
        rule: 'log-destinations',
        resource: setting.name,
        message: `must send to this deployment's workspace only${elsewhere.length > 0 ? `, not to ${elsewhere.join(', ')}` : ''}: logs stay in the UAE (ADR-013)`,
      });
    }
  }
};

const activityLog: Check = (snapshot, _expected, add) => {
  const workspaces = workspaceIds(snapshot);
  const kept = ofType(snapshot, TYPES.diagnostics)
    .filter((setting) =>
      /^\/subscriptions\/[^/]+\/providers\/Microsoft\.Insights\/diagnosticSettings\//i.test(setting.id),
    )
    .some(
      (setting) =>
        workspaces.has(at(setting.properties, 'workspaceId')) &&
        list(at(setting.properties, 'logs')).some(
          (log) => at(log, 'category') === 'Administrative' && at(log, 'enabled') === true,
        ),
    );
  if (!kept) {
    add({
      rule: 'activity-log',
      resource: 'the deployment',
      message: "must keep the subscription's Administrative events in this deployment's workspace (ADR-012 §6)",
    });
  }
};

const budget: Check = (snapshot, _expected, add) => {
  const budgets = ofType(snapshot, TYPES.budget);
  const notices = budgets.flatMap((entry) =>
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
  // Azure takes a monthly budget's start only as the first of a month, and only the current month or later on creation.
  const starts = budgets.every((entry) =>
    /^\d{4}-(0[1-9]|1[0-2])-01$/.test(String(at(entry.properties, 'timePeriod', 'startDate'))),
  );
  if (!has('Actual', 80) || !has('Forecasted', 100) || !starts) {
    add({
      rule: 'budget',
      resource: 'the deployment',
      message:
        "needs a budget, starting on the first of a month, that emails at 80% of it and when the month's forecast passes it",
    });
  }
};

/**
 * The environment runs in this deployment's apps subnet (the one subnet the
 * database and the key vault let in), on the Consumption profile alone (a
 * dedicated one is billed while idle: a decision, never a default), with the
 * traffic inside it encrypted, and its logs sent through Azure Monitor: a
 * diagnostic setting needs no key, where the Log Analytics destination sends
 * with the workspace's shared key (ADR-013 Amendment G1). It has no other way
 * to send telemetry (ADR-013 rule 1).
 */
const appsEnvironment: Check = (snapshot, _expected, add) => {
  const appsSubnets = appsSubnetIds(snapshot);
  for (const environment of ofType(snapshot, TYPES.environment)) {
    const properties = environment.properties;
    const profiles = list(at(properties, 'workloadProfiles'));
    const required: readonly (readonly [string, boolean])[] = [
      ["this deployment's apps subnet", appsSubnets.has(at(properties, 'vnetConfiguration', 'infrastructureSubnetId'))],
      [
        'the Consumption workload profile alone',
        profiles.length === 1 && at(profiles[0], 'workloadProfileType') === 'Consumption',
      ],
      ['peer-to-peer encryption', at(properties, 'peerTrafficConfiguration', 'encryption', 'enabled') === true],
      [
        'its logs sent through Azure Monitor',
        at(properties, 'appLogsConfiguration', 'destination') === 'azure-monitor',
      ],
      [
        'no other telemetry exit (Dapr, OpenTelemetry or Application Insights settings)',
        TELEMETRY_SETTINGS.every((key) => isEmpty(at(properties, key)) || at(properties, key) === ''),
      ],
    ];
    for (const [what, holds] of required) {
      if (!holds) add({ rule: 'apps-environment', resource: environment.name, message: `must run with ${what}` });
    }
  }
};

/**
 * The environment's console and system logs reach this deployment's workspace
 * in resource-specific tables, and no other log of it is sent anywhere. Above
 * all its HTTP log, which a category group would also bring in: it records
 * every client's address and full URL, which our request logs leave out
 * (ADR-011 §7).
 */
const appsLogs: Check = (snapshot, _expected, add) => {
  const workspaces = workspaceIds(snapshot);
  for (const environment of ofType(snapshot, TYPES.environment)) {
    const enabledLogs = (setting: PredictedResource): readonly unknown[] =>
      list(at(setting.properties, 'logs')).filter((log) => at(log, 'enabled') === true);
    const settings = settingsOf(snapshot, environment);
    const sends = (category: string): boolean =>
      settings.some(
        (setting) =>
          workspaces.has(at(setting.properties, 'workspaceId')) &&
          at(setting.properties, 'logAnalyticsDestinationType') === 'Dedicated' &&
          enabledLogs(setting).some((log) => at(log, 'category') === category),
      );
    // A category group names no category, so it is refused here too.
    const otherLog = settings.some((setting) =>
      enabledLogs(setting).some((log) => !APP_LOG_CATEGORIES.includes(at(log, 'category'))),
    );
    if (!APP_LOG_CATEGORIES.every((category) => sends(String(category))) || otherLog) {
      add({
        rule: 'apps-logs',
        resource: environment.name,
        message:
          "must send its console and system logs, and no other, to this deployment's workspace in resource-specific tables: never its HTTP log or a category group (client addresses, ADR-011 §7)",
      });
    }
  }
};

/** An enabled alert on the workspace counts the apps' error events (logging standard §5, "Error spike"). */
const appErrorsAlert: Check = (snapshot, _expected, add) => {
  const workspaces = workspaceIds(snapshot);
  for (const environment of ofType(snapshot, TYPES.environment)) {
    const alerted = ofType(snapshot, TYPES.alert).some(
      (alert) =>
        at(alert.properties, 'enabled') === true &&
        list(at(alert.properties, 'scopes')).some((scope) => workspaces.has(scope)) &&
        list(at(alert.properties, 'criteria', 'allOf')).some((criterion) => {
          const threshold = at(criterion, 'threshold');
          return (
            queryIs(at(criterion, 'query'), 'ContainerAppConsoleLogs', [ERROR_LINES], 'count()') &&
            at(criterion, 'operator') === 'GreaterThan' &&
            typeof threshold === 'number' &&
            threshold >= 0
          );
        }),
    );
    if (!alerted) {
      add({
        rule: 'app-errors-alert',
        resource: environment.name,
        message: "needs an enabled alert on this deployment's workspace that counts the apps' error events",
      });
    }
  }
};

/**
 * Every identity is usable only by resources in its own region (isolation
 * scope Regional, Microsoft's recommendation): a resource created elsewhere
 * can't take it on (ADR-009).
 */
const identities: Check = (snapshot, _expected, add) => {
  for (const identity of ofType(snapshot, TYPES.identity)) {
    if (at(identity.properties, 'isolationScope') !== 'Regional') {
      add({
        rule: 'identities',
        resource: identity.name,
        message: 'must be usable only in its own region (isolationScope Regional)',
      });
    }
  }
};

/** A secret's own name, the last part of its id (its resource name is `<vault>/<secret>`). */
const secretNameOf = (secret: PredictedResource): string => secret.id.slice(secret.id.lastIndexOf('/') + 1);

/** The vault a secret is in: its id up to `/secrets/`. */
const vaultOf = (secret: PredictedResource): string => secret.id.slice(0, secret.id.lastIndexOf('/secrets/'));

const WRITTEN_WHEN_GIVEN = /^\[not\(empty\(parameters\('([^']+)'\)\)\)\]$/;

/**
 * The vault holds exactly the secrets the apps read, each once and in a vault
 * of this deployment (ADR-002 Amendment G2c). Each is written only when its
 * value is given, on a condition naming the parameter its value comes from, so
 * a run that rotates one secret leaves the rest as they are. Zitadel's master
 * key has no such condition, since it is created once: a snapshot drops the
 * option that does that, so `templateProblems` reads it from the compiled
 * template. A value written into the code is `no-secret-literals`'s to refuse.
 */
const vaultSecrets: Check = (snapshot, _expected, add) => {
  const vaults = new Set(ofType(snapshot, TYPES.vault).map((vault) => vault.id));
  const secrets = ofType(snapshot, TYPES.vaultSecret);
  for (const secret of secrets) {
    const name = secretNameOf(secret);
    const problem = (message: string): void => {
      add({ rule: 'vault-secrets', resource: secret.name, message });
    };
    if (!vaults.has(vaultOf(secret))) problem("must be in this deployment's key vault");
    if (!VAULT_SECRETS.has(name)) {
      problem('is no secret an app or job reads (GRANTS): one nobody needs is one more to leak');
    }
    const condition = WRITTEN_WHEN_GIVEN.exec(secret.condition ?? '')?.[1];
    const value = parameterOf(at(secret.properties, 'value'));
    if (CREATED_ONCE.has(name)) {
      if (secret.condition !== undefined) {
        problem('is created once (@onlyIfNotExists()), never on a condition a later run could meet');
      }
    } else if (condition === undefined || (value !== undefined && value !== condition)) {
      problem(
        'must be written only when its value is given (if (!empty(value))), so a run that rotates another secret leaves this one',
      );
    }
  }
  for (const name of VAULT_SECRETS) {
    const count = secrets.filter((secret) => secretNameOf(secret) === name).length;
    if (count !== 1) {
      add({
        rule: 'vault-secrets',
        resource: 'the deployment',
        message: `needs the secret ${name} once; the snapshot has ${String(count)}`,
      });
    }
  }
};

/** An identity's app or job: its name without `id-agentx-<environment>-` (names.bicep). */
const workloadOf = (identityName: string): string => identityName.replace(/^id-agentx-[a-z]+-/, '');

const REFERENCED_PRINCIPAL = /^\[reference\('([^']+)', '[^']+'\)\.principalId\]$/;

/**
 * Who reads what (ADR-002 Amendment G2c). Every role assignment in the
 * deployment gives Key Vault Secrets User on one secret it writes, to an
 * identity it creates, named a service principal: no other role, and nothing
 * at the vault, the resource group or the subscription. Together they are
 * exactly GRANTS, so no identity reads another's secret and each can read its
 * own.
 */
const secretAccess: Check = (snapshot, _expected, add) => {
  const secrets = new Map(ofType(snapshot, TYPES.vaultSecret).map((secret) => [secret.id, secretNameOf(secret)]));
  const identities = new Map(ofType(snapshot, TYPES.identity).map((identity) => [identity.id, identity.name]));
  const marker = `/providers/${TYPES.roleAssignment}/`;
  const granted = new Set<string>();
  for (const assignment of ofType(snapshot, TYPES.roleAssignment)) {
    const properties = assignment.properties;
    const secret = secrets.get(assignment.id.slice(0, assignment.id.lastIndexOf(marker)));
    const principal = REFERENCED_PRINCIPAL.exec(String(at(properties, 'principalId')))?.[1];
    const identity = principal === undefined ? undefined : identities.get(principal);
    const role = String(at(properties, 'roleDefinitionId')).toLowerCase();
    if (
      !role.endsWith(`/providers/microsoft.authorization/roledefinitions/${VAULT_READER_ROLE}`) ||
      secret === undefined ||
      identity === undefined ||
      at(properties, 'principalType') !== 'ServicePrincipal'
    ) {
      add({
        rule: 'secret-access',
        resource: assignment.name,
        message:
          'must give Key Vault Secrets User on one secret this deployment writes to an identity it creates (principalType ServicePrincipal): no other role, and nothing at the vault, the resource group or the subscription',
      });
      continue;
    }
    const grant = `${workloadOf(identity)} reads ${secret}`;
    granted.add(grant);
    if (!GRANTS.has(grant)) {
      add({
        rule: 'secret-access',
        resource: assignment.name,
        message: `lets ${grant.replace(GRANT, ' read ')}, which isn't one of its secrets (GRANTS)`,
      });
    }
  }
  for (const grant of [...GRANTS].filter((needed) => !granted.has(needed))) {
    add({
      rule: 'secret-access',
      resource: 'the deployment',
      message: `must let ${grant.replace(GRANT, ' read ')}, which it needs (GRANTS)`,
    });
  }
};

/** A job's workload: its name without `job-agentx-<environment>-` (names.bicep). */
const jobWorkloadOf = (jobName: string): string => jobName.replace(/^job-agentx-[a-z]+-/, '');

/** The containers a job runs. */
const containersOf = (job: PredictedResource): readonly unknown[] => list(at(job.properties, 'template', 'containers'));

/** An image named by digest: a tag can be moved to another image, a digest can't (SEC-SC-02). */
const PINNED_IMAGE = /@sha256:[0-9a-f]{64}$/;

/**
 * Every job is started by hand, runs one replica per run, gives up rather than
 * retrying, and runs the exact image it names (ADR-002 Amendment G2d). Container
 * Apps has no lock between runs, so starting one at a time is the operator's
 * (Azure.md "The jobs"); what this rule holds is that no run is a clock's or an
 * event's, and that one replica does the work. Together
 * they are the four jobs a deployment needs, so a dropped one is caught here
 * rather than at the first deployment.
 */
const jobs: Check = (snapshot, _expected, add) => {
  const environments = new Set<unknown>(ofType(snapshot, TYPES.environment).map((resource) => resource.id));
  const found = ofType(snapshot, TYPES.job);
  for (const job of found) {
    const problem = (message: string): void => {
      add({ rule: 'jobs', resource: job.name, message });
    };
    const configuration = at(job.properties, 'configuration');
    if (!environments.has(at(job.properties, 'environmentId'))) {
      problem("must run in this deployment's Container Apps environment");
    }
    if (at(job.properties, 'workloadProfileName') !== WORKLOAD_PROFILE) {
      problem(`must run on the ${WORKLOAD_PROFILE} workload profile, the only one the environment offers`);
    }
    if (at(configuration, 'triggerType') !== 'Manual') {
      problem('must be started by hand (triggerType Manual): one that starts itself would use its secrets unwatched');
    }
    for (const trigger of ['scheduleTriggerConfig', 'eventTriggerConfig'] as const) {
      if (at(configuration, trigger) !== undefined) problem(`must have no ${trigger}: it is started by hand`);
    }
    for (const setting of ['parallelism', 'replicaCompletionCount'] as const) {
      if (at(configuration, 'manualTriggerConfig', setting) !== 1) {
        problem(`must run one replica per run (manualTriggerConfig.${setting} 1): two of them would race`);
      }
    }
    if (at(configuration, 'replicaRetryLimit') !== 0) {
      problem('must not retry a failed run (replicaRetryLimit 0): a retry hides why the first run failed');
    }
    const timeout = at(configuration, 'replicaTimeout');
    if (typeof timeout !== 'number' || timeout <= 0 || timeout > LONGEST_RUN_SECONDS) {
      problem(
        `must give up after 1 to ${String(LONGEST_RUN_SECONDS)} seconds (replicaTimeout); it says ${String(timeout)}`,
      );
    }
    const containers = containersOf(job);
    if (containers.length !== 1) {
      problem(`must run exactly one container; the snapshot has ${String(containers.length)}`);
    }
    if (list(at(job.properties, 'template', 'initContainers')).length > 0) {
      problem('must run no init container: the work is the one container, in view of the log');
    }
    for (const container of containers) {
      const image = text(at(container, 'image'));
      if (!PINNED_IMAGE.test(image)) {
        problem(`must name its image by digest (SEC-SC-02); it runs ${image}`);
      }
    }
  }
  for (const workload of JOB_WORKLOADS) {
    const count = found.filter((job) => jobWorkloadOf(job.name) === workload).length;
    if (count !== 1) {
      add({
        rule: 'jobs',
        resource: 'the deployment',
        message: `needs the ${workload} job once; the snapshot has ${String(count)}`,
      });
    }
  }
};

/**
 * A secret read from a vault: the vault's id and the name asked for. A version
 * would be a further part of that name, which the rule refuses by comparing it
 * with the secret's own (a mutation pass showed narrowing the pattern here as
 * well adds nothing).
 */
const VAULT_SECRET_URL = /^\[uri\(reference\('([^']+)', '[^']+'\)\.vaultUri, 'secrets\/([^']+)'\)\]$/;

/**
 * The vault and secret a Container Apps secret reads, or nothing for anything
 * else: an address built from a vault this deployment knows, ending in the
 * secret's own name, so a version can't be pinned into it.
 */
function urlOfSecret(keyVaultUrl: string): { readonly vault: string; readonly secret: string } | undefined {
  const parts = VAULT_SECRET_URL.exec(keyVaultUrl);
  const [, vault, secret] = parts ?? [];
  return vault === undefined || secret === undefined ? undefined : { vault, secret };
}

/** Whether a container's image may take a secret in this setting (`SECRETS_IN_ENVIRONMENT`). */
const mayTakeSecretInEnvironment = (image: unknown, setting: string): boolean =>
  SECRETS_IN_ENVIRONMENT.some(({ images, settings }) => text(image).startsWith(images) && settings.test(setting));

/** The secrets a job names, by how each reaches it: its environment, or a mounted file. */
const secretsUsed = (job: PredictedResource): { readonly environment: string[]; readonly files: string[] } => ({
  environment: containersOf(job).flatMap((container) =>
    list(at(container, 'env')).flatMap((entry) => {
      const read = text(at(entry, 'secretRef'));
      return read === '' ? [] : [read];
    }),
  ),
  files: list(at(job.properties, 'template', 'volumes')).flatMap((volume) =>
    list(at(volume, 'secrets')).flatMap((item) => {
      const read = text(at(item, 'secretRef'));
      return read === '' ? [] : [read];
    }),
  ),
});

/**
 * What each job may read (ADR-002 Amendment G2d): its own identity alone,
 * exactly the secrets `GRANTS` says it reads, each from this deployment's vault
 * by name with no version, through that identity; every one of them read, and
 * nothing read that it wasn't given. A secret reaches a container as a mounted
 * file, except in the few settings `SECRETS_IN_ENVIRONMENT` lists for an image
 * that has no file form for them. The apps join this rule in G2d-2.
 */
const workloadSecrets: Check = (snapshot, _expected, add) => {
  const vaults = new Set(ofType(snapshot, TYPES.vault).map((vault) => vault.id));
  for (const job of ofType(snapshot, TYPES.job)) {
    const workload = jobWorkloadOf(job.name);
    const problem = (message: string): void => {
      add({ rule: 'workload-secrets', resource: job.name, message });
    };
    const assigned = Object.keys(at(job.identity, 'userAssignedIdentities') ?? {});
    if (at(job.identity, 'type') !== 'UserAssigned') {
      problem('must run as a user-assigned identity, never a system-assigned one tied to the resource');
    }
    const only = assigned[0] ?? '';
    if (assigned.length !== 1 || workloadOf(only.slice(only.lastIndexOf('/') + 1)) !== workload) {
      problem(`must run as its own identity alone, the one named for ${workload}`);
    }
    const declared = list(at(job.properties, 'configuration', 'secrets'));
    const given = declared.map((secret) => text(at(secret, 'name')));
    const needed = secretsRead(workload);
    for (const name of given.filter((secret) => !needed.has(secret))) {
      problem(`is given ${name}, which GRANTS doesn't let ${workload} read`);
    }
    for (const name of [...needed].filter((secret) => !given.includes(secret))) {
      problem(`must be given ${name}, which ${workload} reads (GRANTS)`);
    }
    for (const secret of declared) {
      const name = text(at(secret, 'name'));
      if (at(secret, 'value') !== undefined) {
        problem(`holds ${name}'s value; a secret is read from the vault, never carried in the deployment`);
      }
      const url = urlOfSecret(text(at(secret, 'keyVaultUrl')));
      if (url === undefined || !vaults.has(url.vault) || url.secret !== name) {
        problem(`must read ${name} from this deployment's vault by that name and no version, so a rotation reaches it`);
      }
      if (!assigned.includes(text(at(secret, 'identity')))) {
        problem(`must read ${name} through its own identity`);
      }
    }
    const used = secretsUsed(job);
    for (const volume of list(at(job.properties, 'template', 'volumes'))) {
      if (at(volume, 'storageType') === 'Secret' && list(at(volume, 'secrets')).length === 0) {
        problem(`mounts ${text(at(volume, 'name'))} without naming what is in it, which mounts every secret it has`);
      }
    }
    for (const name of given.filter((secret) => ![...used.environment, ...used.files].includes(secret))) {
      problem(`is given ${name} and never reads it; one nobody needs is one more to leak`);
    }
    for (const name of [...used.environment, ...used.files].filter((secret) => !given.includes(secret))) {
      problem(`reads ${name}, which it is not given`);
    }
    for (const container of containersOf(job)) {
      for (const entry of list(at(container, 'env')).filter((setting) => at(setting, 'secretRef') !== undefined)) {
        const setting = text(at(entry, 'name'));
        if (mayTakeSecretInEnvironment(at(container, 'image'), setting)) continue;
        problem(
          `takes ${setting} in the environment, which crash output and every child process see; mount it as a file, or list the setting in SECRETS_IN_ENVIRONMENT with why its image can't read one`,
        );
      }
    }
  }
};

/**
 * Nothing a container runs sends telemetry out of the UAE (ADR-013,
 * SEC-DATA-08): no OpenTelemetry exporter switched on, and Zitadel's daily
 * report to zitadel.com (which carries every instance's domains and counts) and
 * its metrics endpoint said to be off outright, never left to a default a
 * version change could move.
 */
const containerTelemetry: Check = (snapshot, _expected, add) => {
  for (const job of ofType(snapshot, TYPES.job)) {
    const problem = (message: string): void => {
      add({ rule: 'container-telemetry', resource: job.name, message });
    };
    for (const container of containersOf(job)) {
      const settings = new Map(
        list(at(container, 'env')).map((entry) => [text(at(entry, 'name')), at(entry, 'value')] as const),
      );
      for (const [name] of [...settings].filter(
        ([setting, value]) => setting.startsWith('OTEL_') && value !== 'true',
      )) {
        problem(`sets ${name}: OpenTelemetry sends to a collector, and ADR-013 keeps every trace in the UAE`);
      }
      if (!text(at(container, 'image')).startsWith(ZITADEL_IMAGES)) continue;
      for (const [name, wanted] of Object.entries(TELEMETRY_OFF)) {
        if (settings.get(name) !== wanted) {
          problem(`must set ${name} to ${wanted} outright, never leave it to Zitadel's default (ADR-013)`);
        }
      }
    }
  }
};

const CHECKS: readonly Check[] = [
  complete,
  required,
  inCountry,
  stableApi,
  tagged,
  noSecretLiterals,
  database,
  databaseNetwork,
  appsNetwork,
  vault,
  workspaceAndQuota,
  alertRules,
  resourceLogs,
  logDestinations,
  activityLog,
  budget,
  appsEnvironment,
  appsLogs,
  appErrorsAlert,
  identities,
  vaultSecrets,
  secretAccess,
  jobs,
  workloadSecrets,
  containerTelemetry,
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
