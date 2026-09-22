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
import { createHash } from 'node:crypto';

import { APP_KEYS } from './app-keys.ts';
import { readRanges } from './github-ranges.ts';
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
  | 'owner-login-alert'
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
  | 'apps-egress'
  | 'apps-logs'
  | 'app-errors-alert'
  | 'audit-integrity-alert'
  | 'identities'
  | 'release-identity'
  | 'release-access'
  | 'vault-secrets'
  | 'secret-access'
  | 'jobs'
  | 'apps'
  | 'public-doors'
  | 'door-certificates'
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
  app: 'Microsoft.App/containerApps',
  door: 'Microsoft.App/managedEnvironments/httpRouteConfigs',
  certificate: 'Microsoft.App/managedEnvironments/managedCertificates',
  identity: 'Microsoft.ManagedIdentity/userAssignedIdentities',
  trust: 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials',
  job: 'Microsoft.App/jobs',
  network: 'Microsoft.Network/virtualNetworks',
  roleAssignment: 'Microsoft.Authorization/roleAssignments',
  roleDefinition: 'Microsoft.Authorization/roleDefinitions',
  group: 'Microsoft.Resources/resourceGroups',
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

/** How every Postgres log line starts: its time, then its session (Azure's default, held by postgres.bicep). */
const LOG_LINE_PREFIX = '%t-%c-';

/**
 * The start of a line that prefix writes, up to the message, as the login
 * alert matches it: `2026-09-16 19:02:12 UTC-6aaae7b4.1dc3-LOG:  ` (S19).
 * Azure holds the log's time zone at UTC.
 */
const LOG_LINE_START = '^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} UTC-[0-9a-f]+[.][0-9a-f]+-LOG:  ';

/** The role that owns the app's tables and runs the migrations (db/bootstrap/roles.sql). */
const OWNER_ROLE = 'agentx_owner';

/**
 * The owner-login alert's query (ADR-012 §2, Phase 1 A3e-2) for the migration
 * job and the environment it runs in, written again here so that changing it
 * takes both: each owner login paired with the nearest start of that job, and
 * counted unless the start is within two minutes and nothing else is paired
 * with it; a start with no login counted too; each judged only between 20 and
 * 50 minutes old, since Azure's lines for the job reach the workspace minutes
 * after Postgres's. postgres.bicep says why each number.
 */
const ownerLoginQuery = (migrateJob: string, environmentId: string): string =>
  [
    'let near = 2m;',
    'let starts = ContainerAppSystemLogs',
    `    | where _ResourceId =~ "${environmentId}" and JobName == "${migrateJob}" and Reason == "ContainerStarted" and isnotempty(ReplicaName)`,
    '    | project Start = TimeGenerated, Run = ReplicaName;',
    'let logins = PGSQLServerLogs',
    `    | where Message matches regex @"${LOG_LINE_START}connection authorized: user=${OWNER_ROLE} "`,
    '    | project Login = TimeGenerated, Message;',
    'let paired = logins',
    '    | extend Key = 1',
    '    | join kind=leftouter (starts | extend Key = 1) on Key',
    '    | extend Gap = coalesce(abs(Login - Start), 1d)',
    '    | summarize arg_min(Gap, Run) by Login, Message;',
    'let claims = paired',
    '    | where Gap <= near',
    '    | summarize Claims = count() by Run;',
    'let strays = paired',
    '    | where Login between (ago(50m) .. ago(20m))',
    '    | join kind=leftouter claims on Run',
    '    | where Gap > near or Claims > 1',
    '    | project Run;',
    'let unclaimed = starts',
    '    | where Start between (ago(50m) .. ago(20m))',
    '    | join kind=leftanti claims on Run',
    '    | project Run;',
    'union strays, unclaimed',
    '| summarize Unpaired = count()',
  ].join('\n');

/**
 * When the owner-login alert runs, and the hour each run reads: its band is 30
 * minutes, so two runs 15 minutes apart judge every login and start, and the
 * hour holds the band's oldest one and whatever two minutes before it.
 */
const OWNER_LOGIN_RUNS = { every: 'PT15M', reads: 'PT1H' } as const;

/**
 * What counts as an error event: our logger's level and Zitadel's three, in
 * any case, since Zitadel's newer lines write "ERROR" (`in~` ignores case).
 */
const ERROR_LINES = 'where tostring(parse_json(Log).level) in~ ("error", "fatal", "panic")';

/**
 * The integrity alarm's events (ADR-012 §2): an audit chain that failed its
 * check, and a check that broke. Our logger writes each event name exactly, so
 * the match keeps its case.
 */
const INTEGRITY_LINES =
  'where tostring(parse_json(Log).event) in ("audit.integrity_failed", "audit.anchor_check_crashed")';

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
 * login, since each of its runs sets them all. The API reads each of the app's
 * keys (ADR-011 §2), from the one list of them (app-keys.json); the operator's
 * command, the app's login and every version of the audit chains' MAC alone
 * (ADR-011 §3, B1c).
 */
const GRANTS: ReadonlySet<string> = new Set([
  ...APP_KEYS.map((key) => `api reads ${key}`),
  ...APP_KEYS.filter((key) => key.startsWith('key-audit-mac-v')).map((key) => `operator reads ${key}`),
  'api reads db-app-password',
  'operator reads db-app-password',
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
 * a server's roles and databases, the app's migrations, Zitadel's own init and
 * setup, and the operator's command (B1c). This list is what must be there.
 */
const JOB_WORKLOADS: readonly string[] = ['db-setup', 'migrate', 'zitadel-init', 'zitadel-setup', 'operator'];

/**
 * What a job may hold itself rather than read from the vault, by the job: only
 * the operator's request (apps.bicep `operatorRequest`), and only as no
 * request. It isn't a secret: it is kept as one so that a read of the job never
 * shows what a person writes into it before a run (jobs.ts). It reaches the job
 * as a file, like everything else it is given, and is in no vault and no grant.
 * The job is run with that file and nothing else as its arguments: a request
 * written there instead would sit in the deployment and every run's record.
 */
const HELD: Readonly<
  Record<string, { readonly name: string; readonly value: string; readonly args: readonly string[] }>
> = {
  operator: { name: 'operator-request', value: '[]', args: ['--request', '/mnt/secrets/operator-request'] },
};

/**
 * Every app that serves traffic (ADR-002 Amendment G2d): the API, Zitadel and
 * its login pages. The worker joins in Phase 4.
 */
const APP_WORKLOADS: readonly string[] = ['api', 'zitadel', 'login'];

/**
 * The apps whose replicas must stay at one, with why. The API's rate limit
 * counts each client's requests in memory (ADR-011 §4), so a second replica
 * would give every client two allowances; Zitadel's projections and cache are
 * one replica's, and a second would take ten more of the server's 35 user
 * connections (ADR-002 Amendment G1).
 */
const ONE_REPLICA: Readonly<Record<string, string>> = {
  api: "the rate limit's counts are one replica's, in memory",
  zitadel: "its projections are one replica's, and a second would take ten more database connections",
};

/**
 * The public doors (ADR-002 Amendment G2e), by the part of the name `doorName`
 * gives each after the environment's: each door's routing, rule by rule in the
 * order Azure tries them (the first match wins), as `routeLine` writes a rule.
 * A route config can reach an app whose ingress is internal, so a door missing
 * from this list, or one routing any other way, publishes something nobody
 * decided to publish.
 */
const PUBLIC_DOORS: Readonly<Record<string, readonly string[]>> = {
  app: ['prefix "/" to api'],
  // Zitadel's debug pages get the API's 404, whatever their case; its login
  // pages go to the login app; everything else to Zitadel.
  auth: ['prefix "/debug" in any case to api', 'prefix "/ui/v2/login" to login', 'prefix "/" to zitadel'],
};

/** How a door binds its host's certificate: a managed one once it exists, or one it names. `Disabled` is plain http. */
const SECURE_BINDINGS: ReadonlySet<unknown> = new Set(['Auto', 'SniEnabled']);

/** The ways a route matches a path. */
const PATH_MATCHES = ['prefix', 'path', 'pathSeparatedPrefix'] as const;

/** The two ways a target can hold on to an old revision. */
const TARGET_PINS = ['revision', 'label'] as const;

/** The issuer of the tokens a GitHub job signs in to Azure with (G4). */
const GITHUB_ISSUER = 'https://token.actions.githubusercontent.com';

/** The one audience Azure accepts in such a token. */
const TOKEN_EXCHANGE = 'api://AzureADTokenExchange';

/**
 * The GitHub subject CI signs in with (G4): a job of this repository in the
 * GitHub environment of the same name, in the immutable form GitHub writes for
 * a repository made after 15 July 2026. names.bicep writes it too, so changing
 * who may sign in takes both.
 */
const releaseSubject = (environment: string): string =>
  `repo:shahbaz242630@205810405/agent-x@1368211207:environment:${environment}`;

/** CI's identity in an environment, as names.bicep names it. */
const releaseIdentityName = (environment: string): string =>
  `id-agentx-${environment === 'production' ? 'prd' : 'stg'}-release`;

/** The namespace Bicep's and ARM's `guid()` makes its version-5 UUIDs in. */
const BICEP_GUID_NAMESPACE = Buffer.from('11fb06fb712d4ddd98c7e71bbd588830', 'hex');

/**
 * Bicep's `guid(...)`: a version-5 UUID of its arguments joined by `-`, as
 * UTF-8, in BICEP_GUID_NAMESPACE (checked against a snapshot's own value in
 * policy.test.ts).
 */
export function bicepGuid(...parts: readonly string[]): string {
  const hash = createHash('sha1')
    .update(Buffer.concat([BICEP_GUID_NAMESPACE, Buffer.from(parts.join('-'), 'utf8')]))
    .digest()
    .subarray(0, 16);
  hash.writeUInt8(((hash.readUInt8(6) & 0x0f) | 0x50) >>> 0, 6);
  hash.writeUInt8(((hash.readUInt8(8) & 0x3f) | 0x80) >>> 0, 8);
  const hex = hash.toString('hex');
  return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20)].join('-');
}

/**
 * CI's role's name (G4), as names.bicep's `releaseRoleName` makes it from the
 * resource group. A custom role's name is a GUID the template chooses, so
 * holding it to this one keeps any other GUID, a built-in role's among them
 * (Owner's), from passing as CI's.
 */
const releaseRoleName = (groupId: string): string => bicepGuid(groupId, 'release');

/**
 * Everything CI's role allows (G4): an app's and a job's own reads and writes,
 * their revisions and runs, and starting a run. Nothing that lists secrets,
 * opens a shell or a log stream, stops or deletes, writes a door, or grants
 * access. No linked action either (`managedEnvironments/join`,
 * `userAssignedIdentities/assign`): CI's partial update is expected not to
 * need them (release.bicep), which its first run proves (G4-4). The apps
 * deployment says which resources it covers (rule `release-access`).
 */
const RELEASE_ACTIONS: readonly string[] = [
  'Microsoft.App/containerApps/read',
  'Microsoft.App/containerApps/write',
  'Microsoft.App/containerApps/revisions/read',
  'Microsoft.App/jobs/read',
  'Microsoft.App/jobs/write',
  'Microsoft.App/jobs/start/action',
  'Microsoft.App/jobs/executions/read',
  'Microsoft.App/jobs/execution/read',
];

/**
 * What CI's role is given on (G4-2b): the API app, which a merge updates, and
 * the migration job, which it updates and runs. Not Zitadel, its login pages or
 * the set-up job, which holds the server admin's login.
 */
const RELEASE_TARGETS: readonly { readonly type: string; readonly workload: string }[] = [
  { type: TYPES.app, workload: 'api' },
  { type: TYPES.job, workload: 'migrate' },
];

/**
 * Zitadel is two programs in two images (ADR-003 Amendment S10), and they are
 * told different things: the server reads `ZITADEL_*` settings, its login pages
 * are a Next.js app that reads none of them. A rule that took both for the
 * server would ask the login pages for settings they ignore, and would let the
 * one switch they do need go missing.
 */
const ZITADEL_SERVER_IMAGE = 'ghcr.io/zitadel/zitadel:';
const ZITADEL_LOGIN_IMAGE = 'ghcr.io/zitadel/zitadel-login:';

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
    images: ZITADEL_SERVER_IMAGE,
    settings: /^ZITADEL_(?:DATABASE_POSTGRES_(?:USER|ADMIN)_PASSWORD|FIRSTINSTANCE_ORG_HUMAN_PASSWORD)$/,
    reason: 'Zitadel offers no file form for a database login or its first admin’s password',
  },
];

/**
 * What every Zitadel container must say outright, so no default of a later
 * version sends anything out of the UAE (ADR-013, SEC-DATA-08): no daily report
 * to zitadel.com, no metrics endpoint, no tracing — and none of the four
 * exporters of the `Instrumentation` family that v4.17.3 marks the first three
 * deprecated in favour of, each of which offers an "auto" mode that follows the
 * standard `OTEL_*` variables. Every one of them is already the default; saying
 * so here is what makes the version that changes a default a change to this
 * file rather than a surprise. The one that isn't a default: Zitadel asks
 * Google Cloud's metadata server for a machine ID unless told not to (S19). Read off the defaults the pinned image carries
 * (G2d-2a); the jobs carry them too, so one list covers every container.
 */
const TELEMETRY_OFF: readonly {
  readonly images: string;
  readonly settings: Readonly<Record<string, string>>;
}[] = [
  {
    images: ZITADEL_SERVER_IMAGE,
    settings: {
      ZITADEL_SERVICEPING_ENABLED: 'false',
      ZITADEL_METRICS_TYPE: 'none',
      ZITADEL_TRACING_TYPE: 'none',
      ZITADEL_INSTRUMENTATION_TRACE_EXPORTER_TYPE: 'none',
      ZITADEL_INSTRUMENTATION_METRIC_EXPORTER_TYPE: 'none',
      ZITADEL_INSTRUMENTATION_LOG_EXPORTER_TYPE: 'none',
      ZITADEL_MACHINE_IDENTIFICATION_WEBHOOK_ENABLED: 'false',
    },
  },
  {
    // The login pages start an OpenTelemetry SDK unless told not to, and export
    // to an OTLP endpoint (localhost unless one is set).
    images: ZITADEL_LOGIN_IMAGE,
    settings: { OTEL_SDK_DISABLED: 'true' },
  },
];

/** The one workload profile the environment offers (ADR-002 Amendment G2b). */
const WORKLOAD_PROFILE = 'Consumption';

/**
 * The addresses the apps subnet may leave for to pull an image, read from the
 * same file network.bicep compiles into the rules (github-ranges.ts): the rule
 * below holds the deployment to exactly them, so a hand-edited allowlist that
 * has drifted from the refresher's file fails the check.
 */
const GITHUB_RANGES = readRanges();

/** Azure's own DNS, which Microsoft says an environment stops working without. */
const AZURE_DNS = '168.63.129.16';

/** The longest a job's one run may take, so a stuck run can't hold a replica for a day. */
const LONGEST_RUN_SECONDS = 3600;

/**
 * Secrets created once and never written again: Zitadel can't read what it
 * encrypted with another master key, and what one of the app's keys sealed or
 * signed needs that key as it was (a rotation adds a version instead).
 */
const CREATED_ONCE: ReadonlySet<string> = new Set(['zitadel-masterkey', ...APP_KEYS]);

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
 * Whether a SEV-1 alert sees every minute and fires on the first window with a
 * match: its window is as long as the time between runs, so no minute goes
 * unwatched, and one failing window is enough, so it never waits for more.
 */
const watchesEveryWindow = (alert: PredictedResource, criterion: unknown): boolean =>
  at(alert.properties, 'windowSize') === at(alert.properties, 'evaluationFrequency') &&
  at(criterion, 'failingPeriods', 'numberOfEvaluationPeriods') === 1 &&
  at(criterion, 'failingPeriods', 'minFailingPeriodsToAlert') === 1;

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
 * One of the app's keys, as secrets.bicep writes it: its own member of the one
 * secure parameter the keys arrive in as JSON, named for the secret it's
 * written to, so no key is ever given another's value.
 */
const KEY_MEMBER_REFERENCE = /^\[json\(parameters\('[^']+'\)\)\['([^']+)'\]\]$/;

/** Whether a vault secret's value is its own key member: only for one of the app's keys. */
const isOwnKeyMember = (secret: PredictedResource, value: unknown): boolean =>
  typeof value === 'string' &&
  APP_KEYS.includes(secretNameOf(secret)) &&
  KEY_MEMBER_REFERENCE.exec(value)?.[1] === secretNameOf(secret);

/**
 * A secret holds a parameter reference, never a value written in the code:
 * any property whose name ends in "password" or "secret" (a switch named after
 * one, like `passwordAuth`, doesn't), a key vault secret's value, and the value
 * of every entry in a `secrets` list (Container Apps' own secrets). One of the
 * app's keys holds its own member of the parameter they arrive in, and a job
 * holds what `HELD` gives it, which is no secret, as written there.
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
  /** Whether a Container Apps secret is what its app or job may hold: its name and value exactly as `HELD` gives them. */
  const heldBy = (resource: PredictedResource, entry: unknown): boolean => {
    const held = HELD[jobWorkloadOf(resource.name)];
    return held !== undefined && at(entry, 'name') === held.name && at(entry, 'value') === held.value;
  };
  const walk = (resource: PredictedResource, value: unknown, trail: string): void => {
    if (typeof value !== 'object' || value === null) return;
    for (const [key, child] of Object.entries(value)) {
      const where = trail === '' ? key : `${trail}.${key}`;
      if (/(?:password|secret)$/i.test(key) && literal(child)) refuse(resource, where);
      if (key === 'secrets') {
        list(child).forEach((entry, index) => {
          if (literal(at(entry, 'value')) && !heldBy(resource, entry)) {
            refuse(resource, `${where}[${String(index)}].value`);
          }
        });
      }
      walk(resource, child, where);
    }
  };
  for (const resource of snapshot.predictedResources) {
    const value = at(resource.properties, 'value');
    if (resource.type === TYPES.vaultSecret && literal(value) && !isOwnKeyMember(resource, value)) {
      refuse(resource, 'value');
    }
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
 * `vault-secrets`, that leaves Zitadel's master key and the app's keys created
 * once, even under a condition that would vanish from the snapshot (security
 * review, S15), and every other secret written only when given. A module's own template is read
 * the same way.
 *
 * A template that writes secrets looks none up: Azure refuses a template that
 * both writes a secret and looks it up as existing ("defined multiple times"),
 * a refusal no what-if or snapshot shows (the first real secrets run, S19).
 * Lookups go in a module of their own.
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
  const problems = entries.flatMap(([name, resource]): Problem[] => {
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
        "is written on a condition and only if it doesn't exist: a secret that rotates takes the condition alone, one created once (the master key, the app's keys) @onlyIfNotExists() alone",
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
  return [...lookupsBesideWrites(file, entries), ...problems];
}

/** The secrets a template looks up though it writes some, which Azure refuses (`templateProblems`). */
function lookupsBesideWrites(file: string, entries: readonly (readonly [string, unknown])[]): Problem[] {
  const secrets = entries.filter(([, resource]) => at(resource, 'type') === TYPES.vaultSecret);
  const lookups = secrets.filter(([, resource]) => at(resource, 'existing') === true);
  if (lookups.length === secrets.length) return [];
  return lookups.map(([name]): Problem => ({
    rule: 'vault-secrets',
    resource: `${file}: ${name}`,
    message:
      'is looked up in a template that writes secrets, which Azure refuses ("defined multiple times") though no what-if or snapshot shows it: look secrets up in a module of their own',
  }));
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
    // The alert matches the line as Azure writes it, from the prefix held
    // here on (S19: a pattern without the prefix never matched).
    const admin = String(at(properties, 'administratorLogin'));
    const pattern = `@"${LOG_LINE_START}connection authorized: user=(${admin}|${BACKUP_ROLE}) "`;
    const alerted = ofType(snapshot, TYPES.alert).some(
      (alert) =>
        at(alert.properties, 'enabled') === true &&
        at(alert.properties, 'severity') === 1 &&
        at(alert.properties, 'autoMitigate') === false &&
        list(at(alert.properties, 'scopes')).some((scope) => workspaces.has(scope)) &&
        list(at(alert.properties, 'criteria', 'allOf')).some(
          (criterion) =>
            queryIs(at(criterion, 'query'), 'PGSQLServerLogs', [`where Message matches regex ${pattern}`], 'count()') &&
            watchesEveryWindow(alert, criterion),
        ),
    );
    if (settings.get('log_connections') !== 'on' || settings.get('log_line_prefix') !== LOG_LINE_PREFIX || !alerted) {
      problem(
        'database-logins',
        `logs every login, and an enabled, stateless SEV-1 alert on the workspace, watching every minute, fires on the first window when ${admin} or ${BACKUP_ROLE} logs in (ADR-012 §2)`,
      );
    }
  }
};

/**
 * A subnet's rules in one direction, from the rules group of this deployment
 * attached to it: those declared inside the group, and any declared as
 * resources of their own under it, which Azure adds to the same group.
 */
const subnetRules = (snapshot: Snapshot, subnet: unknown, direction: string): readonly unknown[] => {
  const rulesId = at(subnet, 'properties', 'networkSecurityGroup', 'id');
  const inside = list(
    at(ofType(snapshot, TYPES.rules).find((group) => group.id === rulesId)?.properties, 'securityRules'),
  );
  const apart = ofType(snapshot, TYPES.rule).filter((rule) => rule.id.startsWith(`${String(rulesId)}/securityRules/`));
  return [...inside, ...apart]
    .map((rule) => at(rule, 'properties'))
    .filter((rule) => at(rule, 'direction') === direction);
};

const inboundRules = (snapshot: Snapshot, subnet: unknown): readonly unknown[] =>
  subnetRules(snapshot, subnet, 'Inbound');

const outboundRules = (snapshot: Snapshot, subnet: unknown): readonly unknown[] =>
  subnetRules(snapshot, subnet, 'Outbound');

const allowing = (inbound: readonly unknown[]): readonly unknown[] =>
  inbound.filter((rule) => at(rule, 'access') === 'Allow');

/**
 * The backstop of a direction: a rule that denies everything from `source`,
 * after every rule that allows, so it overrides Azure's default rule rather
 * than sitting under one of ours. `access` is kept explicit though it is
 * implied — a rule that allows is in `allowing`, so its priority can never be
 * above the last of them — because a backstop that doesn't say "Deny" is not a
 * backstop to read. It is the one condition a mutant survives, in both
 * directions, and knowingly so.
 */
const deniesRest = (rules: readonly unknown[], source: string): boolean => {
  const lastAllow = Math.max(...allowing(rules).map((rule) => Number(at(rule, 'priority'))));
  return rules.some(
    (rule) =>
      at(rule, 'access') === 'Deny' &&
      at(rule, 'protocol') === '*' &&
      at(rule, 'sourceAddressPrefix') === source &&
      at(rule, 'destinationAddressPrefix') === '*' &&
      at(rule, 'destinationPortRange') === '*' &&
      Number(at(rule, 'priority')) > lastAllow,
  );
};

/** In: Azure's default rule lets the whole network in, so ours denies it after every allow. */
const deniesRestOfNetwork = (inbound: readonly unknown[]): boolean => deniesRest(inbound, 'VirtualNetwork');

/** Out: Azure's defaults let the subnet reach anything, so ours denies every source and destination. */
const deniesRestOfTheInternet = (outbound: readonly unknown[]): boolean => deniesRest(outbound, '*');

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

/** Where a rule sends traffic: its one destination, or its list of them in a settled order. */
const destinationOf = (rule: unknown): string => {
  const one = at(rule, 'destinationAddressPrefix');
  if (one !== undefined) return text(one);
  return list(at(rule, 'destinationAddressPrefixes')).map(text).sort().join(' ');
};

/** One door out, as a single line: what may leave, for where, on which port. */
const doorOf = (rule: unknown): string =>
  `${text(at(rule, 'protocol'))} to ${destinationOf(rule)} on ${text(at(rule, 'destinationPortRange'))}`;

/**
 * Every door the apps subnet may have out, and why it is there. The first three
 * are this deployment's own addresses, the next five Azure's service tags,
 * which Azure keeps current; the last two are GitHub's published addresses,
 * which nothing keeps current but the refresher (github-ranges.ts).
 *
 * What is deliberately absent: `Storage.<region>`, which Microsoft's list needs
 * only for images hosted in Azure Container Registry, and any door for the
 * apps' own outbound calls, which they make none of before Phase 1.
 */
const egressDoors = (region: string, apps: string, database: string): readonly (readonly [string, string])[] => [
  [`* to ${apps} on *`, "the environment's own traffic between its nodes (Microsoft)"],
  [`* to ${AZURE_DNS} on 53`, "Azure's DNS, which resolves the database's private name and every host below"],
  [`Tcp to ${database} on 5432`, 'Postgres, in its own subnet'],
  [`Tcp to AzureKeyVault.${region} on 443`, 'the secrets each app and job reads, in this region alone'],
  ['Tcp to AzureMonitor on 443', "the apps' console logs on their way to the workspace"],
  ['Tcp to AzureActiveDirectory on 443', 'the token an identity reads its own secrets with'],
  ['Tcp to MicrosoftContainerRegistry on 443', "the platform's own system containers"],
  ['Tcp to AzureFrontDoor.FirstParty on 443', 'Microsoft names it a dependency of the registry above'],
  [
    `Tcp to ${[...GITHUB_RANGES.registry.prefixes].sort().join(' ')} on 443`,
    'ghcr.io: the pull token and the manifest',
  ],
  [
    `Tcp to ${[...GITHUB_RANGES.downloads.prefixes].sort().join(' ')} on 443`,
    'where ghcr.io redirects every layer download',
  ],
];

/**
 * The way out of the apps subnet is an allowlist (ADR-002 Amendment G2d-3).
 * Azure's default rules let a subnet reach the whole internet, so a container
 * that was taken over could send anything anywhere, out of the UAE; these
 * rules name what the apps and jobs need and deny the rest after them. The
 * doors must match exactly: one missing breaks a deployment, one extra is a
 * way out nobody decided on.
 */
const appsEgress: Check = (snapshot, _expected, add) => {
  for (const network of ofType(snapshot, TYPES.network)) {
    const apps = appsSubnetOf(network);
    const prefix = text(at(apps, 'properties', 'addressPrefix'));
    const database = list(at(network.properties, 'subnets')).find((subnet) => at(subnet, 'name') === 'database');
    const outbound = outboundRules(snapshot, apps);
    const allows = allowing(outbound);
    const problem = (message: string): void => {
      add({ rule: 'apps-egress', resource: network.name, message });
    };
    // The network's own region, not the expected one: this rule asks that the
    // key vault tag names where this deployment is, and `in-country` asks
    // separately that that is the UAE.
    const wanted = new Map(
      egressDoors(text(network.location), prefix, text(at(database, 'properties', 'addressPrefix'))),
    );
    const open = new Set(allows.map(doorOf));
    for (const [door, why] of wanted) {
      if (!open.has(door)) problem(`its apps subnet must let out ${door}, for ${why}`);
    }
    for (const door of [...open].filter((door) => !wanted.has(door))) {
      problem(`its apps subnet lets out ${door}, which nothing it runs needs`);
    }
    for (const source of new Set(
      allows.map((rule) => text(at(rule, 'sourceAddressPrefix'))).filter((source) => source !== prefix),
    )) {
      problem(`its apps subnet lets out traffic from ${source || 'nowhere named'}, not from the subnet alone`);
    }
    if (!deniesRestOfTheInternet(outbound)) {
      problem('its apps subnet must deny everything else out, after every rule that allows');
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
    const runbook = /^SEV-([12])\. .+ Runbook: Incident-Response-Playbook\.md section [A-J]\.$/.exec(
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
    // One condition: `allOf` fires only when every condition holds, so a
    // second one that never does would keep the alert from ever firing while
    // the first still passed each rule that reads it. And a SEV-1 alert is
    // never muted, which would silence every notification after the first.
    if (
      at(alert.properties, 'enabled') !== true ||
      criteria.length !== 1 ||
      groups.length === 0 ||
      !groups.every((group) => deliversAlerts(snapshot, group)) ||
      (severity === 1 &&
        (at(alert.properties, 'autoMitigate') !== false || at(alert.properties, 'muteActionsDuration') !== undefined))
    ) {
      add({
        rule: 'alert-delivery',
        resource: alert.name,
        message:
          "must be enabled, hold one condition and reach this deployment's action groups, each switched on with someone to tell; a SEV-1 alert is stateless and never muted, so it notifies every time",
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
 * An enabled, stateless SEV-1 alert on the workspace counts every integrity
 * alarm the apps log (ADR-012 §2, SEC-DB-11): one line is enough to fire it,
 * and it notifies again every window the alarm goes on.
 */
const auditIntegrityAlert: Check = (snapshot, _expected, add) => {
  const workspaces = workspaceIds(snapshot);
  for (const environment of ofType(snapshot, TYPES.environment)) {
    const alerted = ofType(snapshot, TYPES.alert).some(
      (alert) =>
        at(alert.properties, 'enabled') === true &&
        at(alert.properties, 'severity') === 1 &&
        at(alert.properties, 'autoMitigate') === false &&
        list(at(alert.properties, 'scopes')).some((scope) => workspaces.has(scope)) &&
        list(at(alert.properties, 'criteria', 'allOf')).some(
          (criterion) =>
            queryIs(at(criterion, 'query'), 'ContainerAppConsoleLogs', [INTEGRITY_LINES], 'count()') &&
            at(criterion, 'operator') === 'GreaterThan' &&
            at(criterion, 'threshold') === 0 &&
            watchesEveryWindow(alert, criterion),
        ),
    );
    if (!alerted) {
      add({
        rule: 'audit-integrity-alert',
        resource: environment.name,
        message:
          "needs an enabled, stateless SEV-1 alert on this deployment's workspace that fires on any audit.integrity_failed or audit.anchor_check_crashed line, watching every minute and firing on the first window (ADR-012 §2)",
      });
    }
  }
};

/**
 * An enabled, stateless SEV-1 alert on the workspace fires when the owner role
 * logs in other than as the migration job starting (ADR-012 §2, Phase 1
 * A3e-2): that role can rewrite the walls the app's checks stand on. Its query
 * names this deployment's own migration job and the environment it runs in,
 * and it runs and reads exactly as its band needs (OWNER_LOGIN_RUNS).
 */
const ownerLoginAlert: Check = (snapshot, _expected, add) => {
  const workspaces = workspaceIds(snapshot);
  const [migrate, ...others] = ofType(snapshot, TYPES.job).filter((job) => jobWorkloadOf(job.name) === 'migrate');
  const [environment, ...otherEnvironments] = ofType(snapshot, TYPES.environment);
  for (const server of ofType(snapshot, TYPES.server)) {
    const alerted =
      migrate !== undefined &&
      others.length === 0 &&
      environment !== undefined &&
      otherEnvironments.length === 0 &&
      ofType(snapshot, TYPES.alert).some(
        (alert) =>
          at(alert.properties, 'enabled') === true &&
          at(alert.properties, 'severity') === 1 &&
          at(alert.properties, 'autoMitigate') === false &&
          at(alert.properties, 'evaluationFrequency') === OWNER_LOGIN_RUNS.every &&
          at(alert.properties, 'overrideQueryTimeRange') === OWNER_LOGIN_RUNS.reads &&
          list(at(alert.properties, 'scopes')).some((scope) => workspaces.has(scope)) &&
          list(at(alert.properties, 'criteria', 'allOf')).some(
            (criterion) =>
              at(criterion, 'query') === ownerLoginQuery(migrate.name, environment.id) &&
              at(criterion, 'operator') === 'GreaterThan' &&
              at(criterion, 'threshold') === 0 &&
              watchesEveryWindow(alert, criterion),
          ),
      );
    if (!alerted) {
      add({
        rule: 'owner-login-alert',
        resource: server.name,
        message: `needs an enabled, stateless SEV-1 alert on this deployment's workspace, every 15 minutes over the hour before, that fires on the first window when ${OWNER_ROLE} logs in other than as this deployment's migration job starting in its environment, or that job starts with no login (ADR-012 §2)`,
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

/** What a role assignment is given on: its id up to the assignment's own part. */
const scopeOf = (assignment: PredictedResource): string =>
  assignment.id.slice(0, assignment.id.lastIndexOf(`/providers/${TYPES.roleAssignment}/`));

/**
 * Who a role assignment gives its role to: the identity of this deployment it
 * names, as a service principal, or undefined for anyone else.
 */
const principalOf = (snapshot: Snapshot, assignment: PredictedResource): PredictedResource | undefined => {
  const principal = REFERENCED_PRINCIPAL.exec(String(at(assignment.properties, 'principalId')))?.[1];
  const identity = ofType(snapshot, TYPES.identity).find((found) => found.id === principal);
  return at(assignment.properties, 'principalType') === 'ServicePrincipal' ? identity : undefined;
};

/** A role assignment's role, as Azure compares ids: without case. */
const roleOf = (assignment: PredictedResource): string =>
  String(at(assignment.properties, 'roleDefinitionId')).toLowerCase();

/** The resource group the deployment creates (a snapshot of an environment has one), or nothing for none. */
const groupOf = (snapshot: Snapshot): string => ofType(snapshot, TYPES.group)[0]?.id ?? '';

/** CI's identity's id, without case: its name in the deployment's resource group, so a namesake elsewhere isn't it. */
const releaseIdentityId = (snapshot: Snapshot, environment: string): string =>
  `${groupOf(snapshot)}/providers/${TYPES.identity}/${releaseIdentityName(environment)}`.toLowerCase();

/**
 * CI's role as a role assignment names it, without case: at the subscription,
 * the form Azure keeps a custom role under wherever it may be given (G4-2b),
 * and by the one name it may have (`releaseRoleName`).
 */
const releaseRoleId = (snapshot: Snapshot): string => {
  const group = groupOf(snapshot);
  const subscription = /^\/subscriptions\/[^/]+/.exec(group)?.[0] ?? '';
  return `${subscription}/providers/${TYPES.roleDefinition}/${releaseRoleName(group)}`.toLowerCase();
};

/**
 * Anything that could grant access but a role assignment or CI's role written
 * exactly so: a type in another case, the older `<resource>/providers/
 * roleAssignments` form, or another Microsoft.Authorization type (a PIM
 * request). The rules read role assignments by their exact type, so any of
 * these would pass them unread.
 */
const ACCESS_TYPE = /authorization|roleassignment|roledefinition/i;

/**
 * Who reads what (ADR-002 Amendment G2c). Every role assignment in the
 * deployment but CI's role's (`release-access`) gives Key Vault Secrets User on
 * one secret it writes, to an identity it creates, named a service principal:
 * no other role, and nothing at the vault, the resource group or the
 * subscription. Together they are exactly GRANTS, so no identity reads
 * another's secret and each can read its own; CI's identity isn't in GRANTS,
 * so it reads none. Nothing else in the deployment grants access (ACCESS_TYPE).
 */
const secretAccess: Check = (snapshot, _expected, add) => {
  for (const resource of snapshot.predictedResources) {
    if (
      ACCESS_TYPE.test(resource.type) &&
      resource.type !== TYPES.roleAssignment &&
      resource.type !== TYPES.roleDefinition
    ) {
      add({
        rule: 'secret-access',
        resource: resource.name,
        message: `is a ${resource.type}, which no rule reads: access is given only as ${TYPES.roleAssignment}, written exactly so`,
      });
    }
  }
  const secrets = new Map(ofType(snapshot, TYPES.vaultSecret).map((secret) => [secret.id, secretNameOf(secret)]));
  const release = releaseRoleId(snapshot);
  const granted = new Set<string>();
  for (const assignment of ofType(snapshot, TYPES.roleAssignment)) {
    const role = roleOf(assignment);
    if (role === release) continue;
    const secret = secrets.get(scopeOf(assignment));
    const identity = principalOf(snapshot, assignment);
    if (
      !role.endsWith(`/providers/microsoft.authorization/roledefinitions/${VAULT_READER_ROLE}`) ||
      secret === undefined ||
      identity === undefined
    ) {
      add({
        rule: 'secret-access',
        resource: assignment.name,
        message:
          "must give Key Vault Secrets User on one secret this deployment writes to an identity it creates (principalType ServicePrincipal), or be CI's role (release-access): no other role, and nothing at the vault, the resource group or the subscription",
      });
      continue;
    }
    const grant = `${workloadOf(identity.name)} reads ${secret}`;
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

/** A set of role actions as Azure compares them: without case or repeats, in order. */
const actionSet = (actions: readonly unknown[]): string =>
  JSON.stringify([...new Set(actions.map((action) => String(action).toLowerCase()))].sort());

/**
 * CI's identity (G4). The deployment trusts GitHub for exactly one identity,
 * the one names.bicep calls release, which no app or job runs as, and only
 * for GitHub's issuer, this
 * environment's subject and the token exchange: no other identity can be
 * signed in to from outside Azure. And it defines exactly one custom role,
 * named as `releaseRoleName` names it, which allows RELEASE_ACTIONS and no data
 * action, and can be given in this deployment's resource group only. Where that role is given is the apps
 * deployment's to say (G4-2b), and `release-access`'s to check.
 */
const releaseIdentity: Check = (snapshot, expected, add) => {
  const problem = (resource: string, message: string): void => {
    add({ rule: 'release-identity', resource, message });
  };
  // One at most, since the id is one resource's: what matters is that it's there.
  const name = releaseIdentityName(expected.environment);
  const ci = releaseIdentityId(snapshot, expected.environment);
  const releases = ofType(snapshot, TYPES.identity).filter((identity) => identity.id.toLowerCase() === ci);
  if (releases.length === 0) problem('the deployment', `needs an identity for CI (${name})`);
  // Nothing runs as it, so its role stays CI's alone. Azure reads an id in any case.
  for (const workload of [...ofType(snapshot, TYPES.job), ...ofType(snapshot, TYPES.app)]) {
    const assigned = Object.keys(at(workload.identity, 'userAssignedIdentities') ?? {});
    if (assigned.some((id) => id.toLowerCase() === ci)) {
      problem(workload.name, "must not run as CI's identity, whose role is CI's alone");
    }
  }
  const trusts = ofType(snapshot, TYPES.trust);
  for (const trust of trusts) {
    if (!releases.some((release) => trust.id.startsWith(`${release.id}/federatedIdentityCredentials/`))) {
      problem(trust.name, "must be on CI's identity: no other identity is signed in to from outside Azure");
    }
    const issuer = at(trust.properties, 'issuer');
    if (issuer !== GITHUB_ISSUER) {
      problem(trust.name, `must trust ${GITHUB_ISSUER} alone; it trusts ${JSON.stringify(issuer)}`);
    }
    const subject = at(trust.properties, 'subject');
    if (subject !== releaseSubject(expected.environment)) {
      problem(
        trust.name,
        `must trust ${releaseSubject(expected.environment)} alone (a job in this environment's GitHub environment); it trusts ${JSON.stringify(subject)}`,
      );
    }
    const audiences = list(at(trust.properties, 'audiences'));
    if (audiences.length !== 1 || audiences[0] !== TOKEN_EXCHANGE) {
      problem(trust.name, `must accept the audience ${TOKEN_EXCHANGE} alone; it accepts ${JSON.stringify(audiences)}`);
    }
  }
  if (trusts.length !== 1) {
    problem('the deployment', `needs one trust, for CI's identity; the snapshot has ${String(trusts.length)}`);
  }

  const groups = ofType(snapshot, TYPES.group).map((group) => group.id);
  const roles = ofType(snapshot, TYPES.roleDefinition);
  const roleName = releaseRoleName(groupOf(snapshot));
  for (const role of roles) {
    if (role.name !== roleName) {
      problem(
        role.name,
        `must be named ${roleName} (names.bicep's releaseRoleName), so that no other role, a built-in one among them, passes as CI's`,
      );
    }
    const scopes = list(at(role.properties, 'assignableScopes'));
    if (scopes.length !== 1 || !groups.includes(String(scopes[0]))) {
      problem(
        role.name,
        `must be assignable in this deployment's resource group alone; it says ${JSON.stringify(scopes)}`,
      );
    }
    const permissions = list(at(role.properties, 'permissions'));
    const actions = permissions.flatMap((entry) => list(at(entry, 'actions')));
    if (actionSet(actions) !== actionSet(RELEASE_ACTIONS)) {
      problem(role.name, `must allow exactly ${RELEASE_ACTIONS.join(', ')}; it allows ${actions.join(', ')}`);
    }
    const dataActions = permissions.flatMap((entry) => list(at(entry, 'dataActions')));
    if (dataActions.length > 0) {
      problem(
        role.name,
        `must allow no data action, which could read a secret's value; it allows ${dataActions.join(', ')}`,
      );
    }
  }
  if (roles.length !== 1) {
    problem('the deployment', `needs one custom role, CI's; the snapshot has ${String(roles.length)}`);
  }
};

/** The work a job or an app does, from its name (`job-agentx-stg-migrate`, `ca-agentx-stg-api`). */
const jobWorkloadOf = (name: string): string => name.replace(/^(?:job|ca)-agentx-[a-z]+-/, '');

/** The containers a job or an app runs. */
const containersOf = (job: PredictedResource): readonly unknown[] => list(at(job.properties, 'template', 'containers'));

/** Everything that runs a container of ours: the jobs and the apps, checked by the same rules. */
const workloadsIn = (snapshot: Snapshot): readonly PredictedResource[] => [
  ...ofType(snapshot, TYPES.job),
  ...ofType(snapshot, TYPES.app),
];

/**
 * Where CI's role is given (G4-2b): on each of RELEASE_TARGETS in the
 * deployment's resource group once, to CI's identity as a service principal,
 * and nowhere else: not on another app or job, the environment, a door, the
 * vault, the resource group or the subscription, and never to an app's or a
 * job's identity. That CI's identity holds no other role is `secret-access`'s:
 * the one other role it allows is Key Vault Secrets User, to the readers
 * GRANTS names, which CI isn't.
 */
const releaseAccess: Check = (snapshot, expected, add) => {
  const role = releaseRoleId(snapshot);
  const ci = releaseIdentityId(snapshot, expected.environment);
  const inGroup = `${groupOf(snapshot)}/providers/`.toLowerCase();
  const targets = new Map(
    workloadsIn(snapshot)
      .filter(
        (workload) =>
          workload.id.toLowerCase().startsWith(inGroup) &&
          RELEASE_TARGETS.some(
            (target) => target.type === workload.type && target.workload === jobWorkloadOf(workload.name),
          ),
      )
      .map((workload) => [workload.id, { name: workload.name, given: 0 }]),
  );
  for (const assignment of ofType(snapshot, TYPES.roleAssignment)) {
    if (roleOf(assignment) !== role) continue;
    const target = targets.get(scopeOf(assignment));
    if (target === undefined || principalOf(snapshot, assignment)?.id.toLowerCase() !== ci) {
      add({
        rule: 'release-access',
        resource: assignment.name,
        message:
          "must give CI's role to CI's identity (principalType ServicePrincipal) on the API app or the migration job alone",
      });
      continue;
    }
    target.given += 1;
  }
  for (const { name, given } of targets.values()) {
    if (given !== 1) {
      add({
        rule: 'release-access',
        resource: 'the deployment',
        message: `must give CI's role on ${name} once; it gives it ${String(given)} times`,
      });
    }
  }
};

/** An image named by digest: a tag can be moved to another image, a digest can't (SEC-SC-02). */
const PINNED_IMAGE = /@sha256:[0-9a-f]{64}$/;

/**
 * Every job is started by hand, runs one replica per run, gives up rather than
 * retrying, and runs the exact image it names (ADR-002 Amendment G2d). Container
 * Apps has no lock between runs, so starting one at a time is the operator's
 * (Azure.md "The jobs"); what this rule holds is that no run is a clock's or an
 * event's, and that one replica does the work. Together
 * they are the five jobs the deployment holds, so a dropped one is caught here
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
 * Every app that serves traffic (ADR-002 Amendment G2d): in this deployment's
 * environment, on Consumption, running the exact image it names, and **never a
 * public door** — the doors are the route configs (G2e), so an app whose ingress
 * is external is one reachable from the internet that nothing decided to
 * publish. Plain http is refused even inside the environment. The apps that
 * hold something one replica's keep to one (`ONE_REPLICA`), and every app can
 * run at least one. Together they are the three apps a deployment needs, so a
 * dropped one is caught here rather than at the first deployment.
 */
const apps: Check = (snapshot, _expected, add) => {
  const environments = new Set<unknown>(ofType(snapshot, TYPES.environment).map((resource) => resource.id));
  const found = ofType(snapshot, TYPES.app);
  for (const app of found) {
    const workload = jobWorkloadOf(app.name);
    const problem = (message: string): void => {
      add({ rule: 'apps', resource: app.name, message });
    };
    if (!environments.has(at(app.properties, 'environmentId'))) {
      problem("must run in this deployment's Container Apps environment");
    }
    if (at(app.properties, 'workloadProfileName') !== WORKLOAD_PROFILE) {
      problem(`must run on the ${WORKLOAD_PROFILE} workload profile, the only one the environment offers`);
    }
    // An ingress left out is caught by the same two conditions: nothing said is
    // nothing that says false, and what isn't said here is Azure's to decide
    // (a mutation pass showed a branch of its own adds nothing).
    const ingress = at(app.properties, 'configuration', 'ingress');
    if (at(ingress, 'external') !== false) {
      problem('must say its ingress is internal (external false): the public doors are the route configs (G2e)');
    }
    if (at(ingress, 'allowInsecure') !== false) {
      problem('must refuse plain http (allowInsecure false), which peer-to-peer encryption already covers');
    }
    const scale = at(app.properties, 'template', 'scale');
    const most = at(scale, 'maxReplicas');
    const fewest = at(scale, 'minReplicas');
    const only = ONE_REPLICA[workload];
    if (only !== undefined && most !== 1) {
      problem(`must run at most one replica (maxReplicas 1): ${only}; it says ${String(most)}`);
    }
    if (typeof most !== 'number' || most < 1) {
      problem(`must be able to run a replica (maxReplicas at least 1); it says ${String(most)}`);
    }
    if (typeof fewest !== 'number' || fewest < 0 || (typeof most === 'number' && fewest > most)) {
      problem(
        `must keep no more replicas than it may run (minReplicas ${String(fewest)}, maxReplicas ${String(most)})`,
      );
    }
    const containers = containersOf(app);
    if (containers.length !== 1) {
      problem(`must run exactly one container; the snapshot has ${String(containers.length)}`);
    }
    if (list(at(app.properties, 'template', 'initContainers')).length > 0) {
      problem('must run no init container: the work is the one container, in view of the log');
    }
    for (const container of containers) {
      const image = text(at(container, 'image'));
      if (!PINNED_IMAGE.test(image)) {
        problem(`must name its image by digest (SEC-SC-02); it runs ${image}`);
      }
    }
  }
  for (const workload of APP_WORKLOADS) {
    const count = found.filter((app) => jobWorkloadOf(app.name) === workload).length;
    if (count !== 1) {
      add({
        rule: 'apps',
        resource: 'the deployment',
        message: `needs the ${workload} app once; the snapshot has ${String(count)}`,
      });
    }
  }
};

/** A door by the part of its name after the environment's (`doorName`): `cae-…/rtagentxstgapp` is `app`. */
const publicDoorOf = (name: string): string =>
  name.slice(name.lastIndexOf('/') + 1).replace(/^rtagentx(?:stg|prd)/, '');

/**
 * One route of a door, to one target, as a line `PUBLIC_DOORS` can hold: how it
 * matches a path, whether case matters, any rewrite, the app it reaches and any
 * pin. Whatever a door leaves to Azure (case), sends elsewhere (an app this
 * deployment doesn't make) or changes on the way (a rewrite, a pinned revision)
 * reads differently from every listed line.
 */
function routeLine(route: unknown, target: unknown, workloadsByApp: ReadonlyMap<unknown, string>): string {
  const match = at(route, 'match');
  const paths = PATH_MATCHES.filter((kind) => at(match, kind) !== undefined).map(
    (kind) => `${kind} ${JSON.stringify(at(match, kind))}`,
  );
  const caseSensitive = at(match, 'caseSensitive');
  const casing = caseSensitive === true ? '' : caseSensitive === false ? ' in any case' : ' with case left to Azure';
  const action = at(route, 'action');
  const rewrite = action === undefined ? '' : ` rewritten by ${JSON.stringify(action)}`;
  const app = at(target, 'containerApp');
  const reaches =
    target === undefined
      ? 'no app'
      : (workloadsByApp.get(app) ?? `${JSON.stringify(app)}, which this deployment doesn't make`);
  const pins = TARGET_PINS.filter((pin) => at(target, pin) !== undefined)
    .map((pin) => ` pinned to ${pin} ${JSON.stringify(at(target, pin))}`)
    .join('');
  return `${paths.join(' and ') || 'no path'}${casing}${rewrite} to ${reaches}${pins}`;
}

/**
 * A door's routing, a line per route and target, rule by rule in the order
 * Azure tries them. A rule with no route or no target still gets its line,
 * since what Azure makes of one isn't written down.
 */
const routingOf = (door: PredictedResource, workloadsByApp: ReadonlyMap<unknown, string>): string[] =>
  list(at(door.properties, 'rules')).flatMap((rule) => {
    const routes = list(at(rule, 'routes'));
    const targets = list(at(rule, 'targets'));
    return (routes.length === 0 ? [undefined] : routes).flatMap((route) =>
      (targets.length === 0 ? [undefined] : targets).map((target) => routeLine(route, target, workloadsByApp)),
    );
  });

/**
 * The public doors (ADR-002 Amendment G2e), the only way in from the internet.
 * Each is a door of this deployment's environment that `PUBLIC_DOORS` names,
 * serves one host with a certificate binding that is never plain http alone,
 * and routes exactly as its entry says, rule for rule and in order: which paths,
 * whether case matters, to which of this deployment's apps, unchanged and at
 * their live revision. Every door the list names is there once.
 */
const publicDoors: Check = (snapshot, _expected, add) => {
  const environments = ofType(snapshot, TYPES.environment).map((resource) => resource.id);
  const workloadsByApp = new Map<unknown, string>(
    ofType(snapshot, TYPES.app).map((app) => [app.name, jobWorkloadOf(app.name)] as const),
  );
  const found = ofType(snapshot, TYPES.door);
  for (const door of found) {
    const problem = (message: string): void => {
      add({ rule: 'public-doors', resource: door.name, message });
    };
    const listed = PUBLIC_DOORS[publicDoorOf(door.name)];
    if (listed === undefined) {
      problem(`isn't a door PUBLIC_DOORS names (${Object.keys(PUBLIC_DOORS).join(', ')}), so it may route nothing`);
    }
    if (!environments.some((id) => door.id.startsWith(`${id}/httpRouteConfigs/`))) {
      problem("must be a door of this deployment's Container Apps environment");
    }
    const hosts = list(at(door.properties, 'customDomains'));
    if (hosts.length !== 1) problem(`must serve exactly one host; it names ${String(hosts.length)}`);
    for (const host of hosts) {
      if (!SECURE_BINDINGS.has(at(host, 'bindingType'))) {
        problem(`must bind a certificate to ${text(at(host, 'name'))} (Auto or SniEnabled), never plain http alone`);
      }
    }
    const routing = routingOf(door, workloadsByApp);
    if (listed !== undefined && routing.join('\n') !== listed.join('\n')) {
      problem(
        `must route exactly as PUBLIC_DOORS says, in order: ${listed.join('; ')}. It routes: ${routing.join('; ') || 'nothing'}`,
      );
    }
  }
  for (const name of Object.keys(PUBLIC_DOORS)) {
    const count = found.filter((door) => publicDoorOf(door.name) === name).length;
    if (count !== 1) {
      add({
        rule: 'public-doors',
        resource: 'the deployment',
        message: `needs the ${name} door once; the snapshot has ${String(count)}`,
      });
    }
  }
};

/**
 * The doors' certificates (ADR-002 Amendment G2e): a door binds its host's
 * managed certificate once one exists and serves plain http until then, so the
 * host of every door has exactly one, in this deployment's environment,
 * validated by HTTP as a host with an A record is (Microsoft); and none is made
 * for a host no door serves.
 */
const doorCertificates: Check = (snapshot, _expected, add) => {
  const environments = ofType(snapshot, TYPES.environment).map((resource) => resource.id);
  const hosts = ofType(snapshot, TYPES.door).flatMap((door) =>
    list(at(door.properties, 'customDomains')).map((host) => at(host, 'name')),
  );
  const found = ofType(snapshot, TYPES.certificate);
  for (const certificate of found) {
    const problem = (message: string): void => {
      add({ rule: 'door-certificates', resource: certificate.name, message });
    };
    if (!environments.some((id) => certificate.id.startsWith(`${id}/managedCertificates/`))) {
      problem("must be a certificate of this deployment's Container Apps environment");
    }
    const subject = at(certificate.properties, 'subjectName');
    if (!hosts.includes(subject)) problem(`is for ${JSON.stringify(subject)}, a host no door serves`);
    const validation = at(certificate.properties, 'domainControlValidation');
    if (validation !== 'HTTP') {
      problem(`must be validated by HTTP, as a door's host with an A record is; it says ${JSON.stringify(validation)}`);
    }
  }
  for (const host of hosts) {
    const count = found.filter((certificate) => at(certificate.properties, 'subjectName') === host).length;
    if (count !== 1) {
      add({
        rule: 'door-certificates',
        resource: 'the deployment',
        message: `needs one certificate for ${JSON.stringify(host)}; the snapshot has ${String(count)}`,
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
 * What each job and app may read (ADR-002 Amendment G2d): its own identity
 * alone, exactly the secrets `GRANTS` says it reads, each from this
 * deployment's vault by name with no version, through that identity; every one
 * of them read, and nothing read that it wasn't given. A secret reaches a
 * container as a mounted file, except in the few settings
 * `SECRETS_IN_ENVIRONMENT` lists for an image that has no file form for them.
 * Besides, a job holds what `HELD` says it may, exactly once and as given there.
 */
const workloadSecrets: Check = (snapshot, _expected, add) => {
  const vaults = new Set(ofType(snapshot, TYPES.vault).map((vault) => vault.id));
  for (const job of workloadsIn(snapshot)) {
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
    const all = list(at(job.properties, 'configuration', 'secrets'));
    const held = HELD[workload];
    const holding = all.filter((secret) => text(at(secret, 'name')) === held?.name);
    if (held !== undefined) {
      // None held fails the value; twice held, the second.
      const [kept, ...again] = holding;
      const fields = typeof kept === 'object' && kept !== null ? Object.keys(kept) : [];
      if (
        again.length > 0 ||
        at(kept, 'value') !== held.value ||
        fields.some((field) => field !== 'name' && field !== 'value')
      ) {
        problem(`must hold ${held.name} once, as ${held.value} and nothing else: a person writes it before a run`);
      }
      for (const container of containersOf(job)) {
        if (JSON.stringify(list(at(container, 'args'))) !== JSON.stringify(held.args)) {
          problem(
            `must be run as ${held.args.join(' ')} and nothing else: a request in its arguments would sit in the deployment and every run's record`,
          );
        }
      }
    }
    const declared = all.filter((secret) => !holding.includes(secret));
    const given = all.map((secret) => text(at(secret, 'name')));
    const needed = secretsRead(workload);
    for (const name of declared.map((secret) => text(at(secret, 'name'))).filter((secret) => !needed.has(secret))) {
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
 * Nothing a container runs — job or app — sends telemetry out of the UAE
 * (ADR-013, SEC-DATA-08): no OpenTelemetry exporter switched on, and every
 * switch in `TELEMETRY_OFF` said outright on a Zitadel image, never left to a
 * default a version change could move. Zitadel's daily report to zitadel.com
 * carries every instance's domains and counts.
 */
const containerTelemetry: Check = (snapshot, _expected, add) => {
  for (const job of workloadsIn(snapshot)) {
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
      const image = text(at(container, 'image'));
      const switches = TELEMETRY_OFF.filter((off) => image.startsWith(off.images)).flatMap((off) =>
        Object.entries(off.settings),
      );
      for (const [name, wanted] of switches) {
        if (settings.get(name) !== wanted) {
          problem(`must set ${name} to ${wanted} outright, never leave it to the image's default (ADR-013)`);
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
  appsEgress,
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
  auditIntegrityAlert,
  ownerLoginAlert,
  identities,
  releaseIdentity,
  releaseAccess,
  vaultSecrets,
  secretAccess,
  jobs,
  apps,
  publicDoors,
  doorCertificates,
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
