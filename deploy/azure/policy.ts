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
import { readFileSync } from 'node:fs';

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
  | 'database-size'
  | 'database-zone'
  | 'database-measures'
  | 'load-run'
  | 'vault'
  | 'evidence-store'
  | 'activity-downloads'
  | 'workspace'
  | 'log-quota-alerts'
  | 'alert-counts-only'
  | 'alert-runbook'
  | 'alert-delivery'
  | 'resource-logs'
  | 'log-destinations'
  | 'activity-log'
  | 'budget'
  | 'email'
  | 'apps-environment'
  | 'apps-network'
  | 'apps-egress'
  | 'dns-watch'
  | 'dns-allow'
  | 'apps-logs'
  | 'app-errors-alert'
  | 'daily-words-alert'
  | 'audit-integrity-alert'
  | 'token-refused-alert'
  | 'denial-surge-alert'
  | 'holdings-check-alert'
  | 'handoff-queue-alert'
  | 'platform-full-alert'
  | 'integrity-runs-alert'
  | 'agent-cancels-alert'
  | 'agent-cancel-cap-alert'
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
  | 'container-telemetry'
  | 'platform-settings';

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
  communication: 'Microsoft.Communication/communicationServices',
  emailService: 'Microsoft.Communication/emailServices',
  emailDomain: 'Microsoft.Communication/emailServices/domains',
  diagnostics: 'Microsoft.Insights/diagnosticSettings',
  dnsLink: 'Microsoft.Network/privateDnsZones/virtualNetworkLinks',
  dnsZone: 'Microsoft.Network/privateDnsZones',
  dnsPolicy: 'Microsoft.Network/dnsResolverPolicies',
  dnsPolicyRule: 'Microsoft.Network/dnsResolverPolicies/dnsSecurityRules',
  dnsPolicyLink: 'Microsoft.Network/dnsResolverPolicies/virtualNetworkLinks',
  dnsDomainList: 'Microsoft.Network/dnsResolverDomainLists',
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
  storage: 'Microsoft.Storage/storageAccounts',
  blobService: 'Microsoft.Storage/storageAccounts/blobServices',
  container: 'Microsoft.Storage/storageAccounts/blobServices/containers',
  lifecycle: 'Microsoft.Storage/storageAccounts/managementPolicies',
  vault: 'Microsoft.KeyVault/vaults',
  vaultSecret: 'Microsoft.KeyVault/vaults/secrets',
  workspace: 'Microsoft.OperationalInsights/workspaces',
} as const;

/**
 * Types Azure offers only as global resources. The first three hold no
 * customer data or logs; email's three keep what they hold at rest in the data
 * location they are given, which rule `email` holds to the UAE.
 */
const GLOBAL_TYPES: ReadonlySet<string> = new Set([
  TYPES.actionGroup,
  TYPES.dnsZone,
  TYPES.dnsLink,
  TYPES.communication,
  TYPES.emailService,
  TYPES.emailDomain,
]);

/** Communication Services' name for the United Arab Emirates as a data location (ADR-009). */
const EMAIL_DATA_LOCATION = 'UAE';

/** Types whose newest API version is a preview, with why the preview is used. */
export const PREVIEW_API_EXCEPTIONS: Readonly<Record<string, string>> = {
  [TYPES.diagnostics]:
    'Azure publishes diagnostic settings only in preview API versions after 2016-09-01, which predates category groups and resource-specific tables',
};

/** The one role besides the server admin whose login raises the alert (ADR-012 §2). */
const BACKUP_ROLE = 'agentx_backup';

/** Staging's database sizes, name/tier: normal (B1ms), and load for the load run alone (main.bicep's databaseSize, D2c). */
const STAGING_DATABASE_SIZES: readonly string[] = ['Standard_B1ms/Burstable', 'Standard_D2ads_v5/GeneralPurpose'];

/**
 * The load run's settings at their Burstable values (postgres.bicep): its measurements off (4D2d P5; Microsoft: "Don't
 * enable query store on the Burstable pricing tier as it causes performance problems.") and the size's own connection
 * limit (S167).
 */
const BURSTABLE_VALUES: ReadonlyMap<string, string> = new Map([
  ['pg_qs.query_capture_mode', 'none'],
  ['pg_qs.store_query_plans', 'off'],
  ['pgms_wait_sampling.query_capture_mode', 'none'],
  ['track_io_timing', 'off'],
  ['max_connections', '50'],
]);

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
/** Warnings too, Zitadel's spellings included: the daily email's lines (decision 29, P4). */
const PROBLEM_LINES = 'where tostring(parse_json(Log).level) in~ ("warn", "warning", "error", "fatal", "panic")';

/**
 * The one column an alert may split by (ADR-013 rule 3 as amended, decision
 * 30): a line's plain words, fixed text from plain-words.ts, public in the
 * repo. Read only from our own logger's containers, never Zitadel's or its
 * login pages', cut to 300 characters; any other line gets the fallback.
 */
const SAYS_FROM_OWN =
  /^extend Says = iff\(coalesce\(ContainerAppName, JobName\) in \(((?:"[a-z0-9-]+", )*"[a-z0-9-]+")\), substring\(tostring\(parse_json\(Log\)\.says\), 0, 300\), ""\)$/;
/** Our logger's containers: the API and the three jobs built on it. */
const OWN_CONTAINER = /^"(?:ca-agentx-(?:stg|prd)-api|job-agentx-(?:stg|prd)-(?:db-setup|migrate|operator))"$/;
const NO_WORDS =
  'A warning or error with no plain words, from the login service or another part: open the saved query What broke, in plain words.';
const SAYS_FALLBACK = `extend Says = iff(isempty(Says), "${NO_WORDS}", Says)`;
const SAYS_DIMENSIONS = [{ name: 'Says', operator: 'Include', values: ['*'] }];

/**
 * The integrity alarm's events (ADR-012 §2): an audit chain that failed its
 * check, and a check that broke. Our logger writes each event name exactly, so
 * the match keeps its case.
 */
const INTEGRITY_LINES =
  'where tostring(parse_json(Log).event) in ("audit.integrity_failed", "audit.anchor_check_crashed")';

/**
 * A token the login service refused (partner, S88): every call to it logs one
 * as the error type LoginTokenRefused (zitadel-call.ts), whichever token.
 */
const TOKEN_REFUSED_LINES = 'where tostring(parse_json(Log).err.type) == "LoginTokenRefused"';

/**
 * A denial surge's lines (Phase 2 E2): every spend request decided as a
 * denial, REQUIRE_NEW_MANDATE among them (PRD §4.2), counted per agent and the
 * highest kept, so the alert returns one number with no ID dimensions.
 */
const DENIAL_LINES = [
  'where tostring(parse_json(Log).event) == "spend_request.decided"',
  'where tostring(parse_json(Log).decision) in ("DENY", "REQUIRE_NEW_MANDATE")',
  'summarize Denials = count() by Agent = tostring(parse_json(Log).agentId)',
] as const;

/** One agent denied more than this many times in a window is a surge (Logging-and-Monitoring.md: well above normal). */
const DENIAL_SURGE_THRESHOLD = 10;

/**
 * An agent's own cancels' lines (Phase 2 G6, partner decision 11b): each
 * `spend_request.cancelled` the agent made itself, counted per agent and the
 * highest kept, so the alert returns one number with no ID dimensions.
 */
const AGENT_CANCEL_LINES = [
  'where tostring(parse_json(Log).event) == "spend_request.cancelled"',
  'where tostring(parse_json(Log)["by"]) == "agent"',
  'summarize Cancels = count() by Agent = tostring(parse_json(Log).agentId)',
] as const;

/** One agent cancelling more of its own than this in a window: half its day's cap (10) at once. */
const AGENT_CANCELS_THRESHOLD = 5;

/** An agent refused a cancel by its day's cap (Phase 2 G6): steady cancelling the burst alert never sees. */
const AGENT_CANCEL_CAP_LINES = 'where tostring(parse_json(Log).event) == "spend_request.agent_cancels_spent"';

/** A page of the holdings check that failed (Phase 2 E1b's review): that organisation is unchecked until it passes. */
const HOLDINGS_CHECK_FAILED_LINES = 'where tostring(parse_json(Log).event) == "holdings_check.failed"';

/** An agent's decision turned away with the whole platform full (4D2e C, PL-63): calm organisations are being slowed. */
const PLATFORM_FULL_LINES =
  'where tostring(parse_json(Log).event) in ("spend_request.platform_full", "db.pool_wait_ran_out")';

/** Approved requests left standing past 15 minutes for no known reason (Phase 4 gate H8): suppliers unpaid, money held. */
const HANDOFF_QUEUE_STALE_LINES = 'where tostring(parse_json(Log).event) == "handoff.queue_stale"';

/**
 * An integrity job that skipped a whole run, its organisation list unread
 * (Phase 2 E2c), or a run of the activity log's daily seal (Phase 3 L6b) or
 * its seal check (L6c) that stopped early: nothing checked, expired or sealed that run.
 */
const INTEGRITY_RUN_FAILED_LINES =
  'where tostring(parse_json(Log).event) in ("access_log_seal.run_failed", "access_log_seal_check.run_failed", "hold_history.run_failed", "holdings_check.run_failed", "mandate_expiry.run_failed", "request_expiry.run_failed", "request_void.run_failed", "waiting_rejection.run_failed")';

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
 * command, the app's login and every version of the audit chains' MAC and of
 * the field encryption alone (ADR-011 §3, B1c, B4-6b).
 */
const GRANTS: ReadonlySet<string> = new Set([
  ...APP_KEYS.map((key) => `api reads ${key}`),
  ...APP_KEYS.filter((key) => key.startsWith('key-audit-mac-v') || key.startsWith('key-field-encryption-v')).map(
    (key) => `operator reads ${key}`,
  ),
  'api reads db-app-password',
  // B2-6: the API's own secret as the login service's client, which Zitadel gave.
  'api reads api-oidc-client-secret',
  // B5-3: the email service's key, copied from it, and the login service's read-only token for addresses.
  'api reads acs-access-key',
  'api reads zitadel-directory-token',
  // B6-3c: the login service's token for removing second factors once a reset has cooled off.
  'api reads zitadel-reset-token',
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
 * shows what a person writes into it before a run (operator.ts). It reaches the job
 * as a file, like everything else it is given, and is in no vault and no grant.
 * The job runs its own command with that file and nothing else as its
 * arguments: a request written into either would sit in the deployment and
 * every run's record.
 */
/** The load test's three jobs (D2c; tooling/load/job.ts), by the part each runs. */
const LOAD_PARTS: readonly string[] = ['first', 'second', 'cleanup'];

const HELD: Readonly<
  Record<
    string,
    {
      readonly name: string;
      readonly value: string;
      readonly command: readonly string[];
      readonly args: readonly string[];
    }
  >
> = {
  operator: {
    name: 'operator-request',
    value: '[]',
    command: ['node', 'apps/operator/src/main.ts'],
    args: ['--request', '/mnt/secrets/operator-request'],
  },
  // The load test's run request (D2c; apps.bicep `loadRequest`), written by load.ts before each run.
  ...Object.fromEntries(
    LOAD_PARTS.map((part) => [
      `load-${part}`,
      { name: 'load-request', value: '{}', command: ['node', 'tooling/load/job.ts'], args: [part] },
    ]),
  ),
};

/**
 * The load test's run (D2c, PL-38; apps.bicep `loadRun`): staging's alone,
 * and all of it or none. Its three jobs run the load image, as the API's
 * identity (none of their own, so no foundation or secrets deploy), and are
 * given the app's login and keys alone of what the API reads. The API, while
 * they are there and only then, runs at the size it is measured at, with its
 * limits out of k6's way and without the email service's key and the
 * directory token, so it sends no email (the four email settings are all or
 * none).
 */
const LOAD_RUN = {
  jobs: LOAD_PARTS.map((part) => `load-${part}`),
  runsAs: 'api',
  image: 'ghcr.io/shahbaz242630/agent-x-load@',
  reads: new Set(['db-app-password', ...APP_KEYS]),
  apiLeavesOut: new Set(['acs-access-key', 'zitadel-directory-token']),
  apiSize: { cpu: 2, memory: '4Gi' },
  // Twenty connections, on the larger server `foundation --load-size` gives, whose limit postgres.bicep states.
  // Staging's small server has 35 for everyone, so out of a load run its API keeps to ten (PL-63).
  apiPool: '20',
  stagingPool: 10,
  apiSettings: {
    AGENTX_RATE_LIMIT_PER_MINUTE: '50000',
    AGENTX_RATE_LIMIT_PER_USER_PER_MINUTE: '50000',
    AGENTX_RATE_LIMIT_PER_AGENT_PER_MINUTE: '50000',
    AGENTX_RATE_LIMIT_PER_ORGANISATION_PER_MINUTE: '50000',
    AGENTX_LOG_EVENT_CAP_PER_MINUTE: '200000',
    // The fair gate's numbers it is measured at (tooling/load/plan.ts's LOAD_GATE).
    AGENTX_DECISION_GATE_ACTIVE: '20',
    AGENTX_DECISION_GATE_PER_ORGANISATION: '6',
    AGENTX_DECISION_GATE_WAITING_PER_ORGANISATION: '100',
    AGENTX_DECISION_GATE_WAIT_MS: '10000',
  } as Readonly<Record<string, string>>,
};

const isLoadJob = (workload: string): boolean => LOAD_RUN.jobs.includes(workload);

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

/**
 * The secrets a run copies from an Azure service of this deployment on every
 * run, by the type of the service (B5-3): nobody pastes or makes them, and a
 * run after the service's key is rotated brings the new one.
 */
const COPIED: Readonly<Record<string, string>> = { 'acs-access-key': TYPES.communication };

/** A copied key's value, as a template and a snapshot write it: the primary key the service lists. */
const LISTED_KEY = /^\[listKeys\('([^']+)', '[^']+'\)\.primaryKey\]$/;

/** Whether a vault secret's value is copied from the service COPIED names for it, one this deployment creates. */
const isCopiedKey = (snapshot: Snapshot, secret: PredictedResource, value: unknown): boolean => {
  const type = COPIED[secretNameOf(secret)];
  const from = typeof value === 'string' ? LISTED_KEY.exec(value)?.[1] : undefined;
  return type !== undefined && from !== undefined && ofType(snapshot, type).some((service) => service.id === from);
};

/** The audit exports' role's one data action: Put Blob of a file not there yet (Microsoft), never overwrite or read. */
const EVIDENCE_WRITE = 'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action';

/** The one container the audit exports go to (modules/evidence.bicep). */
const EVIDENCE_CONTAINER = 'audit-exports';

/** The audit exports' custom role as a role assignment names it, without case (modules/evidence.bicep names it so). */
const evidenceRoleName = (groupId: string): string => bicepGuid(groupId, 'evidence-writer');

/**
 * How long each environment keeps an export unchangeable (decision 27):
 * production five years, Locked for good; staging a few days and Unlocked, so
 * a test file never holds the account (and its resource group) for years.
 * Azure can't create a policy Locked, so production's very first foundation
 * (the account not there yet) is a one-off hand run with Unlocked, outside
 * this check, then every run after it is Locked and checked (PL-44).
 */
const EVIDENCE_KEPT = {
  production: { state: 'Locked', days: (days: number) => days === 1826, sku: 'Standard_ZRS' },
  staging: { state: 'Unlocked', days: (days: number) => days >= 1 && days <= 7, sku: 'Standard_LRS' },
} as const;

/**
 * The two Storage accounts, told apart by name: `stagentx` then the
 * environment's three letters and the suffix for the audit exports
 * (modules/evidence.bicep), with `dl` before the letters for the activity
 * downloads (modules/activity-downloads.bicep). Azure gives an account lower
 * case letters and digits alone, so neither name can be read as the other.
 */
const EVIDENCE_ACCOUNT = /^stagentx(?:stg|prd)[a-z0-9]{4,6}$/;
const DOWNLOADS_ACCOUNT = /^stagentxdl(?:stg|prd)[a-z0-9]{4,6}$/;

/** The one container the activity downloads are kept in (modules/activity-downloads.bicep). */
const DOWNLOADS_CONTAINER = 'activity-downloads';

/**
 * The downloads' role's two data actions: Get Blob (a part of a file), and
 * Put Block and Put Block List (a file written over its own name). Never
 * delete: the lifecycle rule does that.
 */
const DOWNLOADS_ACTIONS = [
  'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read',
  'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write',
] as const;

/** The activity downloads' custom role as a role assignment names it, without case (modules/activity-downloads.bicep). */
const downloadsRoleName = (groupId: string): string => bicepGuid(groupId, 'activity-downloads');

/**
 * The most days the store keeps a download's file: a download reads ready 7
 * days from its last file, and builds for 7 days at most, so its first file
 * may be 14 days old when it expires (decision 31; 32e, F1 G5). The API refuses
 * every read past its 7 days; this deletes what it no longer reads.
 */
const DOWNLOADS_KEPT_DAYS = 14;

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
  if (/^@["']/.test(rest)) return verbatimEnd(query, index + 2, rest.charAt(1));
  if (rest.startsWith('"') || rest.startsWith("'")) {
    const quote = rest.charAt(0);
    let end = index + 1;
    while (end < query.length && query.charAt(end) !== quote) end += query.charAt(end) === '\\' ? 2 : 1;
    return Math.min(end + 1, query.length);
  }
  return undefined;
}

/** Where a verbatim KQL string ends (one past it), its text starting at `from`: no escapes but a doubled quote. */
function verbatimEnd(query: string, from: number, quote: string): number {
  let end = from;
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
 * The column a criterion counts when it splits by plain words and nothing
 * else, with Says its only dimension: exactly `ContainerAppConsoleLogs |
 * <error lines, or warning and error lines> | extend Says = <ours> | extend Says = <fallback> | summarize
 * Name = count() by Says`. No other stage, so nothing can rewrite `Log` or a
 * container's name before the words are read. Undefined for any other shape.
 */
function saysCountColumn(criterion: unknown): string | undefined {
  const stages = kqlStages(String(at(criterion, 'query')));
  const own = SAYS_FROM_OWN.exec(stages.at(-3) ?? '');
  const counted = /^summarize ([A-Za-z_][A-Za-z0-9_]*) = count\(\) by Says$/.exec(stages.at(-1) ?? '');
  const containers = own?.[1]?.split(', ') ?? [];
  return stages.length === 5 &&
    stages[0] === 'ContainerAppConsoleLogs' &&
    (stages[1] === ERROR_LINES || stages[1] === PROBLEM_LINES) &&
    own !== null &&
    containers.every((container) => OWN_CONTAINER.test(container)) &&
    stages.at(-2) === SAYS_FALLBACK &&
    JSON.stringify(at(criterion, 'dimensions')) === JSON.stringify(SAYS_DIMENSIONS)
    ? counted?.[1]
    : undefined;
}

/**
 * Whether an alert sees every minute and fires on the first window with a
 * match: its window is as long as the time between runs, so no minute goes
 * unwatched, and one failing window is enough, so it never waits for more.
 */
const watchesEveryWindow = (alert: PredictedResource, criterion: unknown): boolean =>
  at(alert.properties, 'windowSize') === at(alert.properties, 'evaluationFrequency') &&
  at(criterion, 'failingPeriods', 'numberOfEvaluationPeriods') === 1 &&
  at(criterion, 'failingPeriods', 'minFailingPeriodsToAlert') === 1;

/**
 * Whether a criterion totals its one row's number: `Count` would count the row
 * itself, always 1, so a threshold above it never fires, and one of 0 always
 * does (E2b review).
 */
const totals = (criterion: unknown): boolean => at(criterion, 'timeAggregation') === 'Total';

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

/**
 * Whether an enabled alert on this deployment's workspace has a condition
 * `matches` takes. A `stateless SEV-1` one is severity 1 and never resolves
 * itself (autoMitigate false), so it notifies on every window, not once.
 */
const workspaceAlerted = (
  snapshot: Snapshot,
  kind: 'any' | 'stateless SEV-1',
  matches: (criterion: unknown, alert: PredictedResource) => boolean,
): boolean => {
  const workspaces = workspaceIds(snapshot);
  return ofType(snapshot, TYPES.alert).some(
    (alert) =>
      at(alert.properties, 'enabled') === true &&
      (kind === 'any' || (at(alert.properties, 'severity') === 1 && at(alert.properties, 'autoMitigate') === false)) &&
      list(at(alert.properties, 'scopes')).some((scope) => workspaces.has(scope)) &&
      list(at(alert.properties, 'criteria', 'allOf')).some((criterion) => matches(criterion, alert)),
  );
};

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
    ['the DNS policy', TYPES.dnsPolicy, 1, 1],
    ['the key vault', TYPES.vault, 1, Infinity],
    ['the Postgres server', TYPES.server, 1, Infinity],
    ['the Container Apps environment', TYPES.environment, 1, 1],
    // The audit exports' store and the activity downloads', each with its own blob service and container.
    ["Storage accounts, the audit exports' and the activity downloads'", TYPES.storage, 2, 2],
    ['blob services, one in each Storage account', TYPES.blobService, 2, 2],
    ['containers, one in each Storage account', TYPES.container, 2, 2],
  ];
  for (const [what, type, least, most] of counts) {
    const found = ofType(snapshot, type).length;
    if (found < least || found > most) {
      const exactly = `exactly ${least === 1 ? 'one' : String(least)}`;
      add({
        rule: 'required',
        resource: 'the deployment',
        message: `needs ${least === most ? exactly : 'at least one'} ${what} (${type}); the snapshot has ${String(found)}`,
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
 * app's keys holds its own member of the parameter they arrive in, a copied
 * key what its service lists (`COPIED`), and a job holds what `HELD` gives
 * it, which is no secret, as written there.
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
    if (
      resource.type === TYPES.vaultSecret &&
      literal(value) &&
      !isOwnKeyMember(resource, value) &&
      !isCopiedKey(snapshot, resource, value)
    ) {
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
    // A copied key, written on every run from what its service lists: `vault-secrets` holds which service.
    const copied = !once && condition === undefined && typeof value === 'string' && LISTED_KEY.test(value);
    const problem = (message: string): Problem[] => [{ rule: 'vault-secrets', resource: `${file}: ${name}`, message }];
    if (once && typeof value === 'string' && LISTED_KEY.test(value)) {
      return problem(
        "is copied from its service only if it doesn't exist: a copied key is written on every run, so a key rotated in Azure reaches the vault",
      );
    }
    if (once && condition !== undefined) {
      return problem(
        "is written on a condition and only if it doesn't exist: a secret that rotates takes the condition alone, one created once (the master key, the app's keys) @onlyIfNotExists() alone",
      );
    }
    if (!once && !whenGiven && !copied) {
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

/** Staging runs one of its two sizes (main.bicep), never another by mistake; production's waits on the load run (PL-38). */
const databaseSize: Check = (snapshot, expected, add) => {
  if (expected.environment !== 'staging') return;
  for (const server of ofType(snapshot, TYPES.server)) {
    const size = `${String(at(server, 'sku', 'name'))}/${String(at(server, 'sku', 'tier'))}`;
    if (!STAGING_DATABASE_SIZES.includes(size)) {
      add({
        rule: 'database-size',
        resource: server.name,
        message: `runs ${STAGING_DATABASE_SIZES.join(' or ')} on staging (ADR-002; the load run, D2c)`,
      });
    }
  }
};

/** A server's settings by name, as this deployment sends them. */
const serverSettings = (snapshot: Snapshot, server: PredictedResource): ReadonlyMap<string | undefined, unknown> =>
  new Map(
    ofType(snapshot, TYPES.setting)
      .filter((setting) => setting.id.startsWith(`${server.id}/`))
      .map((setting) => [setting.name.split('/').at(-1), at(setting.properties, 'value')]),
  );

/** Every server states its zone, and measures nothing on a Burstable size (4D2d P5). */
const databaseZoneAndMeasures: Check = (snapshot, _expected, add) => {
  for (const server of ofType(snapshot, TYPES.server)) {
    if (!['1', '2', '3'].includes(String(at(server.properties, 'availabilityZone')))) {
      add({
        rule: 'database-zone',
        resource: server.name,
        message: 'states the zone it runs in, never left to Azure (4D2d P5)',
      });
    }
    const settings = serverSettings(snapshot, server);
    const differing = [...BURSTABLE_VALUES]
      .filter(([name, value]) => settings.get(name) !== value)
      .map(([name]) => name);
    if (at(server, 'sku', 'tier') === 'Burstable' && differing.length > 0) {
      add({
        rule: 'database-measures',
        resource: server.name,
        message: `holds a Burstable size to its own values, measurements off (Microsoft) and a connection limit of 50; differing or not stated: ${differing.join(', ')}`,
      });
    }
  }
};

const database: Check = (snapshot, expected, add) => {
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
    const settings = serverSettings(snapshot, server);
    if (settings.get('require_secure_transport') !== 'on' || settings.get('ssl_min_protocol_version') !== 'TLSv1.3') {
      problem('database-tls', 'requires TLS on every connection, 1.3 at least');
    }
    // ADR-012 §2: every login is logged, and one by the admin or the backup
    // role raises a SEV-1 alert that notifies on every window it happens in.
    // The alert matches the line as Azure writes it, from the prefix held
    // here on (S19: a pattern without the prefix never matched).
    const admin = String(at(properties, 'administratorLogin'));
    const pattern = `@"${LOG_LINE_START}connection authorized: user=(${admin}|${BACKUP_ROLE}) "`;
    const alerted = workspaceAlerted(
      snapshot,
      'stateless SEV-1',
      (criterion, alert) =>
        queryIs(at(criterion, 'query'), 'PGSQLServerLogs', [`where Message matches regex ${pattern}`], 'count()') &&
        watchesEveryWindow(alert, criterion),
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
 * which Azure keeps current; then GitHub's published addresses, two sets,
 * which nothing keeps current but the refresher (github-ranges.ts); and two
 * more service tags for the apps' own outbound calls: email (B5) and the
 * stores of the audit exports (E10c) and the activity downloads (L5c), in
 * this region alone.
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
  // Broad, every Front Door site: the API's list of exact origins is the real limit.
  ['Tcp to AzureFrontDoor.Frontend on 443', "Communication Services' email endpoint, which answers behind Front Door"],
  // Every account in the region, not ours alone: the store's own network rule is the limit until PL-43.
  [`Tcp to Storage.${region} on 443`, "the operator's audit exports and the API's activity downloads, to their stores"],
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

/** Every name, in a DNS domain list (Microsoft: a rule on the '.' domain applies to all domains). */
const EVERY_NAME = '.';

/** A DNS rule's action, which Azure reads without regard to case. */
const dnsActionOf = (rule: PredictedResource): string =>
  text(at(rule.properties, 'action', 'actionType')).toLowerCase();

/** Whether a DNS rule is on: anything but 'Disabled', in any case. */
const dnsRuleOn = (rule: PredictedResource): boolean =>
  text(at(rule.properties, 'dnsSecurityRuleState')).toLowerCase() !== 'disabled';

/**
 * Every lookup the network makes is judged by a DNS policy of this deployment
 * (S68 audit finding 14): its rules see what Azure's DNS answers, which the
 * apps subnet's rules must let out and so can't filter. The network is linked
 * to one of the deployment's policies, which holds an enabled rule over every
 * name, in a list of this deployment, that alerts on or blocks each lookup,
 * so a name no rule above it names is still judged; and no rule allows every
 * name, which would let each lookup through before that rule is reached (it
 * would still be logged, Allow logs too, but never blocked once that rule
 * blocks). A broad Allow short of every name (`com.`) would shadow it the
 * same way: the allowlist that comes with Block must refuse those too. Azure
 * reads the state and the action without regard to case, so they are
 * compared that way. Rule `resource-logs` sends what the policy sees to the
 * workspace.
 */
const dnsWatch: Check = (snapshot, _expected, add) => {
  const everyName = new Set(
    ofType(snapshot, TYPES.dnsDomainList)
      .filter((domains) => list(at(domains.properties, 'domains')).includes(EVERY_NAME))
      .map((domains) => domains.id),
  );
  const rulesOf = (policy: string): readonly PredictedResource[] =>
    ofType(snapshot, TYPES.dnsPolicyRule).filter((rule) => rule.id.startsWith(`${policy}/dnsSecurityRules/`));
  const coversEveryName = (rule: PredictedResource): boolean =>
    list(at(rule.properties, 'dnsResolverDomainLists')).some((domains) => everyName.has(text(at(domains, 'id'))));
  const watches = (rule: PredictedResource): boolean =>
    dnsRuleOn(rule) && ['alert', 'block'].includes(dnsActionOf(rule)) && coversEveryName(rule);
  for (const network of ofType(snapshot, TYPES.network)) {
    const linkedTo = ofType(snapshot, TYPES.dnsPolicyLink)
      .filter((link) => at(link.properties, 'virtualNetwork', 'id') === network.id)
      // A policy this deployment doesn't create has no rules in the snapshot, so it judges nothing.
      .map((link) => link.id.slice(0, link.id.lastIndexOf('/virtualNetworkLinks/')));
    const judged = linkedTo.some((policy) => {
      const rules = rulesOf(policy);
      return rules.some(watches) && !rules.some((rule) => dnsActionOf(rule) === 'allow' && coversEveryName(rule));
    });
    if (!judged) {
      add({
        rule: 'dns-watch',
        resource: network.name,
        message:
          "must be linked to this deployment's DNS policy, with an enabled rule alerting on or blocking every name ('.') and none allowing every name, so each lookup it makes is seen",
      });
    }
  }
};

/** The names the network may look up, reviewed one by one (dns-allowed.json, which dns-policy.bicep compiles into its Allow rule). */
export const DNS_ALLOWED: ReadonlySet<string> = new Set(
  (
    JSON.parse(readFileSync(new URL('./dns-allowed.json', import.meta.url), 'utf8')) as {
      readonly domains: readonly { readonly domain: string }[];
    }
  ).domains.map((entry) => entry.domain),
);

/**
 * A DNS rule that allows lets its names through before the rule that alerts
 * on or blocks every name is reached (dns-watch), so what it allows is held to
 * the reviewed list (S78): every name in every list an enabled Allow rule
 * names is on it (a test holds the list to nothing too broad), and each such
 * list is one this deployment creates (a list the snapshot doesn't hold can't
 * be read, so it is refused).
 */
const dnsAllow: Check = (snapshot, _expected, add) => {
  const lists = new Map(ofType(snapshot, TYPES.dnsDomainList).map((names) => [names.id, names]));
  for (const rule of ofType(snapshot, TYPES.dnsPolicyRule)) {
    if (dnsActionOf(rule) !== 'allow' || !dnsRuleOn(rule)) continue;
    const refused = list(at(rule.properties, 'dnsResolverDomainLists')).flatMap((reference) => {
      const id = text(at(reference, 'id'));
      const names = lists.get(id);
      if (names === undefined) return [`a list it doesn't create (${id})`];
      return list(at(names.properties, 'domains'))
        .map(String)
        .filter((domain) => !DNS_ALLOWED.has(domain));
    });
    if (refused.length > 0) {
      add({
        rule: 'dns-allow',
        resource: rule.name,
        message: `allows names outside the reviewed list (dns-allowed.json): ${refused.join(', ')}`,
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

/**
 * What either store's account must be, each a line a problem names: shut to
 * everyone but Entra sign-ins from this deployment's apps subnet. Its copies
 * and whether it is write-once are each store's own.
 */
function storeAccountLines(
  account: PredictedResource,
  appsSubnets: ReadonlySet<unknown>,
): (readonly [string, boolean])[] {
  const properties = account.properties;
  const acls = at(properties, 'networkAcls');
  const subnetRules = list(at(acls, 'virtualNetworkRules'));
  return [
    ['kind StorageV2', account.kind === 'StorageV2'],
    [
      'TLS 1.2 or later, HTTPS only',
      at(properties, 'minimumTlsVersion') === 'TLS1_2' && at(properties, 'supportsHttpsTrafficOnly') === true,
    ],
    [
      'Entra sign-in only (shared keys off, OAuth by default)',
      at(properties, 'allowSharedKeyAccess') === false && at(properties, 'defaultToOAuthAuthentication') === true,
    ],
    [
      'no public blobs, and no copying from another tenant',
      at(properties, 'allowBlobPublicAccess') === false &&
        at(properties, 'allowCrossTenantReplication') === false &&
        at(properties, 'allowedCopyScope') === 'AAD',
    ],
    [
      'no other way in (hierarchical names, SFTP, local users, NFS)',
      ['isHnsEnabled', 'isSftpEnabled', 'isLocalUserEnabled', 'isNfsV3Enabled'].every(
        (key) => at(properties, key) === false,
      ),
    ],
    [
      'requests refused by default, with no exceptions for Azure services, addresses or resources',
      at(acls, 'defaultAction') === 'Deny' &&
        at(acls, 'bypass') === 'None' &&
        list(at(acls, 'ipRules')).length === 0 &&
        list(at(acls, 'resourceAccessRules')).length === 0,
    ],
    [
      "this deployment's apps subnet as the only subnet let in",
      subnetRules.length === 1 && appsSubnets.has(at(subnetRules[0], 'id')),
    ],
    ['infrastructure encryption', at(properties, 'encryption', 'requireInfrastructureEncryption') === true],
  ];
}

/** What the audit-export store's account must be, each a line a problem names; `kept` is its environment's. */
function evidenceAccountProblems(
  account: PredictedResource,
  kept: (typeof EVIDENCE_KEPT)[keyof typeof EVIDENCE_KEPT],
  appsSubnets: ReadonlySet<unknown>,
): string[] {
  const properties = account.properties;
  const policy = at(properties, 'immutableStorageWithVersioning', 'immutabilityPolicy');
  const required: readonly (readonly [string, boolean])[] = [
    ...storeAccountLines(account, appsSubnets),
    [`${kept.sku} copies`, at(account, 'sku', 'name') === kept.sku],
    [
      `version-level immutability, ${kept.state}, for this environment's days, with no appends to a kept file`,
      at(properties, 'immutableStorageWithVersioning', 'enabled') === true &&
        at(policy, 'state') === kept.state &&
        kept.days(Number(at(policy, 'immutabilityPeriodSinceCreationInDays'))) &&
        at(policy, 'allowProtectedAppendWrites') === false,
    ],
  ];
  return required.filter(([, holds]) => !holds).map(([what]) => what);
}

/** Whether a resource is a part of an activity downloads' account (`activity-downloads`'s, not `evidence-store`'s). */
const inDownloadsStore = (snapshot: Snapshot, resource: PredictedResource): boolean =>
  ofType(snapshot, TYPES.storage)
    .filter((account) => DOWNLOADS_ACCOUNT.test(account.name))
    .some((account) => resource.id.toLowerCase().startsWith(`${account.id}/`.toLowerCase()));

/**
 * The write-once store for our team's audit exports (ADR-005 §6, E10c;
 * decisions 27 and 28): one account, named as modules/evidence.bicep names
 * it and as `evidenceAccountProblems` says, with versioning on its one blob
 * service and one private container; no other Storage resource (a lifecycle
 * rule, a file share, a local user) but the activity downloads' store's,
 * which is `activity-downloads`'s; the apps subnet keeps the service endpoint
 * its network rule needs. Its one custom role allows adding a new file and
 * nothing else, assignable in the resource group alone, and is given once, on
 * the container, to the operator's identity, whose job alone is told where
 * the store is (`storeSettingsProblems`). Its logs are `resource-logs`'s.
 */
const evidenceStore: Check = (snapshot, expected, add) => {
  const problem = (resource: string, message: string): void => {
    add({ rule: 'evidence-store', resource, message });
  };
  const appsSubnets = appsSubnetIds(snapshot);
  const accounts = ofType(snapshot, TYPES.storage).filter((account) => EVIDENCE_ACCOUNT.test(account.name));
  for (const account of ofType(snapshot, TYPES.storage)) {
    if (EVIDENCE_ACCOUNT.test(account.name)) {
      for (const what of evidenceAccountProblems(account, EVIDENCE_KEPT[expected.environment], appsSubnets)) {
        problem(account.name, `must have ${what}`);
      }
    } else if (!DOWNLOADS_ACCOUNT.test(account.name)) {
      problem(
        account.name,
        "is a Storage account named as neither store: the deployment has the audit exports' and the activity downloads' alone",
      );
    }
  }
  if (accounts.length !== 1) {
    problem('the deployment', `needs one audit-export store; the snapshot has ${String(accounts.length)}`);
  }
  evidencePartsProblems(snapshot, accounts, problem);
  for (const network of ofType(snapshot, TYPES.network)) {
    const endpoints = list(at(appsSubnetOf(network), 'properties', 'serviceEndpoints'));
    const kept = endpoints.some(
      (endpoint) =>
        at(endpoint, 'service') === 'Microsoft.Storage' &&
        JSON.stringify(at(endpoint, 'locations')) === JSON.stringify([network.location]),
    );
    if (!kept) {
      problem(network.name, "must keep its apps subnet's Storage service endpoint, in its own region, for the store");
    }
  }
  const writers = storeRoleProblems(
    snapshot,
    {
      name: evidenceRoleName(groupOf(snapshot)),
      dataActions: [EVIDENCE_WRITE],
      containers: ofType(snapshot, TYPES.container).filter((container) => !inDownloadsStore(snapshot, container)),
      workload: 'operator',
      called: "the audit exports' role",
      on: 'the export container',
    },
    problem,
  );
  storeSettingsProblems(
    snapshot,
    {
      prefix: EVIDENCE_SETTING_PREFIX,
      url: 'AGENTX_EVIDENCE_CONTAINER_URL',
      clientId: 'AGENTX_EVIDENCE_CLIENT_ID',
      accounts,
      container: EVIDENCE_CONTAINER,
      holds: (workload) => workload.type === TYPES.job && jobWorkloadOf(workload.name) === 'operator',
      holder: "the operator's job writes to the store",
      store: 'store',
    },
    writers,
    problem,
  );
};

/**
 * The store's blob service, its container and no other Storage resource, a
 * part of `evidence-store`: every one but the activity downloads' store's.
 */
function evidencePartsProblems(
  snapshot: Snapshot,
  accounts: readonly PredictedResource[],
  problem: (resource: string, message: string) => void,
): void {
  const ours = (resource: PredictedResource): boolean => !inDownloadsStore(snapshot, resource);
  const blobServices = ofType(snapshot, TYPES.blobService).filter(ours);
  for (const service of blobServices) {
    if (!accounts.some((account) => service.id === `${account.id}/blobServices/default`)) {
      problem(service.name, "must be the default blob service of this deployment's store");
    }
    if (at(service.properties, 'isVersioningEnabled') !== true) {
      problem(service.name, 'must keep versions: version-level immutability keeps every one');
    }
  }
  for (const container of ofType(snapshot, TYPES.container).filter(ours)) {
    if (
      !blobServices.some((service) => container.id === `${service.id}/containers/${EVIDENCE_CONTAINER}`) ||
      at(container.properties, 'publicAccess') !== 'None'
    ) {
      problem(container.name, `must be ${EVIDENCE_CONTAINER} in this deployment's store, with no public access`);
    }
  }
  const known: readonly string[] = [TYPES.storage, TYPES.blobService, TYPES.container];
  for (const resource of snapshot.predictedResources.filter(ours)) {
    if (resource.type.toLowerCase().startsWith('microsoft.storage/') && !known.includes(resource.type)) {
      problem(resource.name, `is a ${resource.type}: the store holds one container and nothing else`);
    }
  }
}

/** A store's custom role, by what it allows, where it is given, and to whom (modules/evidence.bicep, modules/activity-downloads.bicep). */
interface StoreRole {
  /** Its name as the module makes it, a GUID from the resource group and a fixed word. */
  readonly name: string;
  readonly dataActions: readonly string[];
  /** The containers it may be given on. */
  readonly containers: readonly PredictedResource[];
  /** The one app or job whose identity it is given to. */
  readonly workload: string;
  /** What a problem calls it, and the container it is given on. */
  readonly called: string;
  readonly on: string;
}

/**
 * A store's custom role and its one assignment, a part of `evidence-store` and
 * `activity-downloads`: exactly its data actions, no action, assignable in the
 * resource group alone, given once on the container to its workload's
 * identity. Returns the identities it is given to.
 */
function storeRoleProblems(
  snapshot: Snapshot,
  wanted: StoreRole,
  problem: (resource: string, message: string) => void,
): readonly PredictedResource[] {
  const group = groupOf(snapshot);
  const roles = ofType(snapshot, TYPES.roleDefinition).filter((role) => role.name === wanted.name);
  for (const role of roles) {
    const scopes = list(at(role.properties, 'assignableScopes'));
    const permissions = list(at(role.properties, 'permissions'));
    if (
      scopes.length !== 1 ||
      scopes[0] !== group ||
      permissions.flatMap((entry) => list(at(entry, 'actions'))).length > 0 ||
      actionSet(permissions.flatMap((entry) => list(at(entry, 'dataActions')))) !== actionSet(wanted.dataActions)
    ) {
      problem(
        role.name,
        `must allow ${wanted.dataActions.join(' and ')} alone, no action, and be assignable in this deployment's resource group alone`,
      );
    }
  }
  if (roles.length !== 1) {
    problem('the deployment', `needs one custom role for ${wanted.called}; the snapshot has ${String(roles.length)}`);
  }
  const role = customRoleId(group, wanted.name);
  const assignments = ofType(snapshot, TYPES.roleAssignment).filter((assignment) => roleOf(assignment) === role);
  for (const assignment of assignments) {
    const identity = principalOf(snapshot, assignment);
    if (
      !wanted.containers.some((container) => container.id === scopeOf(assignment)) ||
      identity === undefined ||
      workloadOf(identity.name) !== wanted.workload
    ) {
      problem(
        assignment.name,
        `must give ${wanted.called} on ${wanted.on} alone, to the ${wanted.workload}'s identity (principalType ServicePrincipal)`,
      );
    }
  }
  if (assignments.length !== 1) {
    problem(
      'the deployment',
      `must give ${wanted.called} once, to the ${wanted.workload}; it gives it ${String(assignments.length)} times`,
    );
  }
  return assignments.flatMap((assignment) => principalOf(snapshot, assignment) ?? []);
}

/** How the operator's job is told where to write an audit export (apps.bicep `evidenceSettings`). */
const EVIDENCE_SETTING_PREFIX = 'AGENTX_EVIDENCE_';

/** How the API is told where to keep the activity downloads (apps.bicep `activityDownloadsSettings`). */
const DOWNLOADS_SETTING_PREFIX = 'AGENTX_ACTIVITY_DOWNLOADS_';

/** A store's address as apps.bicep writes it: the account, Azure's own storage suffix, then the container. */
const STORE_URL =
  /^\[format\('https:\/\/\{0\}\.blob\.\{1\}\/\{2\}', '([^']+)', environment\(\)\.suffixes\.storage, '([^']+)'\)\]$/;

/** An identity's client ID as apps.bicep reads it at deployment: the identity's id. */
const CLIENT_ID_OF = /^\[reference\('([^']+)', '[^']+'\)\.clientId\]$/;

/** The two settings that point one workload at a store, and who that workload is. */
interface StoreSettings {
  /** How every setting of the store's starts: no other workload sets one. */
  readonly prefix: string;
  readonly url: string;
  readonly clientId: string;
  /** The store's account by name; the URL must name the one there is. */
  readonly accounts: readonly PredictedResource[];
  readonly container: string;
  readonly holds: (workload: PredictedResource) => boolean;
  /** Who alone is told, and what a problem calls the store. */
  readonly holder: string;
  readonly store: string;
}

/**
 * Where a store's one workload reads and writes, a part of `evidence-store`
 * (E10c-3b-2) and `activity-downloads`: this deployment's one store and its
 * container, as the identity the store's role is given to, each said once as
 * a value. No other workload sets a setting with the store's prefix, so
 * nothing else is pointed at the store, nor at a folder in its place.
 */
function storeSettingsProblems(
  snapshot: Snapshot,
  wanted: StoreSettings,
  holders: readonly PredictedResource[],
  problem: (resource: string, message: string) => void,
): void {
  for (const workload of workloadsIn(snapshot)) {
    for (const container of containersOf(workload)) {
      const settings = list(at(container, 'env')).filter((entry) => text(at(entry, 'name')).startsWith(wanted.prefix));
      const names = settings.map((entry) => text(at(entry, 'name')));
      if (!wanted.holds(workload)) {
        if (names.length > 0) problem(workload.name, `sets ${names.join(', ')}: only ${wanted.holder}`);
        continue;
      }
      const values = new Map(settings.map((entry) => [text(at(entry, 'name')), text(at(entry, 'value'))] as const));
      const url = STORE_URL.exec(values.get(wanted.url) ?? '');
      const client = CLIENT_ID_OF.exec(values.get(wanted.clientId) ?? '');
      const sound =
        names.toSorted().join() === [wanted.url, wanted.clientId].toSorted().join() &&
        wanted.accounts.length === 1 &&
        url !== null &&
        url[1] === wanted.accounts[0]?.name &&
        url[2] === wanted.container &&
        holders.some((holder) => holder.id === client?.[1]);
      if (!sound) {
        problem(
          workload.name,
          `must set ${wanted.url} to this deployment's ${wanted.store}'s ${wanted.container} container, and ${wanted.clientId} to the client ID of the identity its role is given to, each once as a value, and no other ${wanted.prefix} setting`,
        );
      }
    }
  }
}

/** What the activity downloads' account must be, each a line a problem names: as the audit exports', but one copy and not write-once. */
function downloadsAccountProblems(account: PredictedResource, appsSubnets: ReadonlySet<unknown>): string[] {
  const required: readonly (readonly [string, boolean])[] = [
    ...storeAccountLines(account, appsSubnets),
    ['Standard_LRS copies', at(account, 'sku', 'name') === 'Standard_LRS'],
    // A file is written over its own name, which a write-once account refuses.
    [
      'no immutability',
      at(account.properties, 'immutableStorageWithVersioning', 'enabled') !== true &&
        isEmpty(at(account.properties, 'immutableStorageWithVersioning', 'immutabilityPolicy')),
    ],
  ];
  return required.filter(([, holds]) => !holds).map(([what]) => what);
}

/**
 * Whether a lifecycle rule deletes every file in the downloads container
 * within DOWNLOADS_KEPT_DAYS of its making: switched on, for block blobs,
 * narrowed by nothing but the container itself.
 */
function deletesWithinTwoWeeks(rule: unknown): boolean {
  const filters = at(rule, 'definition', 'filters');
  const prefixes = list(at(filters, 'prefixMatch'));
  const days = at(rule, 'definition', 'actions', 'baseBlob', 'delete', 'daysAfterCreationGreaterThan');
  return (
    at(rule, 'enabled') === true &&
    at(rule, 'type') === 'Lifecycle' &&
    list(at(filters, 'blobTypes')).includes('blockBlob') &&
    Object.keys(filters ?? {}).every((key) => key === 'blobTypes' || key === 'prefixMatch') &&
    (prefixes.length === 0 || (prefixes.length === 1 && prefixes[0] === `${DOWNLOADS_CONTAINER}/`)) &&
    typeof days === 'number' &&
    days >= 0 &&
    days <= DOWNLOADS_KEPT_DAYS
  );
}

/**
 * The downloads store's parts, a part of `activity-downloads`: its default
 * blob service with versions and soft delete off, so nothing outlives the
 * lifecycle rule; one private container; that rule; and no other Storage
 * resource.
 */
function downloadsPartsProblems(
  snapshot: Snapshot,
  account: PredictedResource,
  problem: (resource: string, message: string) => void,
): void {
  const service = `${account.id}/blobServices/default`;
  const parts = snapshot.predictedResources.filter((resource) =>
    resource.id.toLowerCase().startsWith(`${account.id}/`.toLowerCase()),
  );
  const blobServices = parts.filter((resource) => resource.type === TYPES.blobService);
  for (const found of blobServices) {
    if (
      found.id !== service ||
      at(found.properties, 'isVersioningEnabled') !== false ||
      at(found.properties, 'deleteRetentionPolicy', 'enabled') !== false
    ) {
      problem(
        found.name,
        'must be the default blob service, with versioning and soft delete off: either would keep a file past its week',
      );
    }
  }
  const containers = parts.filter((resource) => resource.type === TYPES.container);
  for (const found of containers) {
    if (
      found.id !== `${service}/containers/${DOWNLOADS_CONTAINER}` ||
      at(found.properties, 'publicAccess') !== 'None'
    ) {
      problem(found.name, `must be ${DOWNLOADS_CONTAINER} in the downloads store, with no public access`);
    }
  }
  const lifecycles = parts.filter((resource) => resource.type === TYPES.lifecycle);
  const deletes = lifecycles.some(
    (found) =>
      found.id === `${account.id}/managementPolicies/default` &&
      list(at(found.properties, 'policy', 'rules')).some(deletesWithinTwoWeeks),
  );
  if (blobServices.length !== 1 || containers.length !== 1 || lifecycles.length !== 1 || !deletes) {
    problem(
      account.name,
      `needs one blob service, one container and one lifecycle rule deleting every file in it within ${String(DOWNLOADS_KEPT_DAYS)} days of its making (decisions 31, 32e)`,
    );
  }
  const known: readonly string[] = [TYPES.blobService, TYPES.container, TYPES.lifecycle];
  for (const resource of parts) {
    if (resource.type.toLowerCase().startsWith('microsoft.storage/') && !known.includes(resource.type)) {
      problem(resource.name, `is a ${resource.type}: the downloads store holds one container and its lifecycle rule`);
    }
  }
}

/**
 * Where the activity log's background downloads are kept (Phase 3 L5c,
 * decision 31): one account, named as modules/activity-downloads.bicep names
 * it, shut as the audit exports' store is but one copy and not write-once;
 * its parts as `downloadsPartsProblems` says, every file deleted within a
 * week and a day. Its one custom role allows reading and writing a file and
 * nothing else, assignable in the resource group alone, and is given once,
 * on the container, to the API's identity; the API alone is told where the
 * store is. Its logs are `resource-logs`'s, and the subnet's Storage endpoint
 * `evidence-store`'s.
 */
const activityDownloads: Check = (snapshot, _expected, add) => {
  const problem = (resource: string, message: string): void => {
    add({ rule: 'activity-downloads', resource, message });
  };
  const appsSubnets = appsSubnetIds(snapshot);
  const accounts = ofType(snapshot, TYPES.storage).filter((account) => DOWNLOADS_ACCOUNT.test(account.name));
  for (const account of accounts) {
    for (const what of downloadsAccountProblems(account, appsSubnets)) problem(account.name, `must have ${what}`);
    downloadsPartsProblems(snapshot, account, problem);
  }
  if (accounts.length !== 1) {
    problem(
      'the deployment',
      `needs one store for the activity downloads; the snapshot has ${String(accounts.length)}`,
    );
  }
  const keepers = storeRoleProblems(
    snapshot,
    {
      name: downloadsRoleName(groupOf(snapshot)),
      dataActions: DOWNLOADS_ACTIONS,
      containers: ofType(snapshot, TYPES.container).filter((container) => inDownloadsStore(snapshot, container)),
      workload: 'api',
      called: "the activity downloads' role",
      on: 'the downloads container',
    },
    problem,
  );
  storeSettingsProblems(
    snapshot,
    {
      prefix: DOWNLOADS_SETTING_PREFIX,
      url: 'AGENTX_ACTIVITY_DOWNLOADS_URL',
      clientId: 'AGENTX_ACTIVITY_DOWNLOADS_CLIENT_ID',
      accounts,
      container: DOWNLOADS_CONTAINER,
      holds: (workload) => workload.type === TYPES.app && jobWorkloadOf(workload.name) === 'api',
      holder: 'the API keeps the activity downloads',
      store: 'downloads store',
    },
    keepers,
    problem,
  );
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
        const bySays = saysCountColumn(criterion);
        return (
          ((column !== undefined && list(at(criterion, 'dimensions')).length === 0) || bySays !== undefined) &&
          at(criterion, 'metricMeasureColumn') === (column ?? bySays) &&
          at(criterion, 'resourceIdColumn') === undefined
        );
      }) &&
      isEmpty(at(alert.properties, 'actions', 'customProperties'));
    if (!countsOnly) {
      add({
        rule: 'alert-counts-only',
        resource: alert.name,
        message:
          'must end in one summarize with no `by` (or `count() by Says`, our own plain words alone), measured on that column, with no other dimensions or custom properties: notifications leave the UAE (ADR-013 rule 3)',
      });
    }
    const severity = at(alert.properties, 'severity');
    const runbook = /^SEV-([12])\. .+ Runbook: Incident-Response-Playbook\.md section [A-Q]\.$/.exec(
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
    [TYPES.dnsPolicy, (log) => at(log, 'category') === 'DnsResponse'],
    // Both stores, the audit exports' and the activity downloads': every read, write and delete (StorageBlobLogs).
    ...['StorageRead', 'StorageWrite', 'StorageDelete'].map(
      (category) => [TYPES.blobService, (log: unknown) => at(log, 'category') === category] as const,
    ),
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
      const notTo = elsewhere.length > 0 ? `, not to ${elsewhere.join(', ')}` : '';
      add({
        rule: 'log-destinations',
        resource: setting.name,
        message: `must send to this deployment's workspace only${notTo}: logs stay in the UAE (ADR-013)`,
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
 * Email (B5-2): Communication Services and the email service are global
 * resources that keep what they hold at rest (the sender's name, each message
 * while it is sent) in the data location they are given, which can never be
 * changed after (Microsoft), so each is given the UAE (ADR-009). A domain
 * tracks no opens or clicks, which would rewrite the links in a notice and
 * tell Azure when its recipient reads it. The service sends only from domains
 * of this deployment.
 */
const email: Check = (snapshot, _expected, add) => {
  const domains: ReadonlySet<unknown> = new Set(ofType(snapshot, TYPES.emailDomain).map((domain) => domain.id));
  for (const resource of [...ofType(snapshot, TYPES.communication), ...ofType(snapshot, TYPES.emailService)]) {
    if (at(resource.properties, 'dataLocation') !== EMAIL_DATA_LOCATION) {
      add({
        rule: 'email',
        resource: resource.name,
        message: `must keep its data in the ${EMAIL_DATA_LOCATION} (dataLocation), which can't be changed once it exists (ADR-009)`,
      });
    }
  }
  for (const domain of ofType(snapshot, TYPES.emailDomain)) {
    if (at(domain.properties, 'userEngagementTracking') !== 'Disabled') {
      add({
        rule: 'email',
        resource: domain.name,
        message: 'must track no opens or clicks (userEngagementTracking Disabled)',
      });
    }
  }
  for (const service of ofType(snapshot, TYPES.communication)) {
    if (!list(at(service.properties, 'linkedDomains')).every((linked) => domains.has(linked))) {
      add({
        rule: 'email',
        resource: service.name,
        message: "must send only from this deployment's email domains (linkedDomains)",
      });
    }
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

/**
 * An enabled alert on the workspace counts the apps' error events (logging
 * standard §5, "Error spike"), each kind by its plain words (decision 29).
 */
const appErrorsAlert: Check = (snapshot, _expected, add) => {
  for (const environment of ofType(snapshot, TYPES.environment)) {
    const alerted = workspaceAlerted(snapshot, 'any', (criterion) => {
      const threshold = at(criterion, 'threshold');
      return (
        saysCountColumn(criterion) !== undefined &&
        kqlStages(String(at(criterion, 'query')))[1] === ERROR_LINES &&
        at(criterion, 'operator') === 'GreaterThan' &&
        typeof threshold === 'number' &&
        threshold >= 0
      );
    });
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
 * The daily email (decision 29, P4; partner, S128: one email a kind): an
 * enabled alert reads the last day's warnings and errors once a day and
 * notifies each kind by its plain words, every day it saw one (stateless).
 */
const dailyWordsAlert: Check = (snapshot, _expected, add) => {
  for (const environment of ofType(snapshot, TYPES.environment)) {
    const alerted = workspaceAlerted(
      snapshot,
      'any',
      (criterion, alert) =>
        saysCountColumn(criterion) !== undefined &&
        kqlStages(String(at(criterion, 'query')))[1] === PROBLEM_LINES &&
        at(criterion, 'operator') === 'GreaterThan' &&
        at(criterion, 'threshold') === 0 &&
        totals(criterion) &&
        watchesEveryWindow(alert, criterion) &&
        at(alert.properties, 'evaluationFrequency') === 'P1D' &&
        at(alert.properties, 'autoMitigate') === false,
    );
    if (!alerted) {
      add({
        rule: 'daily-words-alert',
        resource: environment.name,
        message:
          "needs an enabled, stateless alert on this deployment's workspace that reads each day's warnings and errors and notifies each kind by its plain words",
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
  for (const environment of ofType(snapshot, TYPES.environment)) {
    const alerted = workspaceAlerted(
      snapshot,
      'stateless SEV-1',
      (criterion, alert) =>
        queryIs(at(criterion, 'query'), 'ContainerAppConsoleLogs', [INTEGRITY_LINES], 'count()') &&
        at(criterion, 'operator') === 'GreaterThan' &&
        at(criterion, 'threshold') === 0 &&
        watchesEveryWindow(alert, criterion),
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
 * An enabled alert on the workspace counts every token the login service
 * refused (partner, S88): one line is enough to fire it, in any window.
 */
const tokenRefusedAlert: Check = (snapshot, _expected, add) => {
  for (const environment of ofType(snapshot, TYPES.environment)) {
    const alerted = workspaceAlerted(
      snapshot,
      'any',
      (criterion, alert) =>
        queryIs(at(criterion, 'query'), 'ContainerAppConsoleLogs', [TOKEN_REFUSED_LINES], 'count()') &&
        totals(criterion) &&
        at(criterion, 'operator') === 'GreaterThan' &&
        at(criterion, 'threshold') === 0 &&
        watchesEveryWindow(alert, criterion),
    );
    if (!alerted) {
      add({
        rule: 'token-refused-alert',
        resource: environment.name,
        message:
          "needs an enabled alert on this deployment's workspace that fires on any LoginTokenRefused error line, watching every minute and firing on the first window",
      });
    }
  }
};

/**
 * An enabled alert on the workspace fires when one agent's denials in a window
 * pass DENIAL_SURGE_THRESHOLD (Phase 2 E2), watching every minute.
 */
const denialSurgeAlert: Check = (snapshot, _expected, add) => {
  for (const environment of ofType(snapshot, TYPES.environment)) {
    const alerted = workspaceAlerted(
      snapshot,
      'any',
      (criterion, alert) =>
        queryIs(at(criterion, 'query'), 'ContainerAppConsoleLogs', DENIAL_LINES, 'max(Denials)') &&
        totals(criterion) &&
        at(criterion, 'operator') === 'GreaterThan' &&
        at(criterion, 'threshold') === DENIAL_SURGE_THRESHOLD &&
        watchesEveryWindow(alert, criterion),
    );
    if (!alerted) {
      add({
        rule: 'denial-surge-alert',
        resource: environment.name,
        message: `needs an enabled alert on this deployment's workspace that fires when one agent has more than ${String(DENIAL_SURGE_THRESHOLD)} spend requests denied in a window, watching every minute`,
      });
    }
  }
};

/**
 * An enabled alert on the workspace fires when one agent's own cancels in a
 * window pass AGENT_CANCELS_THRESHOLD (Phase 2 G6), watching every window.
 */
const agentCancelsAlert: Check = (snapshot, _expected, add) => {
  for (const environment of ofType(snapshot, TYPES.environment)) {
    const alerted = workspaceAlerted(
      snapshot,
      'any',
      (criterion, alert) =>
        queryIs(at(criterion, 'query'), 'ContainerAppConsoleLogs', AGENT_CANCEL_LINES, 'max(Cancels)') &&
        totals(criterion) &&
        at(criterion, 'operator') === 'GreaterThan' &&
        at(criterion, 'threshold') === AGENT_CANCELS_THRESHOLD &&
        watchesEveryWindow(alert, criterion),
    );
    if (!alerted) {
      add({
        rule: 'agent-cancels-alert',
        resource: environment.name,
        message: `needs an enabled alert on this deployment's workspace that fires when one agent cancels more than ${String(AGENT_CANCELS_THRESHOLD)} of its own spend requests in a window, watching every window`,
      });
    }
  }
};

/**
 * An enabled alert on the workspace fires on any cancel an agent's day's cap
 * refused (Phase 2 G6): one line is enough, in any window.
 */
const agentCancelCapAlert: Check = (snapshot, _expected, add) => {
  for (const environment of ofType(snapshot, TYPES.environment)) {
    const alerted = workspaceAlerted(
      snapshot,
      'any',
      (criterion, alert) =>
        queryIs(at(criterion, 'query'), 'ContainerAppConsoleLogs', [AGENT_CANCEL_CAP_LINES], 'count()') &&
        totals(criterion) &&
        at(criterion, 'operator') === 'GreaterThan' &&
        at(criterion, 'threshold') === 0 &&
        watchesEveryWindow(alert, criterion),
    );
    if (!alerted) {
      add({
        rule: 'agent-cancel-cap-alert',
        resource: environment.name,
        message:
          "needs an enabled alert on this deployment's workspace that fires on any agent cancel refused by its day's cap, in any window",
      });
    }
  }
};

/**
 * An enabled alert on the workspace fires on any page of the holdings check
 * that failed (Phase 2 E1b's review): one line is enough, in any window.
 */
const holdingsCheckAlert: Check = (snapshot, _expected, add) => {
  for (const environment of ofType(snapshot, TYPES.environment)) {
    const alerted = workspaceAlerted(
      snapshot,
      'any',
      (criterion, alert) =>
        queryIs(at(criterion, 'query'), 'ContainerAppConsoleLogs', [HOLDINGS_CHECK_FAILED_LINES], 'count()') &&
        totals(criterion) &&
        at(criterion, 'operator') === 'GreaterThan' &&
        at(criterion, 'threshold') === 0 &&
        watchesEveryWindow(alert, criterion),
    );
    if (!alerted) {
      add({
        rule: 'holdings-check-alert',
        resource: environment.name,
        message:
          "needs an enabled alert on this deployment's workspace that fires on any holdings_check.failed line, watching every minute and firing on the first window",
      });
    }
  }
};

/** An enabled alert on the workspace fires on any approved request said left standing (Phase 4 gate H8). */
const handoffQueueAlert: Check = (snapshot, _expected, add) => {
  for (const environment of ofType(snapshot, TYPES.environment)) {
    const alerted = workspaceAlerted(
      snapshot,
      'any',
      (criterion, alert) =>
        queryIs(at(criterion, 'query'), 'ContainerAppConsoleLogs', [HANDOFF_QUEUE_STALE_LINES], 'count()') &&
        totals(criterion) &&
        at(criterion, 'operator') === 'GreaterThan' &&
        at(criterion, 'threshold') === 0 &&
        watchesEveryWindow(alert, criterion),
    );
    if (!alerted) {
      add({
        rule: 'handoff-queue-alert',
        resource: environment.name,
        message:
          "needs an enabled alert on this deployment's workspace that fires on any handoff.queue_stale line, watching every window and firing on the first",
      });
    }
  }
};

/** An enabled alert on the workspace fires on any decision turned away with the whole platform full (4D2e C, PL-63). */
const platformFullAlert: Check = (snapshot, _expected, add) => {
  for (const environment of ofType(snapshot, TYPES.environment)) {
    const alerted = workspaceAlerted(
      snapshot,
      'any',
      (criterion, alert) =>
        queryIs(at(criterion, 'query'), 'ContainerAppConsoleLogs', [PLATFORM_FULL_LINES], 'count()') &&
        totals(criterion) &&
        at(criterion, 'operator') === 'GreaterThan' &&
        at(criterion, 'threshold') === 0 &&
        watchesEveryWindow(alert, criterion),
    );
    if (!alerted) {
      add({
        rule: 'platform-full-alert',
        resource: environment.name,
        message:
          "needs an enabled alert on this deployment's workspace that fires on any spend_request.platform_full or db.pool_wait_ran_out line, watching every window and firing on the first",
      });
    }
  }
};

/**
 * An enabled alert on the workspace fires on any run of the integrity jobs
 * skipped whole (Phase 2 E2c; request expiry, D7), or of the activity log's
 * daily seal stopped early (L6b): one line is enough, in any window.
 */
const integrityRunsAlert: Check = (snapshot, _expected, add) => {
  for (const environment of ofType(snapshot, TYPES.environment)) {
    const alerted = workspaceAlerted(
      snapshot,
      'any',
      (criterion, alert) =>
        queryIs(at(criterion, 'query'), 'ContainerAppConsoleLogs', [INTEGRITY_RUN_FAILED_LINES], 'count()') &&
        totals(criterion) &&
        at(criterion, 'operator') === 'GreaterThan' &&
        at(criterion, 'threshold') === 0 &&
        watchesEveryWindow(alert, criterion),
    );
    if (!alerted) {
      add({
        rule: 'integrity-runs-alert',
        resource: environment.name,
        message:
          "needs an enabled alert on this deployment's workspace that fires on any run_failed line of the holdings check, the hold-history check, mandate expiry, request expiry, request voids, the waiting rejections or the activity log's daily seal, watching every minute and firing on the first window",
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
  const [migrate, ...others] = ofType(snapshot, TYPES.job).filter((job) => jobWorkloadOf(job.name) === 'migrate');
  const [environment, ...otherEnvironments] = ofType(snapshot, TYPES.environment);
  for (const server of ofType(snapshot, TYPES.server)) {
    const alerted =
      migrate !== undefined &&
      others.length === 0 &&
      environment !== undefined &&
      otherEnvironments.length === 0 &&
      workspaceAlerted(
        snapshot,
        'stateless SEV-1',
        (criterion, alert) =>
          at(alert.properties, 'evaluationFrequency') === OWNER_LOGIN_RUNS.every &&
          at(alert.properties, 'overrideQueryTimeRange') === OWNER_LOGIN_RUNS.reads &&
          at(criterion, 'query') === ownerLoginQuery(migrate.name, environment.id) &&
          at(criterion, 'operator') === 'GreaterThan' &&
          at(criterion, 'threshold') === 0 &&
          watchesEveryWindow(alert, criterion),
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

/** What is wrong with when a secret is written (once, copied every run, or only when given), or nothing. */
function whenWrittenProblem(snapshot: Snapshot, secret: PredictedResource, name: string): string | undefined {
  if (CREATED_ONCE.has(name)) {
    if (secret.condition !== undefined) {
      return 'is created once (@onlyIfNotExists()), never on a condition a later run could meet';
    }
    return undefined;
  }
  if (COPIED[name] !== undefined) {
    if (secret.condition !== undefined || !isCopiedKey(snapshot, secret, at(secret.properties, 'value'))) {
      return `is copied on every run from the ${COPIED[name]} this deployment creates (its listKeys().primaryKey), on no condition`;
    }
    return undefined;
  }
  const condition = WRITTEN_WHEN_GIVEN.exec(secret.condition ?? '')?.[1];
  const value = parameterOf(at(secret.properties, 'value'));
  if (condition === undefined || (value !== undefined && value !== condition)) {
    return 'must be written only when its value is given (if (!empty(value))), so a run that rotates another secret leaves this one';
  }
  return undefined;
}

/**
 * The vault holds exactly the secrets the apps read, each once and in a vault
 * of this deployment (ADR-002 Amendment G2c). Each is written only when its
 * value is given, on a condition naming the parameter its value comes from, so
 * a run that rotates one secret leaves the rest as they are. Zitadel's master
 * key has no such condition, since it is created once: a snapshot drops the
 * option that does that, so `templateProblems` reads it from the compiled
 * template. A copied key (`COPIED`) is written on every run, from its
 * service. A value written into the code is `no-secret-literals`'s to refuse.
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
    const written = whenWrittenProblem(snapshot, secret, name);
    if (written !== undefined) problem(written);
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
  return customRoleId(group, releaseRoleName(group));
};

/** A custom role of the resource group's, as a role assignment names it: at the subscription, without case. */
const customRoleId = (group: string, name: string): string => {
  const subscription = /^\/subscriptions\/[^/]+/.exec(group)?.[0] ?? '';
  return `${subscription}/providers/${TYPES.roleDefinition}/${name}`.toLowerCase();
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
 * deployment but CI's role's (`release-access`), the audit exports'
 * (`evidence-store`) and the activity downloads' (`activity-downloads`)
 * gives Key Vault Secrets User on
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
  const evidence = customRoleId(groupOf(snapshot), evidenceRoleName(groupOf(snapshot)));
  const downloads = customRoleId(groupOf(snapshot), downloadsRoleName(groupOf(snapshot)));
  const granted = new Set<string>();
  for (const assignment of ofType(snapshot, TYPES.roleAssignment)) {
    const role = roleOf(assignment);
    if (role === release || role === evidence || role === downloads) continue;
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
 * signed in to from outside Azure. And it defines exactly one custom role
 * besides the stores' (`evidence-store`, `activity-downloads`), named as `releaseRoleName`
 * names it, which allows RELEASE_ACTIONS and no data
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
  releaseRoleProblems(snapshot, problem);
};

/** CI's custom role, half of `release-identity`: exactly one, named so, given in the resource group alone, allowing RELEASE_ACTIONS and no data action. */
function releaseRoleProblems(snapshot: Snapshot, problem: (resource: string, message: string) => void): void {
  const groups = ofType(snapshot, TYPES.group).map((group) => group.id);
  // The stores' roles are `evidence-store`'s and `activity-downloads`'s, which hold each to its data actions.
  const stores = new Set([evidenceRoleName(groupOf(snapshot)), downloadsRoleName(groupOf(snapshot))]);
  const roles = ofType(snapshot, TYPES.roleDefinition).filter((role) => !stores.has(role.name));
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
}

/** The work a job or an app does, from its name (`job-agentx-stg-migrate`, `ca-agentx-stg-api`). */
const jobWorkloadOf = (name: string): string => name.replace(/^(?:job|ca)-agentx-[a-z]+-/, '');

/** The settings a container is given, by name. */
const settingsIn = (container: unknown): ReadonlyMap<string, unknown> =>
  new Map(list(at(container, 'env')).map((entry) => [text(at(entry, 'name')), at(entry, 'value')] as const));

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

/** How a job's configuration says it runs: started by hand, one replica per run, no retry, and a time limit. */
function runProblems(configuration: unknown, problem: (message: string) => void): void {
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
}

/** What a job or an app runs, by the same rules for both: one container, no init container, an image named by digest. */
function containerProblems(workload: PredictedResource, problem: (message: string) => void): void {
  const containers = containersOf(workload);
  if (containers.length !== 1) {
    problem(`must run exactly one container; the snapshot has ${String(containers.length)}`);
  }
  if (list(at(workload.properties, 'template', 'initContainers')).length > 0) {
    problem('must run no init container: the work is the one container, in view of the log');
  }
  for (const container of containers) {
    const image = text(at(container, 'image'));
    if (!PINNED_IMAGE.test(image)) {
      problem(`must name its image by digest (SEC-SC-02); it runs ${image}`);
    }
  }
}

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
    runProblems(configuration, problem);
    containerProblems(job, problem);
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

/** An app's scale: at most one replica when `only` says why, at least one it may run, and no more kept than that. */
function scaleProblems(scale: unknown, only: string | undefined, problem: (message: string) => void): void {
  const most = at(scale, 'maxReplicas');
  const fewest = at(scale, 'minReplicas');
  if (only !== undefined && most !== 1) {
    problem(`must run at most one replica (maxReplicas 1): ${only}; it says ${String(most)}`);
  }
  if (typeof most !== 'number' || most < 1) {
    problem(`must be able to run a replica (maxReplicas at least 1); it says ${String(most)}`);
  }
  if (typeof fewest !== 'number' || fewest < 0 || (typeof most === 'number' && fewest > most)) {
    problem(`must keep no more replicas than it may run (minReplicas ${String(fewest)}, maxReplicas ${String(most)})`);
  }
}

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
    scaleProblems(at(app.properties, 'template', 'scale'), ONE_REPLICA[workload], problem);
    containerProblems(app, problem);
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

/** The load test's jobs in the deployment (D2c). */
const loadJobsIn = (snapshot: Snapshot): readonly PredictedResource[] =>
  ofType(snapshot, TYPES.job).filter((job) => isLoadJob(jobWorkloadOf(job.name)));

/** The API on its own, out of a load run: none of the load run's limits, size or, on staging, connections. */
function apiOutOfLoadRunProblems(container: unknown, staging: boolean, problem: (message: string) => void): void {
  const settings = settingsIn(container);
  for (const name of Object.keys(LOAD_RUN.apiSettings).filter((setting) => settings.has(setting))) {
    problem(`sets ${name}, which only the load run's API does (D2c): out of it the API keeps its own limits`);
  }
  if (at(container, 'resources', 'cpu') === LOAD_RUN.apiSize.cpu) {
    problem("runs at the load run's size out of a load run (D2c): apps --load-run alone sets it");
  }
  if (staging && Number(settings.get('AGENTX_DB_POOL_MAX')) > LOAD_RUN.stagingPool) {
    problem(
      `keeps over ${String(LOAD_RUN.stagingPool)} connections on staging out of a load run (PL-63): its small server has 35 for everyone`,
    );
  }
}

/** The API in a load run: exactly its size, connections and limits, and no email. */
function apiInLoadRunProblems(container: unknown, problem: (message: string) => void): void {
  const settings = settingsIn(container);
  if (
    at(container, 'resources', 'cpu') !== LOAD_RUN.apiSize.cpu ||
    at(container, 'resources', 'memory') !== LOAD_RUN.apiSize.memory
  ) {
    problem(
      `must run at ${String(LOAD_RUN.apiSize.cpu)} CPUs and ${LOAD_RUN.apiSize.memory} in the load run (D2c), the size it is measured at`,
    );
  }
  if (settings.get('AGENTX_DB_POOL_MAX') !== LOAD_RUN.apiPool) {
    problem(`must keep ${LOAD_RUN.apiPool} connections in the load run (PL-63), the size it is measured at`);
  }
  for (const [name, wanted] of Object.entries(LOAD_RUN.apiSettings).filter(
    ([setting, value]) => settings.get(setting) !== value,
  )) {
    problem(`must set ${name} to ${wanted} in the load run (D2c), so k6 meets the API rather than its limits`);
  }
  for (const name of [...settings.keys()].filter((setting) => setting.startsWith('AGENTX_EMAIL_'))) {
    problem(`sets ${name} in the load run (D2c): its seeded admins have no address, so it sends no email`);
  }
}

/** The API's containers, in a load run or out of one. */
function apiLoadProblems(
  api: PredictedResource,
  { loadRun, staging }: { readonly loadRun: boolean; readonly staging: boolean },
  problem: (message: string) => void,
): void {
  for (const container of containersOf(api)) {
    if (loadRun) apiInLoadRunProblems(container, problem);
    else apiOutOfLoadRunProblems(container, staging, problem);
  }
}

/**
 * The load test's run (D2c, PL-38), as `LOAD_RUN` says: on staging alone,
 * its three jobs together or none, each on the load image, and the API at the
 * load run's size and limits exactly while they are there, never otherwise.
 * Who the jobs run as and what they are given is `workload-secrets`'s, with
 * their commands and request (`HELD`).
 */
const loadTest: Check = (snapshot, expected, add) => {
  const found = loadJobsIn(snapshot);
  const problem = (resource: string, message: string): void => {
    add({ rule: 'load-run', resource, message });
  };
  if (found.length > 0 && expected.environment !== 'staging') {
    problem('the deployment', `runs the load test's jobs on ${expected.environment}: the load run is staging's alone`);
  }
  for (const workload of LOAD_RUN.jobs) {
    const count = found.filter((job) => jobWorkloadOf(job.name) === workload).length;
    if (found.length > 0 && count !== 1) {
      problem('the deployment', `needs the ${workload} job once in a load run; the snapshot has ${String(count)}`);
    }
  }
  for (const job of found) {
    for (const container of containersOf(job)) {
      if (!text(at(container, 'image')).startsWith(LOAD_RUN.image)) {
        problem(job.name, `must run the load image (${LOAD_RUN.image}…), which carries k6 and the load test alone`);
      }
    }
  }
  const staging = expected.environment === 'staging';
  for (const api of ofType(snapshot, TYPES.app).filter((app) => jobWorkloadOf(app.name) === LOAD_RUN.runsAs)) {
    apiLoadProblems(api, { loadRun: found.length > 0, staging }, (message) => {
      problem(api.name, message);
    });
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

/** A door's hosts: exactly one, with a certificate binding that is never plain http alone. */
function hostProblems(door: PredictedResource, problem: (message: string) => void): void {
  const hosts = list(at(door.properties, 'customDomains'));
  if (hosts.length !== 1) problem(`must serve exactly one host; it names ${String(hosts.length)}`);
  for (const host of hosts) {
    if (!SECURE_BINDINGS.has(at(host, 'bindingType'))) {
      problem(`must bind a certificate to ${text(at(host, 'name'))} (Auto or SniEnabled), never plain http alone`);
    }
  }
}

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
    hostProblems(door, problem);
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
  const loadRun = loadJobsIn(snapshot).length > 0;
  for (const job of workloadsIn(snapshot)) {
    const workload = jobWorkloadOf(job.name);
    const problem = (message: string): void => {
      add({ rule: 'workload-secrets', resource: job.name, message });
    };
    const assigned = identityProblems(job, isLoadJob(workload) ? LOAD_RUN.runsAs : workload, problem);
    const all = list(at(job.properties, 'configuration', 'secrets'));
    const held = HELD[workload];
    const holding = all.filter((secret) => text(at(secret, 'name')) === held?.name);
    if (held !== undefined) heldProblems(job, held, holding, problem);
    const declared = all.filter((secret) => !holding.includes(secret));
    const given = all.map((secret) => text(at(secret, 'name')));
    const needed = secretsNeeded(workload, loadRun);
    for (const name of declared.map((secret) => text(at(secret, 'name'))).filter((secret) => !needed.has(secret))) {
      problem(`is given ${name}, which GRANTS doesn't let ${workload} read`);
    }
    for (const name of [...needed].filter((secret) => !given.includes(secret))) {
      problem(`must be given ${name}, which ${workload} reads (GRANTS)`);
    }
    for (const secret of declared) declaredSecretProblems(secret, vaults, assigned, problem);
    secretUseProblems(job, given, problem);
  }
};

/** What a workload is given (GRANTS), but a load job's (`LOAD_RUN.reads`) and the API's in a load run. */
function secretsNeeded(workload: string, loadRun: boolean): ReadonlySet<string> {
  if (isLoadJob(workload)) return LOAD_RUN.reads;
  const read = secretsRead(workload);
  if (!loadRun || workload !== LOAD_RUN.runsAs) return read;
  return new Set([...read].filter((secret) => !LOAD_RUN.apiLeavesOut.has(secret)));
}

/** The identity a job or an app runs as: user-assigned, and its own alone. Gives back the ids it is assigned. */
function identityProblems(
  job: PredictedResource,
  workload: string,
  problem: (message: string) => void,
): readonly string[] {
  const assigned = Object.keys(at(job.identity, 'userAssignedIdentities') ?? {});
  if (at(job.identity, 'type') !== 'UserAssigned') {
    problem('must run as a user-assigned identity, never a system-assigned one tied to the resource');
  }
  const only = assigned[0] ?? '';
  if (assigned.length !== 1 || workloadOf(only.slice(only.lastIndexOf('/') + 1)) !== workload) {
    problem(`must run as its own identity alone, the one named for ${workload}`);
  }
  return assigned;
}

/** What a job holds as `HELD` says: once, as given there, and its command and arguments exactly HELD's. */
function heldProblems(
  job: PredictedResource,
  held: (typeof HELD)[string],
  holding: readonly unknown[],
  problem: (message: string) => void,
): void {
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
  const run = JSON.stringify([...held.command, '|', ...held.args]);
  for (const container of containersOf(job)) {
    if (JSON.stringify([...list(at(container, 'command')), '|', ...list(at(container, 'args'))]) !== run) {
      problem(
        `must run ${held.command.join(' ')} ${held.args.join(' ')} and nothing else: a request in its command or arguments would sit in the deployment and every run's record`,
      );
    }
  }
}

/** One secret a job or an app declares: no value of its own, read from this deployment's vault by name, through its own identity. */
function declaredSecretProblems(
  secret: unknown,
  vaults: ReadonlySet<string>,
  assigned: readonly string[],
  problem: (message: string) => void,
): void {
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

/**
 * How a job or an app reads what it is given: every secret volume names what
 * is in it, every secret given is read and none read that isn't, and none
 * reaches the environment but where `SECRETS_IN_ENVIRONMENT` allows it.
 */
function secretUseProblems(job: PredictedResource, given: readonly string[], problem: (message: string) => void): void {
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
      const settings = settingsIn(container);
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

/** How the variables Azure sets itself in every container start: the job's run, the app's revision, the port… */
const PLATFORM_PREFIX = 'CONTAINER_APP_';

/**
 * Where a container gets its identity's token (Microsoft): one set here could
 * send the operator's or the API's token request, and the export or the
 * download, somewhere else (E10c, L5c).
 */
const IDENTITY_SETTING = /^(?:IDENTITY_ENDPOINT|IDENTITY_HEADER|MSI_)/;

/**
 * No container, job or app, sets one of Azure's own variables: one the
 * deployment set could stand in for the platform's, and the operator's
 * platform event records the run's name as Azure gives it (B1c-2b), and gets
 * its token where Azure says (E10c). Names
 * are matched as written, since Linux tells capitals apart: a name that
 * differs only in them is a variable of its own.
 */
const platformSettings: Check = (snapshot, _expected, add) => {
  for (const job of workloadsIn(snapshot)) {
    for (const container of containersOf(job)) {
      for (const name of list(at(container, 'env')).map((entry) => text(at(entry, 'name')))) {
        if (!name.startsWith(PLATFORM_PREFIX) && !IDENTITY_SETTING.test(name)) continue;
        add({
          rule: 'platform-settings',
          resource: job.name,
          message: `sets ${name}: Azure sets its ${PLATFORM_PREFIX} and identity variables in every container itself, and one set here could stand in for the platform's`,
        });
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
  databaseSize,
  databaseZoneAndMeasures,
  databaseNetwork,
  appsNetwork,
  appsEgress,
  dnsWatch,
  dnsAllow,
  vault,
  evidenceStore,
  activityDownloads,
  workspaceAndQuota,
  alertRules,
  resourceLogs,
  logDestinations,
  activityLog,
  budget,
  email,
  appsEnvironment,
  appsLogs,
  appErrorsAlert,
  dailyWordsAlert,
  auditIntegrityAlert,
  tokenRefusedAlert,
  denialSurgeAlert,
  holdingsCheckAlert,
  handoffQueueAlert,
  platformFullAlert,
  integrityRunsAlert,
  agentCancelsAlert,
  agentCancelCapAlert,
  ownerLoginAlert,
  identities,
  releaseIdentity,
  releaseAccess,
  vaultSecrets,
  secretAccess,
  jobs,
  apps,
  loadTest,
  publicDoors,
  doorCertificates,
  workloadSecrets,
  containerTelemetry,
  platformSettings,
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
