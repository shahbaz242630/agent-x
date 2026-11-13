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

import { OLD_EDIT_DAYS } from '../../packages/platform/src/audit-chain/limits.ts';
import { LOGIN_SERVICE_ALERT_EVENTS } from '../../packages/platform/src/observability/login-service-alert.ts';
import { APP_KEYS, operatorOnly, PUBLIC_HALVES } from './app-keys.ts';
import { readRanges } from './github-ranges.ts';
import type { PredictedResource, Snapshot } from './snapshot.ts';
import { STAGE_G_JOB_SECONDS } from '../../tooling/load/stageg.ts';
import {
  POSTGRES_HOST_SUFFIX,
  THROWAWAY_NAME_RULE,
  throwawayAnchorsContainer,
  throwawayIdOf,
  throwawayServerOfHost,
} from '../../tooling/load/throwaway.ts';

export type RuleId =
  | 'snapshot-complete'
  | 'required'
  | 'in-country'
  | 'stable-api'
  | 'tags'
  | 'no-secret-literals'
  | 'database-private'
  | 'database-network'
  | 'database-egress'
  | 'database-logins'
  | 'owner-login-alert'
  | 'refused-login-alert'
  | 'login-lines-alert'
  | 'database-tls'
  | 'database-backup'
  | 'database-size'
  | 'database-disk'
  | 'database-zone'
  | 'database-measures'
  | 'database-stall-evidence'
  | 'load-run'
  | 'load-database'
  | 'connections'
  | 'vault'
  | 'evidence-store'
  | 'anchor-epoch'
  | 'activity-downloads'
  | 'workspace'
  | 'login-workspace'
  | 'workbook'
  | 'log-quota-alerts'
  | 'alert-counts-only'
  | 'alert-window'
  | 'alert-runbook'
  | 'alert-delivery'
  | 'alert-rules-watch'
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
  | 'dns-block-alert'
  | 'apps-logs'
  | 'app-errors-alert'
  | 'daily-words-alert'
  | 'audit-integrity-alert'
  | 'token-refused-alert'
  | 'denial-surge-alert'
  | 'holdings-check-alert'
  | 'handoff-queue-alert'
  | 'login-service-alert'
  | 'platform-full-alert'
  | 'anchor-store-alert'
  | 'daily-check-alert'
  | 'full-pass-alert'
  | 'integrity-runs-alert'
  | 'records-filling-alert'
  | 'dead-man-alerts'
  | 'agent-cancels-alert'
  | 'agent-cancel-cap-alert'
  | 'decisions-suppressed-alert'
  | 'identities'
  | 'release-identity'
  | 'release-access'
  | 'job-watch'
  | 'role-actions'
  | 'release-writes-alert'
  | 'azure-policy'
  | 'vault-secrets'
  | 'secret-access'
  | 'jobs'
  | 'apps'
  | 'public-doors'
  | 'door-certificates'
  | 'workload-secrets'
  | 'container-telemetry'
  | 'zitadel-machine-ids'
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
  metricAlert: 'Microsoft.Insights/metricAlerts',
  activityAlert: 'Microsoft.Insights/activityLogAlerts',
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
  lock: 'Microsoft.Authorization/locks',
  policyDefinition: 'Microsoft.Authorization/policyDefinitions',
  policyAssignment: 'Microsoft.Authorization/policyAssignments',
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
  workbook: 'Microsoft.Insights/workbooks',
} as const;

/**
 * Types Azure offers only as global resources (activity log alerts also in two European regions, never the UAE). The
 * first five hold no
 * customer data or logs; email's three keep what they hold at rest in the data
 * location they are given, which rule `email` holds to the UAE.
 */
const GLOBAL_TYPES: ReadonlySet<string> = new Set([
  TYPES.actionGroup,
  TYPES.metricAlert,
  TYPES.activityAlert,
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

/**
 * What a stall like the soak's 5 s commit pause leaves behind (MO5), every
 * size alike: each checkpoint and each lock waited on for longer than a
 * second in the server's log, and the server's own wait and transaction
 * counts as Azure metrics, which go to no workspace.
 */
const STALL_EVIDENCE: ReadonlyMap<string, string> = new Map([
  ['log_checkpoints', 'on'],
  ['log_lock_waits', 'on'],
  ['deadlock_timeout', '1000'],
  ['metrics.collector_database_activity', 'on'],
]);

/** How every Postgres log line starts: its time, then its session (Azure's default, held by postgres.bicep). */
const LOG_LINE_PREFIX = '%t-%c-';

/**
 * The start of a line that prefix writes, up to its level, as the login alerts
 * match it: `2026-09-16 19:02:12 UTC-6aaae7b4.1dc3-` then `LOG:  ` for a login
 * (S19), `FATAL:  ` for one refused. Azure holds the log's time zone at UTC.
 */
const LINE_START = '^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} UTC-[0-9a-f]+[.][0-9a-f]+-';
const LOG_LINE_START = `${LINE_START}LOG:  `;

/** The role that owns the app's tables and runs the migrations (db/bootstrap/roles.sql). */
const OWNER_ROLE = 'agentx_owner';

/**
 * The owner-login alert's query (ADR-012 §2, Phase 1 A3e-2) for the migration
 * job and the environment it runs in, written again here so that changing it
 * takes both: each owner login paired with the nearest start of that job, and
 * counted unless the start is within two minutes and nothing else is paired
 * with it; a start with no login counted too; each judged once 20 minutes old,
 * since Azure's lines for the job reach the workspace minutes after Postgres's,
 * or once it arrives if later (MO2), over the last 30 minutes of those moments.
 * postgres.bicep says why each number.
 */
const JUDGED = 'Judged = max_of(ingestion_time(), TimeGenerated + 20m)';

const ownerLoginQuery = (migrateJob: string, environmentId: string): string =>
  [
    'let near = 2m;',
    'let starts = ContainerAppSystemLogs',
    `    | where _ResourceId =~ "${environmentId}" and JobName == "${migrateJob}" and Reason == "ContainerStarted" and isnotempty(ReplicaName)`,
    `    | project Start = TimeGenerated, Run = ReplicaName, ${JUDGED};`,
    'let logins = PGSQLServerLogs',
    `    | where Message matches regex @"${LOG_LINE_START}connection authorized: user=${OWNER_ROLE} "`,
    `    | project Login = TimeGenerated, Message, ${JUDGED};`,
    'let paired = logins',
    '    | extend Key = 1',
    '    | join kind=leftouter (starts | project-away Judged | extend Key = 1) on Key',
    '    | extend Gap = coalesce(abs(Login - Start), 1d)',
    '    | summarize arg_min(Gap, Run) by Login, Message, Judged;',
    'let claims = paired',
    '    | where Gap <= near',
    '    | summarize Claims = count() by Run;',
    'let strays = paired',
    '    | where Judged between (ago(30m) .. now())',
    '    | join kind=leftouter claims on Run',
    '    | where Gap > near or Claims > 1',
    '    | project Run;',
    'let unclaimed = starts',
    '    | where Judged between (ago(30m) .. now())',
    '    | join kind=leftanti claims on Run',
    '    | project Run;',
    'union strays, unclaimed',
    '| summarize Unpaired = count()',
  ].join('\n');

/**
 * What a login alert reads before it judges: Azure's most, two days, so a line
 * that reaches the workspace late is in view when it arrives, with whatever it
 * is paired with (MO2: a line over about 35 minutes late was never judged).
 */
const LATE_LINES_READ = 'P2D';

/**
 * When the owner-login alert runs, and what each run reads: its band is 30
 * minutes, so two runs 15 minutes apart judge every login and start.
 */
const OWNER_LOGIN_RUNS = { every: 'PT15M', reads: LATE_LINES_READ } as const;

/**
 * The login alerts that count lines rather than pair them take those that
 * arrived over the last 30 minutes, run every 15: a run late by up to 15
 * leaves no gap, a line may notify twice, and a line arriving late is counted
 * when it arrives (MO2).
 */
const ARRIVED_LATELY = 'where ingestion_time() > ago(30m)';

/**
 * The refused-login alert's query (MO2) for the server's admin: one FATAL line
 * for each login refused as a privileged role, a wrong password or a connection
 * the server's rules refuse, counted by when it arrived (ARRIVED_LATELY), so a
 * late line is still seen. Quotes are RE2's
 * `\x22`: Kusto's verbatim strings can't hold one.
 */
const refusedLoginQuery = (admin: string): string => {
  const quote = String.raw`\x22`;
  const host = `host ${quote}[^${quote}]*${quote}, user`;
  const refused = `(password authentication failed for user|no pg_hba[.]conf entry for ${host}|pg_hba[.]conf rejects connection for ${host})`;
  const roles = `${quote}(${admin}|${BACKUP_ROLE}|${OWNER_ROLE})${quote}`;
  return `PGSQLServerLogs | ${ARRIVED_LATELY} | where Message matches regex @"${LINE_START}FATAL:  ${refused} ${roles}" | summarize Refused = count()`;
};

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
/**
 * Our logger's containers: the API, its jobs where they run apart from it (4D2e D13), and the four jobs built on it
 * (the chain repair's since 4D2e E10).
 */
const OWN_CONTAINER =
  /^"(?:ca-agentx-(?:stg|prd)-(?:api|jobs)|job-agentx-(?:stg|prd)-(?:db-setup|migrate|operator|chain-restore))"$/;
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

/**
 * The anchors' store can't be read after a start, has gone long unread or unwritten, or was never named (4D2e E, PL-58);
 * a file too large for this process, the check behind on its turns, or past the organisations it notes (E6): capacity, never tamper.
 */
const ANCHOR_STORE_LINES =
  'where tostring(parse_json(Log).event) in ("audit.anchor_store_unreadable", "audit.anchor_store_unwritable", "audit.anchor_store_read_failing", "audit.anchor_store_not_set", "audit.anchor_store_beyond_memory", "audit.anchor_store_near_memory", "audit.anchor_check_behind", "audit.anchor_check_over_size", "audit.anchor_store_moved_on")';

/**
 * The fewest days of point-in-time restore a deployment keeps (ADR-002). In production, also twice the days the full pass
 * may take to find an old audit event edited (4D2e E7, decision 3), so the clean rows are still there to restore when it is.
 * Staging's few days are no recovery path.
 */
export const leastRestoreDays = (
  environment: Expectations['environment'],
  oldEditDays: number = OLD_EDIT_DAYS,
): number => (environment === 'production' ? Math.max(35, 2 * oldEditDays) : 7);

/** The anchor check's daily count and walk of older events late (4D2e E7, decisions 1 and 2b). */
const DAILY_CHECK_LATE = 'audit.daily_check_overdue';

/** The full pass of every chain late (4D2e E7, decision 3). */
const FULL_PASS_LATE = 'audit.full_pass_overdue';

/** An agent's decision turned away with the whole platform full (4D2e C, PL-63): calm organisations are being slowed. */
const PLATFORM_FULL_LINES =
  'where tostring(parse_json(Log).event) in ("spend_request.platform_full", "db.pool_wait_ran_out")';

/** Approved requests left standing past 15 minutes for no known reason (Phase 4 gate H8): suppliers unpaid, money held. */
const HANDOFF_QUEUE_STALE_LINES = 'where tostring(parse_json(Log).event) == "handoff.queue_stale"';

/** A change made in the login service behind Agent X, or a moment of its events the copier passed (SA2). */
const LOGIN_SERVICE_LINES = `where tostring(parse_json(Log).event) in (${LOGIN_SERVICE_ALERT_EVENTS.map((event) => JSON.stringify(event)).join(', ')})`;

/** Decision lines past their budget, counted in one line (4D2e F8, PL-52): the denial-surge alert undercounts that minute. */
const DECISIONS_SUPPRESSED_LINES = [
  'where tostring(parse_json(Log).event) == "log.suppressed"',
  'where tostring(parse_json(Log).suppressedEvent) == "spend_request.decided"',
] as const;

/**
 * An integrity job that skipped a whole run, its organisation list unread
 * (Phase 2 E2c), or a run of the activity log's daily seal (Phase 3 L6b) or
 * its seal check (L6c) that stopped early: nothing checked, expired or sealed that run.
 */
const INTEGRITY_RUN_FAILED_LINES =
  'where tostring(parse_json(Log).event) in ("access_log_seal.run_failed", "access_log_seal_check.run_failed", "hold_history.run_failed", "holdings_check.run_failed", "mandate_expiry.run_failed", "request_expiry.run_failed", "request_void.run_failed", "waiting_rejection.run_failed")';

/**
 * An organisation's records past what a list reads well, or a hold clearing reading thousands of one kind
 * (`identity.records_filling`, partner S170): nothing breaks yet, but a list past its limit stops working.
 */
const RECORDS_FILLING_LINES = 'where tostring(parse_json(Log).event) == "identity.records_filling"';

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

/**
 * The login alerts' own workspace (4D2e Stage F, PR 9), by its name: the main one's cap reached stops its collecting,
 * so the alerts on Postgres's logins read a small workspace of their own, holding only what they need, its cap 1 GB.
 */
const LOGIN_WORKSPACE = /^log-agentx-(?:stg|prd)-logins$/;
const LOGIN_WORKSPACE_CAP_GB = 1;
/** What the login workspace holds: Postgres's server log and the platform's lines, for the owner-login pairing. */
const LOGIN_LOG_CATEGORIES: readonly unknown[] = ['PostgreSQLLogs', 'ContainerAppSystemLogs'];

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
 * keys (ADR-011 §2), from the one list of them (app-keys.json), but the
 * operator's own, whose public half it reads instead (PL-57); the operator's
 * command, its own login and every version of the audit chains' MAC, of the
 * field encryption and of its own signing key alone (ADR-011 §3, B1c, B4-6b).
 * The API's jobs, where they run apart from it (`jobs`, 4D2e D13), read what
 * the API reads: the same process at another role, its sign-in's three
 * settings and email's four taken together, whose jobs send the notices and
 * carry out the factor resets.
 */
const GRANTS: ReadonlySet<string> = new Set([
  ...APP_KEYS.filter((key) => !operatorOnly(key)).flatMap((key) => [`api reads ${key}`, `jobs reads ${key}`]),
  ...[...PUBLIC_HALVES.values()].flatMap((half) => [`api reads ${half}`, `jobs reads ${half}`]),
  'jobs reads db-app-password',
  'jobs reads api-oidc-client-secret',
  'jobs reads acs-access-key',
  'jobs reads zitadel-directory-token',
  'jobs reads zitadel-reset-token',
  'jobs reads zitadel-our-actors',
  'jobs reads zitadel-our-service-users',
  ...APP_KEYS.filter(
    (key) => key.startsWith('key-audit-mac-v') || key.startsWith('key-field-encryption-v') || operatorOnly(key),
  ).map((key) => `operator reads ${key}`),
  'api reads db-app-password',
  // B2-6: the API's own secret as the login service's client, which Zitadel gave.
  'api reads api-oidc-client-secret',
  // B5-3: the email service's key, copied from it, and the login service's read-only token for addresses.
  'api reads acs-access-key',
  'api reads zitadel-directory-token',
  // B6-3c: the login service's token for removing second factors once a reset has cooled off.
  'api reads zitadel-reset-token',
  // SA2b: who makes our own routine changes in the login service, and for whom, kept in the vault alone.
  'api reads zitadel-our-actors',
  'api reads zitadel-our-service-users',
  'operator reads db-operator-password',
  'db-setup reads db-admin-password',
  'db-setup reads db-owner-password',
  'db-setup reads db-app-password',
  'db-setup reads db-backup-password',
  'db-setup reads db-operator-password',
  'db-setup reads db-zitadel-password',
  'migrate reads db-owner-password',
  // AZ3: Stage G's mark (as the owner) and checks (as the app and the backup role), on its throwaway copy alone.
  'stage-g reads db-owner-password',
  'stage-g reads db-app-password',
  'stage-g reads db-backup-password',
  // 4D2e E10 (PL-29): the chain repair writes as the owner, the one job besides the migration; it checks the chain
  // with the MAC key and the operator's signatures with their public halves, and holds no other key.
  'chain-restore reads db-owner-password',
  ...APP_KEYS.filter((key) => key.startsWith('key-audit-mac-v')).map((key) => `chain-restore reads ${key}`),
  ...[...PUBLIC_HALVES.values()].map((half) => `chain-restore reads ${half}`),
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
const JOB_WORKLOADS: readonly string[] = [
  'db-setup',
  'migrate',
  'zitadel-init',
  'zitadel-setup',
  'operator',
  'chain-restore',
];

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
  // The chain repair's request (4D2e E10; apps.bicep `restoreRequest`), held as the operator's is.
  'chain-restore': {
    name: 'chain-restore-request',
    value: '[]',
    command: ['node', 'apps/operator/src/chain-restore-main.ts'],
    args: ['--request', '/mnt/secrets/chain-restore-request'],
  },
  // The load test's run request (D2c; apps.bicep `loadRequest`), written by load.ts before each run.
  ...Object.fromEntries(
    LOAD_PARTS.map((part) => [
      `load-${part}`,
      { name: 'load-request', value: '{}', command: ['node', 'tooling/load/job.ts'], args: [part] },
    ]),
  ),
  // Stage G's step and check (4D2e; apps.bicep `stageGJobs`), held as PL-38's: the mark asks nothing.
  ...Object.fromEntries(
    ['step', 'check'].map((part) => [
      `load-${part}`,
      { name: 'load-request', value: '{}', command: ['node', 'tooling/load/stageg-job.ts'], args: [part] },
    ]),
  ),
};

/** The load size's max_connections (postgres.bicep, `measured`); `apps --load-run` reads the live server's against it (deploy.ts). */
export const LOAD_SERVER_CONNECTIONS = 120;

/**
 * The room the decisions keep (S177, partner): at the target, about 170 requests a second at about 0.1 s each
 * (Stage G's decision p50, S179), the copies' gates run at 60% or less, so a slow spell of the database queues
 * nothing (day 2: at 85% a 10% slowdown queued waits of seconds). Changing copies, gate or pool is checked against it.
 */
export const DECISION_HEADROOM = { perSecond: 170, decisionMs: 100, mostBusy: 0.6 } as const;

/** How full the load run's gates run at the target: the decisions in flight over the slots the copies hold. */
export const gateBusy = (copies: number, gate: number): number =>
  (DECISION_HEADROOM.perSecond * DECISION_HEADROOM.decisionMs) / 1000 / (copies * gate);

/**
 * The load test's run (D2c, PL-38; apps.bicep `loadRun`): staging's alone,
 * and all of it or none. Its three jobs run the load image, as the API's
 * identity (none of their own, so no foundation or secrets deploy), and are
 * given the app's login and keys alone of what the API reads. The API, while
 * they are there and only then, runs at the size it is measured at, with its
 * limits out of k6's way and without the email service's key and the
 * directory token, so it sends no email (the four email settings are all or
 * none). It runs split (4D2e D13): three `web` copies of eight connections
 * beside one `jobs` app of six, which goes without them too.
 */
export const LOAD_RUN = {
  jobs: LOAD_PARTS.map((part) => `load-${part}`),
  runsAs: 'api',
  image: 'ghcr.io/shahbaz242630/agent-x-load@',
  reads: new Set(['db-app-password', ...APP_KEYS.filter((key) => !operatorOnly(key)), ...PUBLIC_HALVES.values()]),
  apiLeavesOut: new Set(['acs-access-key', 'zitadel-directory-token']),
  apiSize: { cpu: 2, memory: '4Gi' },
  // Three `web` copies of twelve connections, and the jobs' six, on the larger server `foundation --load-size` gives,
  // whose limit postgres.bicep states (4D2e D13; twelve as Stage G passed, S179). Staging's small server has 35 for
  // everyone, so out of a load run its one API keeps to ten (PL-63).
  apiPool: '12',
  webCopies: '3',
  jobsPool: '6',
  jobsSize: { cpu: 1, memory: '2Gi' },
  stagingPool: 10,
  // The larger server's max_connections (postgres.bicep, `measured`). The apps' snapshot can't show it: the foundation
  // sizes the server, and a plain foundation's numbers are what an apps run's snapshot holds.
  serverConnections: LOAD_SERVER_CONNECTIONS,
  apiSettings: {
    AGENTX_RATE_LIMIT_PER_MINUTE: '50000',
    AGENTX_RATE_LIMIT_PER_USER_PER_MINUTE: '50000',
    AGENTX_RATE_LIMIT_PER_AGENT_PER_MINUTE: '50000',
    AGENTX_RATE_LIMIT_PER_ORGANISATION_PER_MINUTE: '50000',
    AGENTX_LOG_EVENT_CAP_PER_MINUTE: '200000',
    // The fair gate as Stage G passed it on Azure (S179): each copy its own, eleven at once (DECISION_HEADROOM).
    AGENTX_DECISION_GATE_ACTIVE: '11',
    AGENTX_DECISION_GATE_PER_ORGANISATION: '2',
    AGENTX_DECISION_GATE_WAITING_PER_ORGANISATION: '34',
    AGENTX_DECISION_GATE_WAIT_MS: '10000',
  } as Readonly<Record<string, string>>,
  // The jobs log for the same run, so they take the API's cap.
  jobsSettings: { AGENTX_LOG_EVENT_CAP_PER_MINUTE: '200000' } as Readonly<Record<string, string>>,
};

/**
 * Stage G's jobs (4D2e; apps.bicep `stageGJobs`, tooling/load/stageg-job.ts), only on its throwaway copy: who each
 * runs as and what it reads. The mark and the checks as Stage G's own identity (AZ3), which reads the owner's, the
 * app's and the backup role's logins alone, never the server admin's; the step as PL-38's jobs. Each reads a part of
 * its identity's own (a test holds it to GRANTS).
 */
const STAGE_G_JOBS: Readonly<Record<string, { readonly runsAs: string; readonly reads: ReadonlySet<string> }>> = {
  'load-mark': { runsAs: 'stage-g', reads: new Set(['db-owner-password']) },
  'load-step': { runsAs: LOAD_RUN.runsAs, reads: LOAD_RUN.reads },
  'load-check': { runsAs: 'stage-g', reads: new Set(['db-app-password', 'db-backup-password']) },
};

const isStageGJob = (workload: string): boolean => Object.hasOwn(STAGE_G_JOBS, workload);

/** A load job: PL-38's three, or Stage G's. */
const isLoadJob = (workload: string): boolean => LOAD_RUN.jobs.includes(workload) || isStageGJob(workload);

/** The identity a load job runs as (Stage G's its own, PL-38's the API's), and any other workload its own. */
const runsAsOf = (workload: string): string =>
  STAGE_G_JOBS[workload]?.runsAs ?? (isLoadJob(workload) ? LOAD_RUN.runsAs : workload);

/**
 * Stage G's throwaway copy the API reaches (4D2e; apps.bicep `throwaway`), or undefined: read from the `api` app's own
 * AGENTX_DB_HOST, which load-database holds every app and load job to.
 */
function stageGCopyIn(snapshot: Snapshot): string | undefined {
  const api = ofType(snapshot, TYPES.app).find((app) => jobWorkloadOf(app.name) === 'api');
  const host = api === undefined ? undefined : settingsIn(containersOf(api)[0]).get('AGENTX_DB_HOST');
  return typeof host === 'string' ? throwawayServerOfHost(host) : undefined;
}

/** The copy's own anchors container, for a copy's server: modules/evidence.bicep's `audit-anchors` is staging's alone. */
const copyAnchorsOf = (copy: string): string => throwawayAnchorsContainer(throwawayIdOf(copy) ?? '');

/**
 * Every app that serves traffic (ADR-002 Amendment G2d): the API, Zitadel and
 * its login pages. The worker joins in Phase 4.
 */
const APP_WORKLOADS: readonly string[] = ['api', 'zitadel', 'login'];

/** The most replicas an app may run, and why; and, where it has a floor, the fewest it must keep running, and why. */
type MostReplicas = { readonly most: number; readonly why: string } & (
  | { readonly fewest?: undefined; readonly fewestWhy?: undefined }
  | { readonly fewest: number; readonly fewestWhy: string }
);

/**
 * The apps whose replicas must stay at one, with why: the API's jobs apart from it (4D2e D13) keep to one copy, as the
 * lease alone doesn't make a second safe for the copier. An app running the API is held by its role besides
 * (`roleScaleProblems`), and sign-in's two apps by their environment (`SIGN_IN_COPIES`).
 */
const ONE_REPLICA: Readonly<Record<string, string>> = {
  jobs: "the API's jobs keep to one copy, which the lease alone doesn't make safe for the copier",
};

/**
 * Zitadel's most copies, by environment (SA3a). None of its state is one copy's, read from the pinned image itself
 * (v4.17.3): its memory cache is off and the caches it uses are in Postgres, each projection takes a Postgres advisory
 * lock and its `current_states` row before it writes, its queue is River's in Postgres, and every copy mounts the one
 * master key from the vault. Staging keeps one: its server's 35 user connections hold no second pool. Production runs
 * up to four, each one's pool counted against its server (`connections`), and keeps two running, so sign-in never
 * hangs on one copy there. Each copy hashes its hostname to a 16-bit machine ID for the IDs it makes (FNV-1, its low 16
 * bits, read from the image, SA3d); two copies sharing one make the same IDs whenever they make one in the same 10 ms,
 * which the event store's key doesn't always refuse, so distinct IDs are an item before production (SA3d).
 */
export const ZITADEL_COPIES: Readonly<Record<Expectations['environment'], MostReplicas>> = {
  staging: { most: 1, why: "staging's server has no room for a second copy's database connections" },
  production: {
    most: 4,
    why: "Zitadel's copies stop at four (SA3a), each holding its own database connections",
    fewest: 2,
    fewestWhy: 'sign-in must not hang on one copy',
  },
};

/**
 * The login pages' most copies, by environment (SA3c). None of their state is one copy's, read from the pinned image
 * itself (v4.17.3; v4.19.5 signs each `sessions` entry with a key every copy derives alike from the one mounted login
 * key file, as no ZITADEL_SESSION_COOKIE_SECRET is set): a sign-in's sessions travel in the browser's own cookies
 * (`sessions`, `fingerprintId`, `verificationCheck`) and its request in the address (`requestId`), Next's key for server actions is the one built
 * into the image, the system user's key is the one mounted file, and its settings cache (on by default, 15 minutes)
 * only lets each copy be as stale as one would be. Staging keeps one; production two to four, as Zitadel's.
 */
export const LOGIN_COPIES: Readonly<Record<Expectations['environment'], MostReplicas>> = {
  staging: { most: 1, why: 'staging keeps one copy of the login pages, as it does of Zitadel' },
  production: {
    most: 4,
    why: "the login pages' copies stop at four (SA3c), as Zitadel's",
    fewest: 2,
    fewestWhy: 'sign-in must not hang on one copy',
  },
};

/** Sign-in's two apps, held by environment rather than to one: Zitadel (SA3a) and its login pages (SA3c). */
const SIGN_IN_COPIES: Readonly<Record<string, Readonly<Record<Expectations['environment'], MostReplicas>>>> = {
  zitadel: ZITADEL_COPIES,
  login: LOGIN_COPIES,
};

/** The most replicas a workload may run in an environment, or nothing where only the defaults hold it. */
function mostReplicasOf(workload: string, environment: Expectations['environment']): MostReplicas | undefined {
  const signIn = SIGN_IN_COPIES[workload];
  if (signIn !== undefined) return signIn[environment];
  const why = ONE_REPLICA[workload];
  return why === undefined ? undefined : { most: 1, why };
}

/** What Azure keeps of a server's max_connections for itself: 35 of 50 left for everyone (postgres.bicep, S167). */
const AZURE_RESERVED_CONNECTIONS = 15;

/**
 * Zitadel's pool where it sets none: ZITADEL_DATABASE_POSTGRES_MAXOPENCONNS's default, 10, read from the pinned
 * image's own binary (v4.17.3, 4D2e D12; the same in v4.19.5's defaults), not from its documentation.
 */
const ZITADEL_POOL = { setting: 'ZITADEL_DATABASE_POSTGRES_MAXOPENCONNS', unset: 10 } as const;

/** Beside the apps: one job's connection (they are run one at a time, Azure.md "The jobs"), and one to spare. */
const ONE_JOB_AND_ONE_MORE = 2;

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
  // Zitadel's debug pages go to the API (a 404 there), whatever their case; its login
  // pages go to the login app; then an allow-list (SA1): only what a browser
  // needs from Zitadel, each prefix in its one case, and everything else to the
  // API, which answers every request on the auth host with a plain 404
  // (apps/api/src/login-host.ts). Zitadel's system API, instance services, REST gateways,
  // reflection, /openapi, /saml and /idps are never public.
  auth: [
    'prefix "/debug" in any case to api',
    'prefix "/ui/v2/login" to login',
    ...[
      '/.well-known/',
      '/oauth/v2/',
      '/oidc/v1/',
      '/ui/console',
      '/ui/login',
      '/assets/v1/',
      // The gRPC-web services the console's browser code calls (its grpc.service.ts at v4.17.3, unchanged in v4.19.5).
      '/zitadel.admin.v1.AdminService/',
      '/zitadel.management.v1.ManagementService/',
      '/zitadel.auth.v1.AuthService/',
      '/zitadel.user.v2.UserService/',
      '/zitadel.session.v2.SessionService/',
      '/zitadel.feature.v2.FeatureService/',
      '/zitadel.action.v2.ActionService/',
      '/zitadel.webkey.v2.WebKeyService/',
      '/zitadel.org.v2.OrganizationService/',
      '/zitadel.authorization.v2.AuthorizationService/',
      '/zitadel.application.v2.ApplicationService/',
    ].map((prefix) => `prefix "${prefix}" to zitadel`),
    'prefix "/" to api',
  ],
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

/** This repository as GitHub names it in a subject (names.bicep `githubRepository`). */
const GITHUB_REPOSITORY = 'repo:shahbaz242630@205810405/agent-x@1368211207';

/**
 * The GitHub subject CI signs in with (G4): a job of this repository in the
 * GitHub environment of the same name, in the immutable form GitHub writes for
 * a repository made after 15 July 2026. names.bicep writes it too, so changing
 * who may sign in takes both.
 */
const releaseSubject = (environment: string): string => `${GITHUB_REPOSITORY}:environment:${environment}`;

/**
 * The GitHub subject the job-start watch signs in with (S175; names.bicep
 * `jobWatchSubject`): a job of this repository on main, in no environment. Never
 * CI's environment subject, so the watch's trust can't stand in for CI's.
 */
const WATCH_SUBJECT = `${GITHUB_REPOSITORY}:ref:refs/heads/main`;

/** CI's identity in an environment, as names.bicep names it. */
const releaseIdentityName = (environment: string): string =>
  `id-agentx-${environment === 'production' ? 'prd' : 'stg'}-release`;

/** The job-start watch's identity in an environment (S175), as names.bicep names it. */
const watchIdentityName = (environment: string): string =>
  `id-agentx-${environment === 'production' ? 'prd' : 'stg'}-job-watch`;

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

/** The job-start watch's role's name (S175), as names.bicep's `jobWatchRoleName` makes it. */
const watchRoleName = (groupId: string): string => bicepGuid(groupId, 'job-watch');

/**
 * Everything the job-start watch's role allows (S175): reading the jobs and
 * their runs (Azure names a run's read both ways). Nothing that starts, stops,
 * writes, lists a secret or opens a shell: the watch only reads.
 */
const WATCH_ACTIONS: readonly string[] = [
  'Microsoft.App/jobs/read',
  'Microsoft.App/jobs/executions/read',
  'Microsoft.App/jobs/execution/read',
];

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
 * file rather than a surprise. Zitadel's machine-ID webhook, whose default asks
 * Google Cloud's metadata server (S19), is `zitadel-machine-ids`'s: it asks our API. Read off the defaults the pinned image carries
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
const CREATED_ONCE: ReadonlySet<string> = new Set(['zitadel-masterkey', ...APP_KEYS, ...PUBLIC_HALVES.values()]);

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

/** The two containers of the write-once store (modules/evidence.bicep): the audit exports', the chains' anchors' (4D2e E, PL-58). */
const EVIDENCE_CONTAINER = 'audit-exports';
const ANCHOR_CONTAINER = 'audit-anchors';

/**
 * The anchors' role's two data actions: Put Blob of a file not there yet, and
 * Get Blob with List Blobs, which a restart needs. Never overwrite or delete.
 */
const ANCHOR_ACTIONS = [
  EVIDENCE_WRITE,
  'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read',
] as const;

/** The anchors' custom role as a role assignment names it, without case (modules/evidence.bicep names it so). */
const anchorRoleName = (groupId: string): string => bicepGuid(groupId, 'audit-anchors');

/**
 * A read-only role on a store's container: Get Blob and List Blobs alone. The chain repair's read of the anchors and
 * of the plans (4D2e E10). The operator holds the anchors' own role instead, to add a rebase (E11).
 */
const ANCHOR_READ_ACTIONS = ['Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'] as const;

/** The chain repair's read of the anchors as a role assignment names it, without case (modules/evidence.bicep names it so). */
const anchorReaderRoleName = (groupId: string): string => bicepGuid(groupId, 'audit-anchors-reader');

/** The chain repair's read of the plans as a role assignment names it, without case (modules/evidence.bicep, 4D2e E10). */
const planReaderRoleName = (groupId: string): string => bicepGuid(groupId, 'evidence-plan-reader');

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

/** The ids of the login alerts' own workspace: only the one this deployment creates under its name. */
const loginWorkspaceIds = (snapshot: Snapshot): ReadonlySet<unknown> =>
  new Set(
    ofType(snapshot, TYPES.workspace)
      .filter((workspace) => LOGIN_WORKSPACE.test(workspace.name))
      .map((workspace) => workspace.id),
  );

/**
 * The ids of the main workspace: every workspace of this deployment but the login alerts' own, which takes no
 * console lines, so an alert or a workbook on the apps' lines there would never see one.
 */
const mainWorkspaceIds = (snapshot: Snapshot): ReadonlySet<unknown> => {
  const logins = loginWorkspaceIds(snapshot);
  return new Set([...workspaceIds(snapshot)].filter((id) => !logins.has(id)));
};

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
 * Whether an enabled alert on this deployment's main workspace (or on those
 * given) has a condition `matches` takes. A `stateless SEV-1` one is severity 1
 * and never resolves itself (autoMitigate false), so it notifies on every
 * window, not once.
 */
const workspaceAlerted = (
  snapshot: Snapshot,
  kind: 'any' | 'stateless SEV-1',
  matches: (criterion: unknown, alert: PredictedResource) => boolean,
  workspaces: ReadonlySet<unknown> = mainWorkspaceIds(snapshot),
): boolean => {
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
    // The main one and the login alerts' own (rule login-workspace).
    ["log workspaces, the main one and the login alerts' own", TYPES.workspace, 2, 2],
    ['an action group', TYPES.actionGroup, 1, Infinity],
    ['the network', TYPES.network, 1, 1],
    ['the DNS policy', TYPES.dnsPolicy, 1, 1],
    ['the key vault', TYPES.vault, 1, Infinity],
    ['the Postgres server', TYPES.server, 1, Infinity],
    ['the Container Apps environment', TYPES.environment, 1, 1],
    // The audit exports' store and the activity downloads', each with its own blob service and container.
    ["Storage accounts, the audit exports' and the activity downloads'", TYPES.storage, 2, 2],
    ['blob services, one in each Storage account', TYPES.blobService, 2, 2],
    // And on Stage G's run, its copy's own anchors (apps.bicep `throwawayAnchors`), which load-database judges.
    [
      'containers: the write-once store two, the activity downloads one',
      TYPES.container,
      3,
      3 + copyAnchorsContainers(snapshot).length,
    ],
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
  (APP_KEYS.includes(secretNameOf(secret)) || [...PUBLIC_HALVES.values()].includes(secretNameOf(secret))) &&
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

/** Every server grows its disk and an alert says so first (4D2e A): a full disk stops every write. */
const databaseDisk: Check = (snapshot, _expected, add) => {
  for (const server of ofType(snapshot, TYPES.server)) {
    if (at(server.properties, 'storage', 'autoGrow') !== 'Enabled') {
      add({ rule: 'database-disk', resource: server.name, message: 'grows its disk: a full disk stops every write' });
    }
    const watched = ofType(snapshot, TYPES.metricAlert).some(
      (alert) =>
        at(alert.properties, 'enabled') === true &&
        list(at(alert.properties, 'scopes')).includes(server.id) &&
        list(at(alert.properties, 'criteria', 'allOf')).some((one) => at(one, 'metricName') === 'storage_percent') &&
        list(at(alert.properties, 'actions')).some((one) => deliversAlerts(snapshot, at(one, 'actionGroupId'))),
    );
    if (!watched) {
      add({
        rule: 'database-disk',
        resource: server.name,
        message: 'has an alert on how full its disk is, switched on, that reaches someone',
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

/** Every server states its zone, measures nothing on a Burstable size (4D2d P5), and keeps what names a stall (MO5). */
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
    const unrecorded = [...STALL_EVIDENCE]
      .filter(([name, value]) => settings.get(name) !== value)
      .map(([name, value]) => `${name}=${value}`);
    if (unrecorded.length > 0) {
      add({
        rule: 'database-stall-evidence',
        resource: server.name,
        message: `keeps what names a stall (MO5): its checkpoints and lock waits over a second logged, and its wait counts as metrics; differing or not stated: ${unrecorded.join(', ')}`,
      });
    }
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
    const minimum = leastRestoreDays(expected.environment);
    if (typeof retention !== 'number' || retention < minimum) {
      problem(
        'database-backup',
        `keeps at least ${String(minimum)} days of point-in-time restore (ADR-002; in production, twice the days an old audit event edited may go unfound, 4D2e decision 3)`,
      );
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
        at(alert.properties, 'overrideQueryTimeRange') === LATE_LINES_READ &&
        queryIs(
          at(criterion, 'query'),
          'PGSQLServerLogs',
          [ARRIVED_LATELY, `where Message matches regex ${pattern}`],
          'count()',
        ) &&
        watchesEveryWindow(alert, criterion),
      loginWorkspaceIds(snapshot),
    );
    if (settings.get('log_connections') !== 'on' || settings.get('log_line_prefix') !== LOG_LINE_PREFIX || !alerted) {
      problem(
        'database-logins',
        `logs every login, and an enabled, stateless SEV-1 alert on the login alerts' workspace, watching every minute by when each line arrived, over the two days before, fires on the first window when ${admin} or ${BACKUP_ROLE} logs in (ADR-012 §2)`,
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
    .filter((rule) => sameWord(at(rule, 'direction'), direction));
};

/** Azure reads a rule's direction and access without case (`outbound` is `Outbound`), so these checks do too (AZ8e). */
const sameWord = (value: unknown, word: string): boolean =>
  typeof value === 'string' && value.toLowerCase() === word.toLowerCase();

const inboundRules = (snapshot: Snapshot, subnet: unknown): readonly unknown[] =>
  subnetRules(snapshot, subnet, 'Inbound');

const outboundRules = (snapshot: Snapshot, subnet: unknown): readonly unknown[] =>
  subnetRules(snapshot, subnet, 'Outbound');

const allowing = (inbound: readonly unknown[]): readonly unknown[] =>
  inbound.filter((rule) => sameWord(at(rule, 'access'), 'Allow'));

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
      sameWord(at(rule, 'access'), 'Deny') &&
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
    // The network's own region, not the expected one: this rule asks that the
    // key vault tag names where this deployment is, and `in-country` asks
    // separately that that is the UAE.
    const wanted = new Map(
      egressDoors(text(network.location), prefix, text(at(database, 'properties', 'addressPrefix'))),
    );
    for (const message of egressProblems(snapshot, apps, 'apps', wanted)) {
      add({ rule: 'apps-egress', resource: network.name, message });
    }
  }
};

/**
 * What is wrong with a subnet's way out, against the doors it must have,
 * exactly: one missing, one extra, one from another source, or the rest not
 * denied after them. Empty for a subnet whose way out is just `wanted`.
 */
function egressProblems(
  snapshot: Snapshot,
  subnet: unknown,
  name: string,
  wanted: ReadonlyMap<string, string>,
): string[] {
  const prefix = text(at(subnet, 'properties', 'addressPrefix'));
  const outbound = outboundRules(snapshot, subnet);
  const allows = allowing(outbound);
  const problems: string[] = [];
  const open = new Set(allows.map(doorOf));
  for (const [door, why] of wanted) {
    if (!open.has(door)) problems.push(`its ${name} subnet must let out ${door}, for ${why}`);
  }
  for (const door of [...open].filter((door) => !wanted.has(door))) {
    problems.push(`its ${name} subnet lets out ${door}, which nothing it runs needs`);
  }
  for (const source of new Set(
    allows.map((rule) => text(at(rule, 'sourceAddressPrefix'))).filter((source) => source !== prefix),
  )) {
    problems.push(`its ${name} subnet lets out traffic from ${source || 'nowhere named'}, not from the subnet alone`);
  }
  if (!deniesRestOfTheInternet(outbound)) {
    problems.push(`its ${name} subnet must deny everything else out, after every rule that allows`);
  }
  return problems;
}

/**
 * The way out of every Postgres subnet is an allowlist too (AZ8): Azure's
 * default rules let the server reach the whole internet, so a server taken
 * over could send the data out of the UAE (ADR-009). Microsoft names what a
 * server in a subnet needs when an NSG denies the rest: port 5432 inside its
 * subnet and Azure Storage, where the write-ahead log is archived, narrowed
 * to the region. Azure's DNS is written down as the apps subnet's is.
 */
const databaseEgress: Check = (snapshot, _expected, add) => {
  for (const { subnet, network } of postgresSubnets(snapshot)) {
    const prefix = text(at(subnet, 'properties', 'addressPrefix'));
    const wanted = new Map([
      [`Tcp to ${prefix} on 5432`, "the server's own features inside its subnet, high availability among them"],
      [`* to ${AZURE_DNS} on 53`, "Azure's DNS, which resolves the storage below"],
      [`Tcp to Storage.${text(network.location)} on 443`, 'the write-ahead log and backups, in this region alone'],
    ]);
    for (const message of egressProblems(snapshot, subnet, text(at(subnet, 'name')), wanted)) {
      add({ rule: 'database-egress', resource: network.name, message });
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

/** This deployment's DNS lists that hold every name ('.'), their names by id. */
const everyNameLists = (snapshot: Snapshot): ReadonlyMap<string, string> =>
  new Map(
    ofType(snapshot, TYPES.dnsDomainList)
      .filter((domains) => list(at(domains.properties, 'domains')).includes(EVERY_NAME))
      .map((domains) => [domains.id, domains.name]),
  );

/** A DNS policy's own rules: their ids sit under the policy's. */
const dnsRulesOf = (snapshot: Snapshot, policy: string): readonly PredictedResource[] =>
  ofType(snapshot, TYPES.dnsPolicyRule).filter((rule) => rule.id.startsWith(`${policy}/dnsSecurityRules/`));

/** The names of the every-name lists an enabled rule of `policy` blocks: the lookups no rule above it allows. */
const blockedEveryName = (snapshot: Snapshot, policy: string): readonly string[] => {
  const everyName = everyNameLists(snapshot);
  return dnsRulesOf(snapshot, policy)
    .filter((rule) => dnsRuleOn(rule) && dnsActionOf(rule) === 'block')
    .flatMap((rule) => list(at(rule.properties, 'dnsResolverDomainLists')))
    .flatMap((domains) => everyName.get(text(at(domains, 'id'))) ?? []);
};

/**
 * Every lookup the network makes is judged by a DNS policy of this deployment
 * (S68 audit finding 14): its rules see what Azure's DNS answers, which the
 * apps subnet's rules must let out and so can't filter. The network is linked
 * to one of the deployment's policies, which holds an enabled rule over every
 * name, in a list of this deployment, that blocks each lookup (AZ1, S188:
 * alerting alone let any name be answered), so a name no rule above it allows
 * is refused and logged; and no rule allows every name, which would let each
 * lookup through before that rule is reached (it would still be logged, Allow
 * logs too, but never blocked). A broad Allow short of every name (`com.`)
 * would shadow it the same way: the allowlist refuses those too (dns-allow).
 * Azure reads the state and the action without regard to case, so they are
 * compared that way. Rule `resource-logs` sends what the policy sees to the
 * workspace, and `dns-block-alert` tells someone of each blocked lookup.
 */
const dnsWatch: Check = (snapshot, _expected, add) => {
  const everyName = everyNameLists(snapshot);
  const rulesOf = (policy: string): readonly PredictedResource[] => dnsRulesOf(snapshot, policy);
  const coversEveryName = (rule: PredictedResource): boolean =>
    list(at(rule.properties, 'dnsResolverDomainLists')).some((domains) => everyName.has(text(at(domains, 'id'))));
  const watches = (rule: PredictedResource): boolean =>
    dnsRuleOn(rule) && dnsActionOf(rule) === 'block' && coversEveryName(rule);
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
          "must be linked to this deployment's DNS policy, with an enabled rule blocking every name ('.') and none allowing every name, so each lookup no Allow names is refused and logged",
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

/**
 * The lookups the catch-all refuses that are expected, each answered no-such-name before Block too, and each one's
 * labels reaching only servers no customer runs (S85, S188: 6,698 of 14 days' 8,130 catch-all lookups): reverse
 * lookups of the network's and the platform's private addresses (public AS112 servers), the root's own NS, the
 * nodes' bare names, and CoreDNS's loop check (a HINFO of two random numbers). Anything else blocked is news.
 */
export const DNS_EXPECTED_LEFTOVERS =
  'where not((QueryType == "PTR" and (QueryName endswith ".10.in-addr.arpa." or QueryName endswith ".100.100.in-addr.arpa.")) or (QueryType == "NS" and QueryName == ".") or (QueryType == "HINFO" and QueryName matches regex "^[0-9]+[.][0-9]+[.]$") or QueryName matches regex "^aks-[a-z0-9]+-[0-9]+-vmss[0-9A-Z]{6}[.]$")';

/** The lookups an every-name list judged, by its name: the ones the catch-all blocks once it blocks. */
const dnsCatchAllLines = (listName: string): string => `where ResolverPolicyDomainListId endswith "/${listName}"`;

/**
 * A stateless SEV-1 alert on the main workspace fires on any lookup a DNS policy's catch-all blocks, past the expected
 * leftovers, every window (AZ1, S188; partner S98: Microsoft adds storage stamps and moves its chains, and a blocked
 * one can stop the vault, sign-in, image pulls or a database's backups until its name is listed). Its query names the
 * every-name list that policy's Block rule holds, so a renamed list never leaves it counting nothing; counts only.
 */
const dnsBlockAlert: Check = (snapshot, _expected, add) => {
  for (const policy of ofType(snapshot, TYPES.dnsPolicy)) {
    const alerted = blockedEveryName(snapshot, policy.id).some((listName) =>
      workspaceAlerted(
        snapshot,
        'stateless SEV-1',
        (criterion, alert) =>
          queryIs(
            at(criterion, 'query'),
            'DNSQueryLogs',
            [dnsCatchAllLines(listName), DNS_EXPECTED_LEFTOVERS],
            'count()',
          ) &&
          totals(criterion) &&
          at(criterion, 'operator') === 'GreaterThan' &&
          at(criterion, 'threshold') === 0 &&
          watchesEveryWindow(alert, criterion),
      ),
    );
    if (!alerted) {
      add({
        rule: 'dns-block-alert',
        resource: policy.name,
        message:
          "needs an enabled stateless SEV-1 alert on this deployment's main workspace that fires on any lookup its every-name Block rule refuses, past the expected leftovers, watching every window and firing on the first",
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
 * decisions 27 and 28) and the chains' anchors (4D2e E, PL-58): one account,
 * named as modules/evidence.bicep names it and as `evidenceAccountProblems`
 * says, with versioning on its one blob service and two private containers; no
 * other Storage resource (a lifecycle rule, a file share, a local user) but the
 * activity downloads' store's, which is `activity-downloads`'s; the apps subnet
 * keeps the service endpoint its network rule needs. Each container has one
 * custom role, assignable in the resource group alone, given on that
 * container alone: the exports' adds a new file and nothing else, to the
 * operator's identity, whose job alone is told where they go; the anchors' adds
 * a new file and reads, to the identities of the apps that may hold the jobs
 * (`ANCHOR_KEEPERS`, 4D2e D13) and to the operator's (a chain recovery plan,
 * 4D2e E9, and a rebase, E11). The anchors container has a second role, reading
 * alone, to the chain repair's identity (4D2e E10). The app that holds the jobs,
 * the operator's job and the chain repair's job alone are told where the anchors
 * are, each as its own identity, which its role is given to (`storeSettingsProblems`). None can
 * overwrite or delete. The account's immutability covers both. Its logs are
 * `resource-logs`'s.
 */
const evidenceStore: Check = (snapshot, expected, add) => {
  const problem = (resource: string, message: string): void => {
    add({ rule: 'evidence-store', resource, message });
  };
  const copy = stageGCopyIn(snapshot);
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
      containers: containersNamed(snapshot, EVIDENCE_CONTAINER),
      workloads: STORE_WRITERS,
      called: "the audit exports' role",
      on: 'the export container',
    },
    problem,
  );
  // The chain repair reads the plan it applies (4D2e E10): reading alone, on the exports, to its identity alone.
  storeRoleProblems(
    snapshot,
    {
      name: planReaderRoleName(groupOf(snapshot)),
      dataActions: ANCHOR_READ_ACTIONS,
      containers: containersNamed(snapshot, EVIDENCE_CONTAINER),
      workloads: ['chain-restore'],
      called: "the chain repair's read of the plans",
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
      container: () => EVIDENCE_CONTAINER,
      holders: (workload) => (isJobOf(workload, STORE_WRITERS) ? ownOf(workload, writers) : undefined),
      holder: "the operator's and the chain repair's jobs write to the store",
      store: 'store',
    },
    problem,
  );
  const keepers = storeRoleProblems(
    snapshot,
    {
      name: anchorRoleName(groupOf(snapshot)),
      dataActions: ANCHOR_ACTIONS,
      containers: containersNamed(snapshot, ANCHOR_CONTAINER),
      // The operator adds a chain's rebase (4D2e E11) as the app holding the jobs adds an anchor.
      workloads: [...ANCHOR_KEEPERS[expected.environment], 'operator'],
      called: "the anchors' role",
      on: 'the anchors container',
      apart: copyAnchorsContainers(snapshot),
    },
    problem,
  );
  const readers = storeRoleProblems(
    snapshot,
    {
      name: anchorReaderRoleName(groupOf(snapshot)),
      dataActions: ANCHOR_READ_ACTIONS,
      containers: containersNamed(snapshot, ANCHOR_CONTAINER),
      workloads: ['chain-restore'],
      called: "the chain repair's read of the anchors",
      on: 'the anchors container',
    },
    problem,
  );
  storeSettingsProblems(
    snapshot,
    {
      prefix: ANCHOR_SETTING_PREFIX,
      url: 'AGENTX_AUDIT_ANCHORS_URL',
      clientId: 'AGENTX_AUDIT_ANCHORS_CLIENT_ID',
      accounts,
      // On Stage G's copy the app holding the jobs keeps the copy's anchors in their own container, never staging's.
      container: (workload) => (copy !== undefined && holdsJobs(workload) ? copyAnchorsOf(copy) : ANCHOR_CONTAINER),
      holders: (workload) => {
        if (holdsJobs(workload) || isJobOf(workload, ['operator'])) return ownOf(workload, keepers);
        return isJobOf(workload, ['chain-restore']) ? ownOf(workload, readers) : undefined;
      },
      holder:
        "the app that holds the jobs and the operator's job keep the chains' anchors and the chain repair's job reads them",
      store: 'store',
    },
    problem,
  );
};

/** An app that runs the API (4D2e D13): `api`, or the `jobs` app apart from it (every API process is told AGENTX_ENV). */
const runsApi = (workload: PredictedResource): boolean =>
  workload.type === TYPES.app && apiSettingsOf(workload) !== undefined;

/** The app that holds the API's jobs (4D2e D13): at AGENTX_ROLE all, or jobs; never a `web` copy. */
function holdsJobs(workload: PredictedResource): boolean {
  if (workload.type !== TYPES.app) return false;
  const settings = apiSettingsOf(workload);
  const role = settings === undefined ? undefined : roleIn(settings);
  return role === 'all' || role === 'jobs';
}

/** Of a store's identities, the workload's own: a workload is told only the identity it runs as, its role given to it. */
const ownOf = (workload: PredictedResource, identities: readonly PredictedResource[]): readonly PredictedResource[] =>
  identities.filter((identity) => workloadOf(identity.name) === jobWorkloadOf(workload.name));

/**
 * Who keeps the chains' anchors, by environment (main.bicep `anchorKeepers`, 4D2e D13): the identity of the app that
 * holds the jobs. Production always runs them apart, in `jobs`; staging's one API holds them out of a load run and the
 * `jobs` app in one, so both are given the role there, and only the one holding the jobs is told where the store is.
 */
const ANCHOR_KEEPERS: Readonly<Record<Expectations['environment'], readonly string[]>> = {
  production: ['jobs'],
  staging: ['api', 'jobs'],
};

/**
 * The jobs that write to the evidence store and read the anchors, each as its
 * own identity: the operator's (E10c, 4D2e E9) and the chain repair's (4D2e E10).
 */
const STORE_WRITERS: readonly string[] = ['operator', 'chain-restore'];

/** A job among `jobs`, as a store's settings judge it. */
const isJobOf = (workload: PredictedResource, jobs: readonly string[]): boolean =>
  workload.type === TYPES.job && jobs.includes(jobWorkloadOf(workload.name));

/**
 * The anchors' epoch (AGENTX_ANCHOR_EPOCH, 4D2e E9): the app that holds the jobs
 * (4D2e D13), which signs for it, and the operator's and the chain repair's jobs,
 * which read the anchors for a chain recovery plan or a repair, each
 * set it once, to the same value, and nothing else sets it. Apart, the operator
 * would read another epoch's files, or none, and plan against the wrong anchors.
 */
const anchorEpoch: Check = (snapshot, _expected, add) => {
  const values = new Map<string, readonly string[]>();
  for (const workload of workloadsIn(snapshot)) {
    const set = containersOf(workload).flatMap((container) =>
      list(at(container, 'env'))
        .filter((entry) => at(entry, 'name') === 'AGENTX_ANCHOR_EPOCH')
        .map((entry) => text(at(entry, 'value'))),
    );
    if (holdsJobs(workload) || isJobOf(workload, STORE_WRITERS)) {
      values.set(workload.name, set);
    } else if (set.length > 0) {
      add({
        rule: 'anchor-epoch',
        resource: workload.name,
        message:
          "sets AGENTX_ANCHOR_EPOCH: only the app that holds the jobs, the operator's job and the chain repair's",
      });
    }
  }
  const said = [...values.values()];
  const first = said[0]?.[0];
  if (said.length !== 1 + STORE_WRITERS.length || said.some((set) => set.length !== 1 || set[0] !== first)) {
    add({
      rule: 'anchor-epoch',
      resource: 'the deployment',
      message:
        "must set AGENTX_ANCHOR_EPOCH once on the app that holds the jobs, once on the operator's job and once on the chain repair's, to the same value",
    });
  }
};

/** A resource's own name, the last part of its id. */
const nameOf = (resource: PredictedResource): string => resource.id.slice(resource.id.lastIndexOf('/') + 1);

/** Stage G's copies' own anchors containers (apps.bicep `throwawayAnchors`), by their name's shape alone. */
const copyAnchorsContainers = (snapshot: Snapshot): readonly PredictedResource[] =>
  ofType(snapshot, TYPES.container).filter(
    (container) => !inDownloadsStore(snapshot, container) && /^audit-anchors-g-[a-z0-9]+$/.test(nameOf(container)),
  );

/** One of the write-once store's containers, by its name: a role is given on it alone. */
const containersNamed = (snapshot: Snapshot, name: string): readonly PredictedResource[] =>
  ofType(snapshot, TYPES.container).filter(
    (container) => !inDownloadsStore(snapshot, container) && container.id.endsWith(`/containers/${name}`),
  );

/**
 * The store's blob service, its two containers and no other Storage resource, a
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
  // Stage G's copy's own anchors are load-database's to judge: here, only that they are in this store.
  const wanted = [EVIDENCE_CONTAINER, ANCHOR_CONTAINER, ...copyAnchorsContainers(snapshot).map(nameOf)];
  for (const container of ofType(snapshot, TYPES.container).filter(ours)) {
    if (
      !blobServices.some((service) => wanted.some((name) => container.id === `${service.id}/containers/${name}`)) ||
      at(container.properties, 'publicAccess') !== 'None'
    ) {
      problem(container.name, `must be ${wanted.join(' or ')} in this deployment's store, with no public access`);
    }
  }
  const known: readonly string[] = [TYPES.storage, TYPES.blobService, TYPES.container];
  for (const resource of snapshot.predictedResources.filter(ours)) {
    if (resource.type.toLowerCase().startsWith('microsoft.storage/') && !known.includes(resource.type)) {
      problem(resource.name, `is a ${resource.type}: the store holds its two containers and nothing else`);
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
  /** The apps or jobs whose identities it is given to, once each. */
  readonly workloads: readonly string[];
  /** Containers whose assignments of this role another rule judges (Stage G's copy's own anchors, load-database). */
  readonly apart?: readonly PredictedResource[];
  /** What a problem calls it, and the container it is given on. */
  readonly called: string;
  readonly on: string;
}

/**
 * A store's custom role and its assignments, a part of `evidence-store` and
 * `activity-downloads`: exactly its data actions, no action, assignable in the
 * resource group alone, given on the container once to each of its workloads'
 * identities and to no one else. Returns the identities it is given to.
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
  const apart = new Set((wanted.apart ?? []).map((container) => container.id));
  const assignments = ofType(snapshot, TYPES.roleAssignment).filter(
    (assignment) => roleOf(assignment) === role && !apart.has(scopeOf(assignment)),
  );
  const whose = wanted.workloads.join(' and ');
  const given = assignments.map((assignment) => principalOf(snapshot, assignment));
  for (const [index, assignment] of assignments.entries()) {
    const identity = given[index];
    if (
      !wanted.containers.some((container) => container.id === scopeOf(assignment)) ||
      identity === undefined ||
      !wanted.workloads.includes(workloadOf(identity.name))
    ) {
      problem(
        assignment.name,
        `must give ${wanted.called} on ${wanted.on} alone, to the ${whose}'s identity (principalType ServicePrincipal)`,
      );
    }
  }
  for (const workload of wanted.workloads) {
    const times = given.filter((identity) => identity !== undefined && workloadOf(identity.name) === workload).length;
    if (times !== 1 || assignments.length !== wanted.workloads.length) {
      problem(
        'the deployment',
        `must give ${wanted.called} once to each of the ${whose}, and to no one else; it gives it ${String(assignments.length)} times, ${String(times)} to the ${workload}`,
      );
    }
  }
  return given.flatMap((identity) => identity ?? []);
}

/** How the operator's job is told where to write an audit export (apps.bicep `evidenceSettings`). */
const EVIDENCE_SETTING_PREFIX = 'AGENTX_EVIDENCE_';

/** How the API is told where to keep the chains' anchors (apps.bicep `anchorStoreSettings`). */
const ANCHOR_SETTING_PREFIX = 'AGENTX_AUDIT_ANCHORS_';

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
  /** The container a workload's URL must name. */
  readonly container: (workload: PredictedResource) => string;
  /** The identities a workload may name, those its store's role is given to; undefined for one never told of the store. */
  readonly holders: (workload: PredictedResource) => readonly PredictedResource[] | undefined;
  /** Who alone is told, and what a problem calls the store. */
  readonly holder: string;
  readonly store: string;
}

/** Whether a workload's settings of a store are its URL to `container` and the client ID of one of `holders`, alone. */
function storeSettingsSound(
  wanted: StoreSettings,
  names: readonly string[],
  values: ReadonlyMap<string, string>,
  container: string,
  holders: readonly PredictedResource[],
): boolean {
  const url = STORE_URL.exec(values.get(wanted.url) ?? '');
  const client = CLIENT_ID_OF.exec(values.get(wanted.clientId) ?? '');
  return (
    names.toSorted().join() === [wanted.url, wanted.clientId].toSorted().join() &&
    wanted.accounts.length === 1 &&
    url !== null &&
    url[1] === wanted.accounts[0]?.name &&
    url[2] === container &&
    holders.some((holder) => holder.id === client?.[1])
  );
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
  problem: (resource: string, message: string) => void,
): void {
  for (const workload of workloadsIn(snapshot)) {
    const holders = wanted.holders(workload);
    for (const container of containersOf(workload)) {
      const settings = list(at(container, 'env')).filter((entry) => text(at(entry, 'name')).startsWith(wanted.prefix));
      const names = settings.map((entry) => text(at(entry, 'name')));
      if (holders === undefined) {
        if (names.length > 0) problem(workload.name, `sets ${names.join(', ')}: only ${wanted.holder}`);
        continue;
      }
      const values = new Map(settings.map((entry) => [text(at(entry, 'name')), text(at(entry, 'value'))] as const));
      const containerName = wanted.container(workload);
      if (!storeSettingsSound(wanted, names, values, containerName, holders)) {
        problem(
          workload.name,
          `must set ${wanted.url} to this deployment's ${wanted.store}'s ${containerName} container, and ${wanted.clientId} to the client ID of the identity its role is given to, each once as a value, and no other ${wanted.prefix} setting`,
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
 * on the container, to the identity of each app that runs the API (4D2e D13:
 * a `web` copy hands a file out, the jobs build it); they alone are told where
 * the store is, each as its own identity. Its logs are `resource-logs`'s, and the subnet's Storage endpoint
 * `evidence-store`'s.
 */
const activityDownloads: Check = (snapshot, _expected, add) => {
  const problem = (resource: string, message: string): void => {
    add({ rule: 'activity-downloads', resource, message });
  };
  const copy = stageGCopyIn(snapshot);
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
      workloads: API_APPS,
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
      container: () => DOWNLOADS_CONTAINER,
      // Not on Stage G's copy (4D2e): it holds staging's downloads under way, which it would write over.
      holders: (workload) => (runsApi(workload) && copy === undefined ? ownOf(workload, keepers) : undefined),
      holder: `the apps that run the API keep the activity downloads${copy === undefined ? '' : ", and never on Stage G's copy"}`,
      store: 'downloads store',
    },
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

/** The categories one diagnostic setting sends, switched on. */
const sentCategories = (setting: PredictedResource): readonly unknown[] =>
  list(at(setting.properties, 'logs'))
    .filter((log) => at(log, 'enabled') === true)
    .map((log) => at(log, 'category') ?? at(log, 'categoryGroup'));

/** Whether every resource of the type, and at least one, sends the category to the workspace, in its own table. */
const sendsTo = (snapshot: Snapshot, type: string, category: string, workspace: string): boolean => {
  const resources = ofType(snapshot, type);
  return (
    resources.length > 0 &&
    resources.every((resource) =>
      settingsOf(snapshot, resource).some(
        (setting) =>
          at(setting.properties, 'workspaceId') === workspace &&
          at(setting.properties, 'logAnalyticsDestinationType') === 'Dedicated' &&
          sentCategories(setting).includes(category),
      ),
    )
  );
};

/**
 * The login alerts' own workspace (4D2e Stage F, PR 9): exactly one, its cap 1 GB; the server's log and the
 * platform's lines reach it, and nothing else does, so the apps' volume can never fill it; its cap reached is a
 * stateless SEV-1. Rules database-logins and owner-login-alert hold the login alerts to it.
 */
const loginWorkspace: Check = (snapshot, _expected, add) => {
  const found = ofType(snapshot, TYPES.workspace).filter((workspace) => LOGIN_WORKSPACE.test(workspace.name));
  const [workspace] = found;
  if (workspace === undefined || found.length > 1) {
    add({
      rule: 'login-workspace',
      resource: 'the deployment',
      message: `needs exactly one workspace for the login alerts (log-agentx-<env>-logins); the snapshot has ${String(found.length)}`,
    });
    return;
  }
  const missing: string[] = [];
  if (at(workspace.properties, 'workspaceCapping', 'dailyQuotaGb') !== LOGIN_WORKSPACE_CAP_GB) {
    missing.push(`a daily cap of ${String(LOGIN_WORKSPACE_CAP_GB)} GB`);
  }
  if (
    !sendsTo(snapshot, TYPES.server, 'PostgreSQLLogs', workspace.id) ||
    !sendsTo(snapshot, TYPES.environment, 'ContainerAppSystemLogs', workspace.id)
  ) {
    missing.push("the database server's log and the platform's lines, in resource-specific tables");
  }
  const others = ofType(snapshot, TYPES.diagnostics).filter(
    (setting) =>
      at(setting.properties, 'workspaceId') === workspace.id &&
      sentCategories(setting).some((category) => !LOGIN_LOG_CATEGORIES.includes(category)),
  );
  if (others.length > 0) missing.push(`no other logs (${others.map((setting) => setting.name).join(', ')} sends some)`);
  const capAlerted = workspaceAlerted(
    snapshot,
    'stateless SEV-1',
    (criterion) =>
      queryIs(
        at(criterion, 'query'),
        '_LogOperation',
        ['where Category =~ "Ingestion"', 'where Detail contains "OverQuota"'],
        'count()',
      ),
    new Set([workspace.id]),
  );
  if (!capAlerted) missing.push('a stateless SEV-1 alert when its cap is reached');
  for (const what of missing) add({ rule: 'login-workspace', resource: workspace.name, message: `must have ${what}` });
};

/** Every Azure resource ID a workbook's content names: its fallback workspaces and any it reads across. */
const resourceIdsIn = (content: unknown): readonly string[] => {
  if (typeof content === 'string') return content.startsWith('/subscriptions/') ? [content] : [];
  if (typeof content !== 'object' || content === null) return [];
  return Object.values(content).flatMap(resourceIdsIn);
};

/** The fields that name who: a workbook shows how much, never which organisation, agent, key or request. */
const WHO_FIELDS = /\b(?:orgId|agentId|agentKeyId|correlationId|userId)\b/;

/**
 * A workbook (4D2e Stage F, PR 10) reads only this deployment's workspaces, keeps its content in Azure's own store
 * in the region rather than a storage account of anyone's, and counts without naming who.
 */
const workbooks: Check = (snapshot, _expected, add) => {
  const workspaces = mainWorkspaceIds(snapshot);
  for (const workbook of ofType(snapshot, TYPES.workbook)) {
    const problem = (message: string): void => {
      add({ rule: 'workbook', resource: workbook.name, message });
    };
    let content: unknown;
    try {
      content = JSON.parse(text(at(workbook.properties, 'serializedData')));
    } catch {
      problem('needs its content as JSON the snapshot can read');
      continue;
    }
    const read = [at(workbook.properties, 'sourceId'), ...resourceIdsIn(content)];
    if (!read.every((id) => workspaces.has(id))) problem("must read this deployment's main workspace only");
    if (!isEmpty(at(workbook.properties, 'storageUri')))
      problem("keeps its content in Azure's own store, not storageUri");
    if (WHO_FIELDS.test(JSON.stringify(content)))
      problem('counts only: names no organisation, agent, key, person or request');
  }
};

/**
 * The rules that fire on the jobs' lines missing (4D2e D, PL-33): what stands behind a process that can say nothing.
 * Each line, how long without it, and at what severity. Only these may be off, and only on staging, which sleeps.
 */
const DEAD_MEN = [
  {
    event: 'audit.anchor_check_done',
    windowSize: 'PT30M',
    minutes: 30,
    column: 'Done',
    severity: 1,
    autoMitigate: false,
  },
  { event: 'jobs.pulse', windowSize: 'PT15M', minutes: 15, column: 'Pulses', severity: 2, autoMitigate: true },
] as const;

/**
 * The workspace's own word that its daily cap has stopped collection, the newest of the day: one row while it is
 * over, and for one window after its newest word (the reset's), as nothing from the stretch over arrived and new lines
 * come 4 to 9 minutes late: so a line missing then counts as seen (S183). Nothing arrives over the cap, so silence then says nothing of
 * the jobs; the cap's own alert says monitoring is blind. The day's word needs the day: `overrideQueryTimeRange`.
 */
const overCap = (minutes: number): string =>
  `(_LogOperation | where Category =~ "Ingestion" | where Detail contains "Ingestion status" | summarize arg_max(TimeGenerated, Detail) | where Detail contains "OverQuota" or TimeGenerated > ago(${String(minutes)}m))`;

/** The one query a dead man may run: its line within its own window, or the cap's word. */
const deadManQuery = ({ event, minutes, column }: (typeof DEAD_MEN)[number]): string =>
  `union (ContainerAppConsoleLogs | where TimeGenerated > ago(${String(minutes)}m) | where tostring(parse_json(Log).event) == "${event}"), ${overCap(minutes)} | summarize ${column} = count()`;

/** Whether the alert counts one of those lines, however else it is set. */
const isDeadMan = (alert: PredictedResource): boolean =>
  list(at(alert.properties, 'criteria', 'allOf')).some((criterion) =>
    DEAD_MEN.some((man) => at(criterion, 'query') === deadManQuery(man)),
  );

const deadManAlerts: Check = (snapshot, expected, add) => {
  const workspaces = mainWorkspaceIds(snapshot);
  for (const man of DEAD_MEN) {
    const { event, windowSize, severity, autoMitigate } = man;
    const found = ofType(snapshot, TYPES.alert).some(
      (alert) =>
        (expected.environment === 'staging' || at(alert.properties, 'enabled') === true) &&
        at(alert.properties, 'severity') === severity &&
        at(alert.properties, 'autoMitigate') === autoMitigate &&
        at(alert.properties, 'windowSize') === windowSize &&
        at(alert.properties, 'overrideQueryTimeRange') === 'P1D' &&
        list(at(alert.properties, 'scopes')).some((scope) => workspaces.has(scope)) &&
        list(at(alert.properties, 'criteria', 'allOf')).some(
          (criterion) =>
            at(criterion, 'query') === deadManQuery(man) &&
            totals(criterion) &&
            at(criterion, 'operator') === 'LessThan' &&
            at(criterion, 'threshold') === 1 &&
            at(criterion, 'failingPeriods', 'numberOfEvaluationPeriods') === 1 &&
            at(criterion, 'failingPeriods', 'minFailingPeriodsToAlert') === 1,
        ),
    );
    if (!found) {
      add({
        rule: 'dead-man-alerts',
        resource: event,
        message: `needs an alert on this deployment's workspace firing, at SEV-${String(severity)}, when ${windowSize} pass with none of this line and the workspace not over its daily cap, on everywhere but staging`,
      });
    }
  }
};

/** The look-back windows Azure accepts on a log alert; any other is refused only at deploy, after the what-if (S171). */
const ALERT_WINDOWS = new Set(
  [5, 10, 15, 30, 45, 60, 120, 180, 240, 300, 360, 720, 1440, 2880].map((minutes) =>
    minutes < 60
      ? `PT${String(minutes)}M`
      : minutes < 1440
        ? `PT${String(minutes / 60)}H`
        : `P${String(minutes / 1440)}D`,
  ),
);

const alertRules: Check = (snapshot, expected, add) => {
  for (const alert of ofType(snapshot, TYPES.alert)) {
    if (!ALERT_WINDOWS.has(String(at(alert.properties, 'windowSize')))) {
      add({
        rule: 'alert-window',
        resource: alert.name,
        message: `its windowSize must be one Azure accepts (${[...ALERT_WINDOWS].join(', ')}): Azure refuses any other only when the deploy runs`,
      });
    }
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
    // The playbook's alert sections: A to S, and W (a blocked DNS lookup, AZ1); T to V answer workflows, not alerts.
    const runbook = /^SEV-([12])\. .+ Runbook: Incident-Response-Playbook\.md section [A-SW]\.$/.exec(
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
      (at(alert.properties, 'enabled') !== true && !(expected.environment === 'staging' && isDeadMan(alert))) ||
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
  // The main workspace: the login alerts' own holds a copy of the platform's lines, never instead of it.
  const workspaces = mainWorkspaceIds(snapshot);
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
          "must send its console and system logs, and no other, to this deployment's main workspace in resource-specific tables: never its HTTP log or a category group (client addresses, ADR-011 §7)",
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
    const alerted = workspaceAlerted(
      snapshot,
      'any',
      (criterion) =>
        saysCountColumn(criterion) !== undefined &&
        kqlStages(String(at(criterion, 'query')))[1] === ERROR_LINES &&
        at(criterion, 'operator') === 'GreaterThan' &&
        // One error is enough, in every environment: a record past its event cap logs one and refuses the action (PL-41).
        at(criterion, 'threshold') === 0,
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

/** An enabled alert on the workspace fires on any count of decision lines held back (4D2e F8, PL-52), in any window. */
const decisionsSuppressedAlert: Check = (snapshot, _expected, add) => {
  for (const environment of ofType(snapshot, TYPES.environment)) {
    const alerted = workspaceAlerted(
      snapshot,
      'any',
      (criterion, alert) =>
        queryIs(at(criterion, 'query'), 'ContainerAppConsoleLogs', DECISIONS_SUPPRESSED_LINES, 'count()') &&
        totals(criterion) &&
        at(criterion, 'operator') === 'GreaterThan' &&
        at(criterion, 'threshold') === 0 &&
        watchesEveryWindow(alert, criterion),
    );
    if (!alerted) {
      add({
        rule: 'decisions-suppressed-alert',
        resource: environment.name,
        message:
          "needs an enabled alert on this deployment's workspace that fires on any log.suppressed line for spend_request.decided, in any window",
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

/**
 * A stateless SEV-1 alert on the workspace fires on any one of the login events copier's lines for a change made in the
 * login service behind Agent X, or a moment of its events passed (SA2), every window: exactly its list, so a line
 * added to it is never left out of the rule.
 */
const loginServiceAlert: Check = (snapshot, _expected, add) => {
  for (const environment of ofType(snapshot, TYPES.environment)) {
    const alerted = workspaceAlerted(
      snapshot,
      'stateless SEV-1',
      (criterion, alert) =>
        queryIs(at(criterion, 'query'), 'ContainerAppConsoleLogs', [LOGIN_SERVICE_LINES], 'count()') &&
        totals(criterion) &&
        at(criterion, 'operator') === 'GreaterThan' &&
        at(criterion, 'threshold') === 0 &&
        watchesEveryWindow(alert, criterion),
    );
    if (!alerted) {
      add({
        rule: 'login-service-alert',
        resource: environment.name,
        message: `needs an enabled stateless SEV-1 alert on this deployment's workspace that fires on any one of ${LOGIN_SERVICE_ALERT_EVENTS.join(', ')}, watching every window and firing on the first`,
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

/** An enabled alert on the workspace fires on the anchors' store unreadable after a start, long unread or unwritten, or never named (4D2e E, PL-58). */
const anchorStoreAlert: Check = (snapshot, _expected, add) => {
  for (const environment of ofType(snapshot, TYPES.environment)) {
    const alerted = workspaceAlerted(
      snapshot,
      'any',
      (criterion, alert) =>
        queryIs(at(criterion, 'query'), 'ContainerAppConsoleLogs', [ANCHOR_STORE_LINES], 'count()') &&
        totals(criterion) &&
        at(criterion, 'operator') === 'GreaterThan' &&
        at(criterion, 'threshold') === 0 &&
        watchesEveryWindow(alert, criterion),
    );
    if (!alerted) {
      add({
        rule: 'anchor-store-alert',
        resource: environment.name,
        message:
          "needs an enabled alert on this deployment's workspace that fires on any audit.anchor_store_unreadable, audit.anchor_store_unwritable, audit.anchor_store_read_failing or audit.anchor_store_not_set line, watching every window and firing on the first",
      });
    }
  }
};

/**
 * An enabled alert on the workspace fires on any one of these lines, watching every window and firing on the first:
 * the shape of the five checks above it, for the alerts added since. Those five stay as written while open pull
 * requests change the lines around them.
 */
const anyLineAlert =
  (rule: RuleId, lines: string, what: string): Check =>
  (snapshot, _expected, add) => {
    for (const environment of ofType(snapshot, TYPES.environment)) {
      const alerted = workspaceAlerted(
        snapshot,
        'any',
        (criterion, alert) =>
          queryIs(at(criterion, 'query'), 'ContainerAppConsoleLogs', [lines], 'count()') &&
          totals(criterion) &&
          at(criterion, 'operator') === 'GreaterThan' &&
          at(criterion, 'threshold') === 0 &&
          watchesEveryWindow(alert, criterion),
      );
      if (!alerted) {
        add({
          rule,
          resource: environment.name,
          message: `needs an enabled alert on this deployment's workspace that fires on any ${what} line, watching every window and firing on the first`,
        });
      }
    }
  };

/** The anchor check's lateness, each its own alert (4D2e E7): a deletion found past 24 hours, an old edit past 7 days. */
const dailyCheckAlert = anyLineAlert(
  'daily-check-alert',
  `where tostring(parse_json(Log).event) == "${DAILY_CHECK_LATE}"`,
  DAILY_CHECK_LATE,
);
const fullPassAlert = anyLineAlert(
  'full-pass-alert',
  `where tostring(parse_json(Log).event) == "${FULL_PASS_LATE}"`,
  FULL_PASS_LATE,
);

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

/** An enabled alert on the workspace fires on any organisation's records filling (partner S170). */
const recordsFillingAlert = anyLineAlert('records-filling-alert', RECORDS_FILLING_LINES, 'identity.records_filling');

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
        loginWorkspaceIds(snapshot),
      );
    if (!alerted) {
      add({
        rule: 'owner-login-alert',
        resource: server.name,
        message: `needs an enabled, stateless SEV-1 alert on this deployment's login alerts' workspace, every 15 minutes over the two days before, judging each line once 20 minutes old or once it arrives, that fires on the first window when ${OWNER_ROLE} logs in other than as this deployment's migration job starting in its environment, or that job starts with no login (ADR-012 §2)`,
      });
    }
  }
};

/**
 * An enabled, stateless SEV-1 alert on the login alerts' workspace fires when a
 * login as the owner, the server admin or the backup role is refused (MO2):
 * nothing got in, but someone may be trying. It counts by when a line arrived,
 * so a late one is still seen (refusedLoginQuery).
 */
const refusedLoginAlert: Check = (snapshot, _expected, add) => {
  for (const server of ofType(snapshot, TYPES.server)) {
    const query = refusedLoginQuery(String(at(server.properties, 'administratorLogin')));
    const alerted = workspaceAlerted(
      snapshot,
      'stateless SEV-1',
      (criterion, alert) =>
        at(alert.properties, 'overrideQueryTimeRange') === LATE_LINES_READ &&
        at(criterion, 'query') === query &&
        totals(criterion) &&
        at(criterion, 'operator') === 'GreaterThan' &&
        at(criterion, 'threshold') === 0 &&
        watchesEveryWindow(alert, criterion),
      loginWorkspaceIds(snapshot),
    );
    if (!alerted) {
      add({
        rule: 'refused-login-alert',
        resource: server.name,
        message: `needs an enabled, stateless SEV-1 alert on this deployment's login alerts' workspace, every 15 minutes over the two days before, that fires on any refused login as ${OWNER_ROLE}, the server admin or ${BACKUP_ROLE} arriving since the run before (MO2)`,
      });
    }
  }
};

/** The query of the alert on the server's lines stopping (MO6): none arrived over the hour, the cap's word aside. */
const LOGIN_LINES_QUERY = `union (PGSQLServerLogs | where ingestion_time() > ago(60m)), ${overCap(60)} | summarize Lines = count()`;

/**
 * An enabled, stateless SEV-1 alert on the login alerts' workspace fires when no server log line has arrived there
 * for an hour (MO6): a log setting rewritten (categories off, another workspace) leaves every login alert healthy
 * over a table nothing reaches, and the rule watch sees only a setting deleted. Run every 15 minutes, as the login
 * alerts are, over the hour the server's quietest gap (12 minutes on staging) never comes near.
 */
const loginLinesAlert: Check = (snapshot, _expected, add) => {
  const alerted = workspaceAlerted(
    snapshot,
    'stateless SEV-1',
    (criterion, alert) =>
      at(alert.properties, 'evaluationFrequency') === 'PT15M' &&
      at(alert.properties, 'windowSize') === 'PT1H' &&
      at(alert.properties, 'overrideQueryTimeRange') === 'P1D' &&
      at(criterion, 'query') === LOGIN_LINES_QUERY &&
      totals(criterion) &&
      at(criterion, 'operator') === 'LessThan' &&
      at(criterion, 'threshold') === 1 &&
      at(criterion, 'failingPeriods', 'numberOfEvaluationPeriods') === 1 &&
      at(criterion, 'failingPeriods', 'minFailingPeriodsToAlert') === 1,
    loginWorkspaceIds(snapshot),
  );
  // No server, no lines to miss: the other login alerts are checked a server at a time.
  if (!alerted && ofType(snapshot, TYPES.server).length > 0) {
    add({
      rule: 'login-lines-alert',
      resource: 'the login workspace',
      message:
        "needs an enabled, stateless SEV-1 alert on this deployment's login alerts' workspace, every 15 minutes, that fires when no database server log line has arrived for an hour and the workspace is not over its daily cap (MO6)",
    });
  }
};

/** An alert processing rule: one that removes action groups mutes every alert in its scope (MO2). */
const PROCESSING_RULE = 'Microsoft.AlertsManagement/actionRules';

/** One leaf of an activity log alert's condition: the event's field holds this value (Azure compares without case). */
const leaf = (field: string, equals: string): Readonly<Record<string, string>> => ({ field, equals });

/**
 * The two watches on the alert rules themselves (MO2), each an activity log
 * alert's whole condition: every change that succeeded to an alert rule of any
 * kind or to an action group, and a log alert rule Azure reports degraded or
 * unavailable. Exactly these: one more condition in `allOf` narrows what
 * fires, and one fewer change kind leaves that kind unwatched.
 */
const RULE_WATCHES: readonly { readonly what: string; readonly condition: unknown }[] = [
  {
    what: 'a change to any alert rule, action group or alert processing rule, or a diagnostic setting deleted',
    condition: {
      allOf: [
        leaf('category', 'Administrative'),
        leaf('status', 'Succeeded'),
        {
          anyOf: [
            ...[TYPES.alert, TYPES.metricAlert, TYPES.activityAlert, TYPES.actionGroup, PROCESSING_RULE].flatMap(
              (type) => [leaf('operationName', `${type}/write`), leaf('operationName', `${type}/delete`)],
            ),
            // Deploys never delete one; they rewrite every one, so its writes would be noise.
            leaf('operationName', `${TYPES.diagnostics}/delete`),
          ],
        },
      ],
    },
  },
  {
    what: 'a log alert rule degraded or unavailable',
    condition: {
      allOf: [
        leaf('category', 'ResourceHealth'),
        leaf('resourceType', TYPES.alert),
        { anyOf: ['Degraded', 'Unavailable'].map((status) => leaf('properties.currentHealthStatus', status)) },
      ],
    },
  },
];

/** The same JSON, whatever order an object's keys were written in. */
const canonical = (value: unknown): string =>
  JSON.stringify(value, (_key, inner: unknown) =>
    inner !== null && typeof inner === 'object' && !Array.isArray(inner)
      ? Object.fromEntries(Object.entries(inner).sort(([a], [b]) => a.localeCompare(b)))
      : inner,
  );

/**
 * Each watch on the alert rules (MO2) is an enabled activity log alert on this
 * deployment's resource group alone, with exactly its condition, a SEV-1
 * description ending in its runbook section, and only action groups of this
 * deployment that reach someone. Activity log alerts have no severity or
 * resolving of their own: each event notifies once.
 */
const alertRulesWatch: Check = (snapshot, _expected, add) => {
  const group = groupOf(snapshot);
  for (const { what, condition } of RULE_WATCHES) {
    const watched = ofType(snapshot, TYPES.activityAlert).some((alert) => {
      const groups = list(at(alert.properties, 'actions', 'actionGroups'));
      return (
        at(alert.properties, 'enabled') === true &&
        canonical(at(alert.properties, 'scopes')) === canonical([group]) &&
        canonical(at(alert.properties, 'condition')) === canonical(condition) &&
        /^SEV-1\. .+ Runbook: Incident-Response-Playbook\.md section [A-S]\.$/.test(
          String(at(alert.properties, 'description')),
        ) &&
        groups.length > 0 &&
        groups.every((one) => deliversAlerts(snapshot, at(one, 'actionGroupId')))
      );
    });
    if (!watched) {
      add({
        rule: 'alert-rules-watch',
        resource: 'the deployment',
        message: `needs an enabled activity log alert on this deployment's resource group, SEV-1 with its runbook section, reaching someone, on ${what} (MO2): an alert rule switched off, deleted or failing tells nobody`,
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

/** The job-start watch's identity's id, without case, in the deployment's resource group. */
const watchIdentityId = (snapshot: Snapshot, environment: string): string =>
  `${groupOf(snapshot)}/providers/${TYPES.identity}/${watchIdentityName(environment)}`.toLowerCase();

/** The job-start watch's role as a role assignment names it, without case. */
const watchRoleId = (snapshot: Snapshot): string => customRoleId(groupOf(snapshot), watchRoleName(groupOf(snapshot)));

/** Whether a trust is on the identity whose id (without case) is given. */
const trustOn = (trust: PredictedResource, identity: string): boolean =>
  trust.id.toLowerCase().startsWith(`${identity}/federatedidentitycredentials/`);

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
 * deployment but CI's role's (`release-access`), the audit exports' and the
 * anchors' (`evidence-store`) and the activity downloads' (`activity-downloads`)
 * gives Key Vault Secrets User on
 * one secret it writes, to an identity it creates, named a service principal:
 * no other role, and nothing at the vault, the resource group or the
 * subscription. Together they are exactly GRANTS, so no identity reads
 * another's secret and each can read its own; CI's identity isn't in GRANTS,
 * so it reads none. Nothing else in the deployment grants access (ACCESS_TYPE).
 */
/**
 * A lock grants nothing: `CanNotDelete` only makes Azure refuse a delete (the live server's, postgres.bicep, S185). Any
 * other level (`ReadOnly` would stop the server's own writes and key reads) stays refused as an unread access type.
 */
const deleteLock = (resource: PredictedResource): boolean =>
  resource.type === TYPES.lock &&
  typeof resource.properties === 'object' &&
  resource.properties !== null &&
  (resource.properties as { level?: unknown }).level === 'CanNotDelete';

const secretAccess: Check = (snapshot, _expected, add) => {
  for (const resource of snapshot.predictedResources) {
    if (
      ACCESS_TYPE.test(resource.type) &&
      resource.type !== TYPES.roleAssignment &&
      resource.type !== TYPES.roleDefinition &&
      // Azure's own refusals grant nothing, and are `azure-policy`'s to read.
      resource.type !== TYPES.policyDefinition &&
      resource.type !== TYPES.policyAssignment &&
      !deleteLock(resource)
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
  const keptAnchors = customRoleId(groupOf(snapshot), anchorRoleName(groupOf(snapshot)));
  const readAnchors = customRoleId(groupOf(snapshot), anchorReaderRoleName(groupOf(snapshot)));
  const readPlans = customRoleId(groupOf(snapshot), planReaderRoleName(groupOf(snapshot)));
  // The watch's role is `job-watch`'s to check.
  const stores = new Set([release, evidence, downloads, keptAnchors, readAnchors, readPlans, watchRoleId(snapshot)]);
  const granted = new Set<string>();
  for (const assignment of ofType(snapshot, TYPES.roleAssignment)) {
    const role = roleOf(assignment);
    if (stores.has(role)) continue;
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
  // The job-start watch's own trust is `job-watch`'s to check.
  const watch = watchIdentityId(snapshot, expected.environment);
  const trusts = ofType(snapshot, TYPES.trust).filter((trust) => !trustOn(trust, watch));
  for (const trust of trusts) {
    if (!releases.some((release) => trust.id.startsWith(`${release.id}/federatedIdentityCredentials/`))) {
      problem(trust.name, "must be on CI's identity: no other identity is signed in to from outside Azure");
    }
    trustProblems(
      trust,
      { subject: releaseSubject(expected.environment), who: "a job in this environment's GitHub environment" },
      problem,
    );
  }
  if (trusts.length !== 1) {
    problem('the deployment', `needs one trust, for CI's identity; the snapshot has ${String(trusts.length)}`);
  }
  releaseRoleProblems(snapshot, problem);
};

/** A trust in GitHub, for CI or the watch: GitHub's issuer, the one subject wanted and the token exchange alone. */
function trustProblems(
  trust: PredictedResource,
  wanted: { readonly subject: string; readonly who: string },
  problem: (resource: string, message: string) => void,
): void {
  const issuer = at(trust.properties, 'issuer');
  if (issuer !== GITHUB_ISSUER) {
    problem(trust.name, `must trust ${GITHUB_ISSUER} alone; it trusts ${JSON.stringify(issuer)}`);
  }
  const subject = at(trust.properties, 'subject');
  if (subject !== wanted.subject) {
    problem(trust.name, `must trust ${wanted.subject} alone (${wanted.who}); it trusts ${JSON.stringify(subject)}`);
  }
  const audiences = list(at(trust.properties, 'audiences'));
  if (audiences.length !== 1 || audiences[0] !== TOKEN_EXCHANGE) {
    problem(trust.name, `must accept the audience ${TOKEN_EXCHANGE} alone; it accepts ${JSON.stringify(audiences)}`);
  }
}

/** CI's custom role, half of `release-identity`: exactly one, named so, given in the resource group alone, allowing RELEASE_ACTIONS and no data action. */
function releaseRoleProblems(snapshot: Snapshot, problem: (resource: string, message: string) => void): void {
  const groups = ofType(snapshot, TYPES.group).map((group) => group.id);
  // The stores' roles are `evidence-store`'s and `activity-downloads`'s, which hold each to its data actions.
  const stores = new Set([
    evidenceRoleName(groupOf(snapshot)),
    anchorRoleName(groupOf(snapshot)),
    anchorReaderRoleName(groupOf(snapshot)),
    planReaderRoleName(groupOf(snapshot)),
    downloadsRoleName(groupOf(snapshot)),
    // The watch's is `job-watch`'s.
    watchRoleName(groupOf(snapshot)),
  ]);
  const roles = ofType(snapshot, TYPES.roleDefinition).filter((role) => !stores.has(role.name));
  const roleName = releaseRoleName(groupOf(snapshot));
  for (const role of roles) {
    if (role.name !== roleName) {
      problem(
        role.name,
        `must be named ${roleName} (names.bicep's releaseRoleName), so that no other role, a built-in one among them, passes as CI's`,
      );
    }
    roleShapeProblems(role, groups, RELEASE_ACTIONS, problem);
  }
  if (roles.length !== 1) {
    problem('the deployment', `needs one custom role, CI's; the snapshot has ${String(roles.length)}`);
  }
}

/** A custom role of CI's or the watch's: assignable in the resource group alone, exactly `allowed`, no data action. */
function roleShapeProblems(
  role: PredictedResource,
  groups: readonly string[],
  allowed: readonly string[],
  problem: (resource: string, message: string) => void,
): void {
  const scopes = list(at(role.properties, 'assignableScopes'));
  if (scopes.length !== 1 || !groups.includes(String(scopes[0]))) {
    problem(
      role.name,
      `must be assignable in this deployment's resource group alone; it says ${JSON.stringify(scopes)}`,
    );
  }
  const permissions = list(at(role.properties, 'permissions'));
  const actions = permissions.flatMap((entry) => list(at(entry, 'actions')));
  if (actionSet(actions) !== actionSet(allowed)) {
    problem(role.name, `must allow exactly ${allowed.join(', ')}; it allows ${actions.join(', ')}`);
  }
  const dataActions = permissions.flatMap((entry) => list(at(entry, 'dataActions')));
  if (dataActions.length > 0) {
    problem(
      role.name,
      `must allow no data action, which could read a secret's value; it allows ${dataActions.join(', ')}`,
    );
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

/**
 * The job-start watch (S175): a scheduled GitHub job that reads every job's
 * recent runs (deploy/azure/job-starts.ts). Its identity, the one names.bicep
 * calls job-watch, which no app or job runs as, is trusted for GitHub's issuer,
 * main's own subject (WATCH_SUBJECT, never CI's environment subject) and the
 * token exchange alone, once. Its one custom
 * role, named as `jobWatchRoleName` names it and assignable in the resource
 * group alone, allows WATCH_ACTIONS (reads) and no data action, and is given
 * once, on the resource group, to the watch's identity as a service principal,
 * and to no one else. That the watch holds no other role is `secret-access`'s.
 */
const jobWatch: Check = (snapshot, expected, add) => {
  const problem = (resource: string, message: string): void => {
    add({ rule: 'job-watch', resource, message });
  };
  const name = watchIdentityName(expected.environment);
  const watch = watchIdentityId(snapshot, expected.environment);
  if (!ofType(snapshot, TYPES.identity).some((identity) => identity.id.toLowerCase() === watch)) {
    problem('the deployment', `needs an identity for the job-start watch (${name})`);
  }
  for (const workload of workloadsIn(snapshot)) {
    const assigned = Object.keys(at(workload.identity, 'userAssignedIdentities') ?? {});
    if (assigned.some((id) => id.toLowerCase() === watch)) {
      problem(workload.name, "must not run as the job-start watch's identity, whose role is the watch's alone");
    }
  }
  const trusts = ofType(snapshot, TYPES.trust).filter((trust) => trustOn(trust, watch));
  for (const trust of trusts) {
    trustProblems(trust, { subject: WATCH_SUBJECT, who: 'a job on main, in no GitHub environment' }, problem);
  }
  if (trusts.length !== 1) {
    problem(
      'the deployment',
      `needs one trust for the job-start watch's identity; the snapshot has ${String(trusts.length)}`,
    );
  }
  const roleName = watchRoleName(groupOf(snapshot));
  const roles = ofType(snapshot, TYPES.roleDefinition).filter((role) => role.name === roleName);
  const groups = ofType(snapshot, TYPES.group).map((group) => group.id);
  for (const role of roles) roleShapeProblems(role, groups, WATCH_ACTIONS, problem);
  if (roles.length !== 1) {
    problem(
      'the deployment',
      `needs one custom role for the job-start watch; the snapshot has ${String(roles.length)}`,
    );
  }
  const given = ofType(snapshot, TYPES.roleAssignment).filter(
    (assignment) => roleOf(assignment) === watchRoleId(snapshot),
  );
  for (const assignment of given) {
    if (
      scopeOf(assignment).toLowerCase() !== groupOf(snapshot).toLowerCase() ||
      principalOf(snapshot, assignment)?.id.toLowerCase() !== watch
    ) {
      problem(
        assignment.name,
        "must give the job-start watch's role to the watch's identity (principalType ServicePrincipal) on this deployment's resource group alone",
      );
    }
  }
  if (given.length !== 1) {
    problem('the deployment', `must give the job-start watch's role once; it gives it ${String(given.length)} times`);
  }
};

/**
 * What no custom role of the deployment may allow (AZ2): writing a door (a route
 * config reaches an app whose ingress is internal, and needs nothing on the app,
 * Security-Handoff §13), the environment itself, a grant or a role, an Azure
 * Policy rule, its assignment or an exemption from one, a secret's listing, a
 * token minted as an app or a job (`getAuthToken`), the vault or its access
 * policies, a secret read (the vault is RBAC: `getSecret` is its data action), a
 * storage account rewritten or its keys listed or remade (shared-key access back
 * on opens every blob), a federated trust (a new way to sign in as an identity),
 * giving an identity to a resource (`assign`), or a lock's removal. Without case, as Azure
 * reads an action.
 */
const FORBIDDEN_ACTIONS: ReadonlySet<string> = new Set(
  [
    'Microsoft.App/managedEnvironments/httpRouteConfigs/write',
    'Microsoft.App/managedEnvironments/write',
    'Microsoft.App/containerApps/listSecrets/action',
    'Microsoft.App/jobs/listSecrets/action',
    'Microsoft.Authorization/roleAssignments/write',
    'Microsoft.Authorization/policyAssignments/write',
    'Microsoft.Authorization/policyAssignments/delete',
    'Microsoft.Authorization/policyExemptions/write',
    'Microsoft.Authorization/policyDefinitions/write',
    'Microsoft.Authorization/policyDefinitions/delete',
    'Microsoft.Authorization/roleDefinitions/write',
    'Microsoft.Authorization/locks/delete',
    'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write',
    'Microsoft.ManagedIdentity/userAssignedIdentities/assign/action',
    'Microsoft.App/containerApps/getAuthToken/action',
    'Microsoft.App/jobs/getAuthToken/action',
    'Microsoft.KeyVault/vaults/write',
    'Microsoft.KeyVault/vaults/accessPolicies/write',
    // The vault is RBAC, so reading a secret is this data action, not a listing (S188 review).
    'Microsoft.KeyVault/vaults/secrets/getSecret/action',
    // A storage account rewritten can switch shared-key access back on, and then its keys open every blob.
    'Microsoft.Storage/storageAccounts/write',
    'Microsoft.Storage/storageAccounts/listKeys/action',
    'Microsoft.Storage/storageAccounts/regenerateKey/action',
  ].map((action) => action.toLowerCase()),
);

/** Starting a job's run, as Azure names the action, without case. */
const JOB_START = 'microsoft.app/jobs/start/action';

/**
 * Every custom role the deployment defines (AZ2): no wildcard in any action or
 * data action (`Microsoft.App/jobs/*\/action` would add a secret's listing and
 * every action Azure adds later, Microsoft's jobs page), and none of
 * FORBIDDEN_ACTIONS. And only CI's role may start a job (AZ3): a start is the
 * job's secrets and identity (Microsoft's jobs page), and CI's is given on the
 * migration job alone (`release-access`), so no identity of ours but CI's can
 * start migrate, and none can start chain-restore or the operator's job; a
 * person starts those, as the subscription's owner. CI's and the watch's roles
 * are held to their exact lists besides (`release-identity`, `job-watch`): this
 * holds every role, a new one included.
 */
const roleActions: Check = (snapshot, _expected, add) => {
  const ci = releaseRoleName(groupOf(snapshot));
  for (const role of ofType(snapshot, TYPES.roleDefinition)) {
    const permissions = list(at(role.properties, 'permissions'));
    const allowed = permissions.flatMap((entry) => [...list(at(entry, 'actions')), ...list(at(entry, 'dataActions'))]);
    for (const action of allowed.map(String)) {
      if (action.includes('*') || FORBIDDEN_ACTIONS.has(action.toLowerCase())) {
        add({
          rule: 'role-actions',
          resource: role.name,
          message: `allows ${action}: no role of ours allows a wildcard or one of FORBIDDEN_ACTIONS: a door, the environment, a grant or a role, a policy rule, its assignment or exemption, a secret's listing, an app's token, the vault, a trust, an identity's assignment or a lock's removal`,
        });
      }
      if (action.toLowerCase() === JOB_START && role.name !== ci) {
        add({
          rule: 'role-actions',
          resource: role.name,
          message: `allows ${action}: only CI's role starts a job, and only the migration (release-access); a start uses the job's secrets`,
        });
      }
    }
  }
};

/** CI's writes a release makes (release.ts): the API written, the migration job written and started. */
const releaseWritesQuery = (identity: string, api: string, migrate: string): string =>
  [
    'AzureActivity',
    `where tostring(parse_json(Claims).xms_mirid) =~ "${identity}"`,
    `where not((OperationNameValue =~ "Microsoft.App/containerApps/write" and _ResourceId =~ "${api}") or (OperationNameValue in~ ("Microsoft.App/jobs/write", "Microsoft.App/jobs/start/action") and _ResourceId =~ "${migrate}"))`,
    'summarize Writes = count()',
  ].join(' | ');

/** The id of the deployment's app or job of this kind and work in its resource group, or '' for none. */
const workloadIdOf = (snapshot: Snapshot, type: string, workload: string): string =>
  ofType(snapshot, type).find(
    (found) =>
      found.id.toLowerCase().startsWith(`${groupOf(snapshot)}/providers/`.toLowerCase()) &&
      jobWorkloadOf(found.name) === workload,
  )?.id ?? '';

/**
 * A stateless SEV-1 alert on the main workspace fires on anything CI's identity
 * does but a release's three writes (AZ2): any other write, delete or action, or
 * one of the three on another resource, refused or not. Read from the sign-in's
 * own claim naming the identity, the hour before every 15 minutes, as the
 * activity log reaches the workspace late; one line is enough.
 */
const releaseWritesAlert: Check = (snapshot, expected, add) => {
  const identity =
    ofType(snapshot, TYPES.identity).find(
      (found) => found.id.toLowerCase() === releaseIdentityId(snapshot, expected.environment),
    )?.id ?? '';
  const wanted = releaseWritesQuery(
    identity,
    workloadIdOf(snapshot, TYPES.app, 'api'),
    workloadIdOf(snapshot, TYPES.job, 'migrate'),
  ).toLowerCase();
  const alerted = workspaceAlerted(
    snapshot,
    'stateless SEV-1',
    (criterion, alert) =>
      identity !== '' &&
      String(at(criterion, 'query')).toLowerCase() === wanted &&
      totals(criterion) &&
      at(criterion, 'operator') === 'GreaterThan' &&
      at(criterion, 'threshold') === 0 &&
      at(alert.properties, 'evaluationFrequency') === 'PT15M' &&
      at(alert.properties, 'windowSize') === 'PT1H' &&
      at(criterion, 'failingPeriods', 'numberOfEvaluationPeriods') === 1 &&
      at(criterion, 'failingPeriods', 'minFailingPeriodsToAlert') === 1,
  );
  if (!alerted) {
    add({
      rule: 'release-writes-alert',
      resource: 'the deployment',
      message:
        "needs an enabled stateless SEV-1 alert on this deployment's workspace, every 15 minutes over the hour before, that fires on any activity-log line by CI's identity but a release's write of the API, write of the migration job and start of it",
    });
  }
};

/** A field an Azure Policy condition reads, as these checks can read it: a value, or none for a missing field. */
type PolicyValue = unknown;

/** One element of an array a `count` walks, and the alias that names it (`…containers[*].image` → `…containers[*]`). */
interface PolicyScope {
  readonly prefix: string;
  readonly element: unknown;
}

/** A condition these checks can't read: the rule is refused rather than judged wrongly. */
class UnreadCondition extends Error {}

/** Azure Policy's `like`: one `*` at most, without case. */
export function policyLike(value: unknown, pattern: unknown): boolean {
  if (typeof value !== 'string' || typeof pattern !== 'string') return false;
  const [before, after, ...more] = pattern.toLowerCase().split('*');
  if (more.length > 0) throw new UnreadCondition(`like with more than one wildcard: ${pattern}`);
  const text = value.toLowerCase();
  if (after === undefined) return text === before;
  return text.length >= (before ?? '').length + after.length && text.startsWith(before ?? '') && text.endsWith(after);
}

/** Azure Policy's equality: strings without case, anything else exactly. */
const policySame = (value: unknown, wanted: unknown): boolean =>
  typeof value === 'string' && typeof wanted === 'string'
    ? value.toLowerCase() === wanted.toLowerCase()
    : value === wanted;

/**
 * What a field names on a resource (Microsoft.App's aliases are its properties'
 * paths), or undefined when it isn't there. Inside a `count`, its own array's
 * alias names the element being counted.
 */
function policyFieldOf(resource: PredictedResource, field: string, scope?: PolicyScope): PolicyValue {
  if (field === 'type') return resource.type;
  if (field === 'name') return resource.name;
  const inScope = scope !== undefined && field.startsWith(scope.prefix);
  const path = inScope ? field.slice(scope.prefix.length) : field;
  if (!inScope && !path.toLowerCase().startsWith(`${resource.type.toLowerCase()}/`)) return undefined;
  const rest = inScope ? path : path.slice(resource.type.length + 1);
  if (rest.includes('[*]')) throw new UnreadCondition(`an array field outside a count: ${field}`);
  const keys = rest.split('.').filter((key) => key !== '');
  return inScope ? at(scope.element, ...keys) : at(resource.properties, ...keys);
}

/** A leaf condition's test on one value. */
function policyCompare(value: PolicyValue, condition: Readonly<Record<string, unknown>>): boolean {
  const known: Readonly<Record<string, (wanted: unknown) => boolean>> = {
    equals: (wanted) => value !== undefined && policySame(value, wanted),
    notEquals: (wanted) => !(value !== undefined && policySame(value, wanted)),
    like: (wanted) => policyLike(value, wanted),
    notLike: (wanted) => !policyLike(value, wanted),
    notContains: (wanted) =>
      !(typeof value === 'string' && typeof wanted === 'string' && value.toLowerCase().includes(wanted.toLowerCase())),
    exists: (wanted) => (value !== undefined) === (wanted === true || wanted === 'true'),
    greater: (wanted) => typeof value === 'number' && typeof wanted === 'number' && value > wanted,
    in: (wanted) => list(wanted).some((each) => policySame(value, each)),
    notIn: (wanted) => !list(wanted).some((each) => policySame(value, each)),
  };
  const operators = Object.keys(condition).filter((key) => key !== 'field' && key !== 'count');
  const [operator, ...more] = operators;
  const test = operator === undefined ? undefined : known[operator];
  if (operator === undefined || more.length > 0 || test === undefined) {
    throw new UnreadCondition(`an operator these checks don't read: ${operators.join(', ')}`);
  }
  return test(condition[operator]);
}

/**
 * Whether an Azure Policy condition matches a resource (and so, with Deny, Azure
 * refuses it): `allOf`, `anyOf`, `not`, a field's test, or a `count` of an
 * array's elements matching its `where`. Anything else is UnreadCondition.
 */
function policyMatches(condition: unknown, resource: PredictedResource, scope?: PolicyScope): boolean {
  const object = (condition ?? {}) as Readonly<Record<string, unknown>>;
  if ('allOf' in object) return list(object.allOf).every((each) => policyMatches(each, resource, scope));
  if ('anyOf' in object) return list(object.anyOf).some((each) => policyMatches(each, resource, scope));
  if ('not' in object) return !policyMatches(object.not, resource, scope);
  if ('count' in object) {
    const field = text(at(object.count, 'field'));
    const cut = field.indexOf('[*]');
    if (cut < 0 || field.slice(cut + 3).includes('[*]')) throw new UnreadCondition(`a count over ${field}`);
    const prefix = field.slice(0, cut + 3);
    const array = list(policyFieldOf(resource, field.slice(0, cut), scope));
    const where = at(object.count, 'where');
    const counted = array.filter(
      (element) => where === undefined || policyMatches(where, resource, { prefix, element }),
    ).length;
    return policyCompare(counted, object);
  }
  if (typeof object.field !== 'string') throw new UnreadCondition('a condition with no field');
  return policyCompare(policyFieldOf(resource, object.field, scope), object);
}

/** The most replicas any app runs in any environment (production's Zitadel, 4D2e D12): Azure refuses more. */
const MOST_APP_REPLICAS = 4;

/**
 * Azure's own refusals (AZ2, modules/guardrails.bicep), by the part of the name
 * after `agentx-<environment>-`, each with bad examples it must refuse, made
 * from the deployment's own API app or migration job: so a rule whose alias or
 * value is wrong, and refuses nothing, is caught here rather than by an attacker.
 */
const GUARDRAILS: Readonly<
  Record<string, readonly (readonly [workload: string, change: Readonly<Record<string, unknown>>])[]>
> = {
  'apps-internal': [['api', { 'configuration.ingress.external': true }]],
  'apps-https': [['api', { 'configuration.ingress.allowInsecure': true }]],
  images: [
    ['api', { 'template.containers.0.image': 'ghcr.io/shahbaz242630/agent-x:latest' }],
    // Zitadel's own by tag alone: only the digest's own condition refuses it.
    ['api', { 'template.containers.0.image': 'ghcr.io/zitadel/zitadel:latest' }],
    ['migrate', { 'template.containers.0.image': 'ghcr.io/zitadel/zitadel-login:latest' }],
    ['api', { 'template.containers.0.image': `docker.io/library/busybox@sha256:${'0'.repeat(64)}` }],
    ['api', { 'template.initContainers': [{ image: `docker.io/library/busybox@sha256:${'0'.repeat(64)}` }] }],
    ['api', { 'template.initContainers': [{ image: 'ghcr.io/zitadel/zitadel:latest' }] }],
    ['migrate', { 'template.initContainers': [{ image: 'ghcr.io/zitadel/zitadel:latest' }] }],
    ['migrate', { 'template.containers.0.image': `ghcr.io/shahbaz242630/agent-x-evil@sha256:${'0'.repeat(64)}` }],
    ['migrate', { 'template.initContainers': [{ image: `docker.io/library/busybox@sha256:${'0'.repeat(64)}` }] }],
  ],
  'jobs-by-hand': [
    ['migrate', { 'configuration.triggerType': 'Schedule' }],
    ['migrate', { 'configuration.manualTriggerConfig.parallelism': 2 }],
    ['migrate', { 'configuration.manualTriggerConfig.replicaCompletionCount': 2 }],
  ],
  'app-replicas': [
    ['api', { 'template.scale.maxReplicas': MOST_APP_REPLICAS + 1 }],
    ['jobs', { 'template.scale.maxReplicas': 2 }],
  ],
  'allowed-types': [['', {}]],
};

/**
 * The types Azure lets be made on the resource group (AZ2): every type the
 * deployments create (policy.test.ts holds this to staging's snapshot, a load
 * run's and Stage G's included) and the deployments' own records. A type
 * the deployment adds and this leaves out is refused by Azure, which the rule's
 * own run over the snapshot catches; one this names and nothing makes is one
 * more door, caught here.
 */
export const ALLOWED_TYPES: readonly string[] = [
  'Microsoft.App/containerApps',
  'Microsoft.App/jobs',
  'Microsoft.App/managedEnvironments',
  'Microsoft.App/managedEnvironments/httpRouteConfigs',
  'Microsoft.App/managedEnvironments/managedCertificates',
  'Microsoft.Authorization/locks',
  'Microsoft.Authorization/policyAssignments',
  'Microsoft.Authorization/policyDefinitions',
  'Microsoft.Authorization/roleAssignments',
  'Microsoft.Authorization/roleDefinitions',
  'Microsoft.Communication/communicationServices',
  'Microsoft.Communication/emailServices',
  'Microsoft.Communication/emailServices/domains',
  'Microsoft.Consumption/budgets',
  'Microsoft.DBforPostgreSQL/flexibleServers',
  'Microsoft.DBforPostgreSQL/flexibleServers/configurations',
  'Microsoft.Insights/actionGroups',
  // #627's activity-log alerts (rules changed, rules unhealthy), allowed before they land: global, with tags, so
  // Indexed judges them, and a list that waited would refuse the foundation that brings them.
  'Microsoft.Insights/activityLogAlerts',
  'Microsoft.Insights/diagnosticSettings',
  'Microsoft.Insights/metricAlerts',
  'Microsoft.Insights/scheduledQueryRules',
  'Microsoft.Insights/workbooks',
  'Microsoft.KeyVault/vaults',
  'Microsoft.KeyVault/vaults/secrets',
  'Microsoft.ManagedIdentity/userAssignedIdentities',
  'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials',
  'Microsoft.Network/dnsResolverDomainLists',
  'Microsoft.Network/dnsResolverPolicies',
  'Microsoft.Network/dnsResolverPolicies/dnsSecurityRules',
  'Microsoft.Network/dnsResolverPolicies/virtualNetworkLinks',
  'Microsoft.Network/networkSecurityGroups',
  'Microsoft.Network/privateDnsZones',
  'Microsoft.Network/privateDnsZones/virtualNetworkLinks',
  'Microsoft.Network/virtualNetworks',
  'Microsoft.OperationalInsights/workspaces',
  'Microsoft.OperationalInsights/workspaces/savedSearches',
  'Microsoft.Resources/deployments',
  'Microsoft.Resources/resourceGroups',
  'Microsoft.Storage/storageAccounts',
  'Microsoft.Storage/storageAccounts/blobServices',
  'Microsoft.Storage/storageAccounts/blobServices/containers',
  'Microsoft.Storage/storageAccounts/managementPolicies',
];

/** A copy of a resource with each `path` (dotted, a number an array's index) set to its value. */
function changedCopy(resource: PredictedResource, change: Readonly<Record<string, unknown>>): PredictedResource {
  const copy = structuredClone(resource) as { properties?: unknown } & PredictedResource;
  for (const [path, value] of Object.entries(change)) {
    const keys = path.split('.');
    const last = keys.pop() ?? '';
    let place = copy.properties as Record<string, unknown>;
    for (const key of keys) {
      place[key] ??= {};
      place = place[key] as Record<string, unknown>;
    }
    place[last] = value;
  }
  return copy;
}

/**
 * The bad examples of one guardrail, from the deployment's API app and migration
 * job: for the jobs app's cap, the API renamed as the jobs app; for the types
 * allowed, a virtual machine.
 */
function badExamples(snapshot: Snapshot, guardrail: string): readonly PredictedResource[] {
  const api = ofType(snapshot, TYPES.app).find((found) => jobWorkloadOf(found.name) === 'api');
  const migrate = ofType(snapshot, TYPES.job).find((found) => jobWorkloadOf(found.name) === 'migrate');
  return (GUARDRAILS[guardrail] ?? []).flatMap(([workload, change]) => {
    if (guardrail === 'allowed-types') {
      return [{ id: '/a/virtual/machine', type: 'Microsoft.Compute/virtualMachines', name: 'vm', apiVersion: '' }];
    }
    const from = workload === 'migrate' ? migrate : api;
    if (from === undefined) return [];
    const renamed = workload === 'jobs' ? { ...from, name: from.name.replace(/-api$/, '-jobs') } : from;
    return [changedCopy(renamed, change)];
  });
}

/**
 * What Azure must let through besides what the deployment ships: CI's release (a
 * PATCH of the containers alone, release.ts), with no ingress, trigger, scale or
 * replica fields, so a rule that matched a missing field would refuse every
 * release; and the load test's image by digest (D2c), with the API at the most
 * replicas any environment runs.
 */
function mustPass(snapshot: Snapshot): readonly PredictedResource[] {
  const ours = [...ofType(snapshot, TYPES.app), ...ofType(snapshot, TYPES.job)].filter((found) =>
    ['api', 'migrate'].includes(jobWorkloadOf(found.name)),
  );
  return [
    ...ours.flatMap((found) => [
      { ...found, properties: { template: { containers: [{ image: at(containersOf(found)[0], 'image') }] } } },
      changedCopy(found, {
        'template.containers.0.image': `ghcr.io/shahbaz242630/agent-x-load@sha256:${'0'.repeat(64)}`,
        ...(found.type === TYPES.app ? { 'template.scale.maxReplicas': MOST_APP_REPLICAS } : {}),
      }),
    ]),
    // #627's activity-log alert, global with tags (so Indexed judges it), before it is in the snapshot.
    {
      id: `${groupOf(snapshot)}/providers/Microsoft.Insights/activityLogAlerts/coming`,
      type: 'Microsoft.Insights/activityLogAlerts',
      name: 'an activity-log alert',
      apiVersion: '2026-01-01',
      location: 'global',
    },
  ];
}

/** What is wrong with one guardrail's definition and its assignment, or nothing. */
function guardrailShapeProblems(
  snapshot: Snapshot,
  definition: PredictedResource,
  problem: (resource: string, message: string) => void,
): void {
  const properties = definition.properties;
  if (
    !/^\/subscriptions\/[^/]+\/providers\/Microsoft\.Authorization\/policyDefinitions\/[^/]+$/i.test(definition.id) ||
    at(properties, 'policyType') !== 'Custom' ||
    at(properties, 'mode') !== 'Indexed' ||
    text(at(properties, 'policyRule', 'then', 'effect')).toLowerCase() !== 'deny' ||
    !isEmpty(at(properties, 'parameters'))
  ) {
    problem(
      definition.name,
      'must be a custom rule of the subscription, Indexed, with the Deny effect and no parameters, so Azure refuses what it matches',
    );
  }
  const given = ofType(snapshot, TYPES.policyAssignment).filter(
    (assignment) => text(at(assignment.properties, 'policyDefinitionId')).toLowerCase() === definition.id.toLowerCase(),
  );
  const atGroup = given.filter(
    (assignment) =>
      assignment.id.toLowerCase() ===
        `${groupOf(snapshot)}/providers/${TYPES.policyAssignment}/${assignment.name}`.toLowerCase() &&
      at(assignment.properties, 'enforcementMode') === 'Default' &&
      isEmpty(at(assignment.properties, 'notScopes')) &&
      list(at(assignment.properties, 'nonComplianceMessages')).some((entry) => text(at(entry, 'message')) !== ''),
  );
  if (given.length !== 1 || atGroup.length !== 1) {
    problem(
      definition.name,
      "must be given once, on this deployment's resource group, enforced, with nothing left out of it and the words a refusal gets back",
    );
  }
}

/**
 * What one guardrail's rule makes of the deployment, `mustPass` and its bad examples. Indexed, as Azure judges it:
 * only a resource with a location (the types with tags and a location), so a child or an extension the rules never
 * see, a vault secret or a role assignment, isn't judged here either.
 */
function guardrailRuleProblems(
  snapshot: Snapshot,
  guardrail: string,
  definition: PredictedResource,
  problem: (resource: string, message: string) => void,
): void {
  const condition = at(definition.properties, 'policyRule', 'if');
  try {
    const refused = [...snapshot.predictedResources, ...mustPass(snapshot)].filter(
      (resource) => resource.location !== undefined && policyMatches(condition, resource),
    );
    for (const resource of refused) {
      problem(
        definition.name,
        `refuses ${resource.name}, which this deployment ships or a release sends: Azure would refuse our own deploy`,
      );
    }
    if (badExamples(snapshot, guardrail).some((resource) => !policyMatches(condition, resource))) {
      problem(definition.name, `lets through what it is for (${guardrail}): its condition matches nothing it should`);
    }
  } catch (error) {
    if (!(error instanceof UnreadCondition)) throw error;
    problem(
      definition.name,
      `holds a condition these checks can't read (${error.message}), so none can say it's right`,
    );
  }
}

/**
 * Azure's own refusals (AZ2, modules/guardrails.bicep): each of GUARDRAILS once,
 * named `agentx-<environment>-<guardrail>`, a custom Indexed Deny rule given
 * once on the resource group, enforced. Each rule refuses nothing the
 * deployment ships nor anything of `mustPass`, and refuses each of its bad
 * examples; the types allowed are exactly ALLOWED_TYPES.
 * Nothing else in the deployment is a policy rule or an assignment of one.
 */
const azurePolicy: Check = (snapshot, expected, add) => {
  const problem = (resource: string, message: string): void => {
    add({ rule: 'azure-policy', resource, message });
  };
  const names = new Set(Object.keys(GUARDRAILS).map((guardrail) => `agentx-${expected.environment}-${guardrail}`));
  for (const resource of [...ofType(snapshot, TYPES.policyDefinition), ...ofType(snapshot, TYPES.policyAssignment)]) {
    if (!names.has(resource.name)) problem(resource.name, 'is no rule of modules/guardrails.bicep: one no check reads');
  }
  for (const guardrail of Object.keys(GUARDRAILS)) {
    const name = `agentx-${expected.environment}-${guardrail}`;
    const found = ofType(snapshot, TYPES.policyDefinition).filter((definition) => definition.name === name);
    const definition = found[0];
    if (found.length !== 1 || definition === undefined) {
      problem('the deployment', `needs the Azure Policy rule ${name} once; the snapshot has ${String(found.length)}`);
      continue;
    }
    guardrailShapeProblems(snapshot, definition, problem);
    guardrailRuleProblems(snapshot, guardrail, definition, problem);
  }
  const typesRule = ofType(snapshot, TYPES.policyDefinition).find(
    (definition) => definition.name === `agentx-${expected.environment}-allowed-types`,
  );
  const allowed = list(at(typesRule?.properties, 'policyRule', 'if', 'not', 'in')).map((type) => text(type));
  if (typesRule !== undefined && actionSet(allowed) !== actionSet(ALLOWED_TYPES)) {
    problem(typesRule.name, `must allow exactly ${ALLOWED_TYPES.join(', ')}; it allows ${allowed.join(', ')}`);
  }
};

/** An image named by digest: a tag can be moved to another image, a digest can't (SEC-SC-02). */
const PINNED_IMAGE = /@sha256:[0-9a-f]{64}$/;

/** How a job's configuration says it runs: started by hand, one replica per run, no retry, and a time limit. */
function runProblems(configuration: unknown, longest: number, problem: (message: string) => void): void {
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
  if (typeof timeout !== 'number' || timeout <= 0 || timeout > longest) {
    problem(`must give up after 1 to ${String(longest)} seconds (replicaTimeout); it says ${String(timeout)}`);
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
    sizeProblems(container, problem);
  }
}

/** A Consumption size's step: a quarter vCPU, with half a GiB of memory (512 MiB) for each. */
const CONSUMPTION_STEP = { cpu: 0.25, mebibytes: 512 } as const;

/** The Consumption profile's largest size, in steps: 4 vCPU and 8Gi. */
const CONSUMPTION_MOST_STEPS = 16;

/**
 * A container's size is one the Consumption profile offers (Microsoft Learn, "Containers in Azure Container Apps",
 * vCPU and memory allocation requirements, checked 13 Nov 2026): 0.25 vCPU with 0.5Gi, then each quarter vCPU more with
 * 0.5Gi more, up to 4 vCPU with 8Gi, memory always twice the vCPUs in GiB. Any other pair passes a what-if and fails
 * the deployment.
 */
function sizeProblems(container: unknown, problem: (message: string) => void): void {
  const cpu = at(container, 'resources', 'cpu');
  const memory = at(container, 'resources', 'memory');
  const steps = typeof cpu === 'number' ? cpu / CONSUMPTION_STEP.cpu : Number.NaN;
  const offered =
    Number.isInteger(steps) &&
    steps >= 1 &&
    steps <= CONSUMPTION_MOST_STEPS &&
    mebibytesOf(memory) === steps * CONSUMPTION_STEP.mebibytes;
  if (!offered) {
    problem(
      `must run at a size the Consumption profile offers (0.25 to 4 vCPU in quarters, with 2Gi for each vCPU); it says ${String(cpu)} vCPU and ${String(memory)}`,
    );
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
    // Stage G's step alone runs past the hour: one step a run, the soak's full hour and its margin (stageg.ts).
    const longest = jobWorkloadOf(job.name) === 'load-step' ? STAGE_G_JOB_SECONDS : LONGEST_RUN_SECONDS;
    runProblems(configuration, longest, problem);
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

/**
 * An app's ingress: internal, refusing plain http. An ingress left out is caught by the same two conditions: nothing
 * said is nothing that says false, and what isn't said here is Azure's to decide (a mutation pass showed a branch of its
 * own adds nothing). The API's jobs (4D2e D13) have none at all: they serve nothing, so nothing should reach them.
 */
function ingressProblems(ingress: unknown, servesNothing: boolean, problem: (message: string) => void): void {
  if (servesNothing) {
    if (ingress !== undefined && ingress !== null) {
      problem('must have no ingress: AGENTX_ROLE jobs serves nothing, so neither a door nor a neighbour may reach it');
    }
    return;
  }
  if (at(ingress, 'external') !== false) {
    problem('must say its ingress is internal (external false): the public doors are the route configs (G2e)');
  }
  if (at(ingress, 'allowInsecure') !== false) {
    problem('must refuse plain http (allowInsecure false), which peer-to-peer encryption already covers');
  }
}

/** An app's scale: no more replicas than `limit` allows where it has one, at least one, and no more kept than that. */
function scaleProblems(scale: unknown, limit: MostReplicas | undefined, problem: (message: string) => void): void {
  const most = at(scale, 'maxReplicas');
  const fewest = at(scale, 'minReplicas');
  if (limit !== undefined && !(typeof most === 'number' && most <= limit.most)) {
    const replicas = limit.most === 1 ? 'one replica' : `${String(limit.most)} replicas`;
    problem(`must run at most ${replicas} (maxReplicas ${String(limit.most)}): ${limit.why}; it says ${String(most)}`);
  }
  if (limit?.fewest !== undefined && !(typeof fewest === 'number' && fewest >= limit.fewest)) {
    problem(
      `must keep at least ${String(limit.fewest)} replicas running (minReplicas ${String(limit.fewest)}): ${limit.fewestWhy}; it says ${String(fewest)}`,
    );
  }
  if (typeof most !== 'number' || most < 1) {
    problem(`must be able to run a replica (maxReplicas at least 1); it says ${String(most)}`);
  }
  if (typeof fewest !== 'number' || fewest < 0 || (typeof most === 'number' && fewest > most)) {
    problem(`must keep no more replicas than it may run (minReplicas ${String(fewest)}, maxReplicas ${String(most)})`);
  }
}

/** An app's one container's settings where it runs the API (every API process is told AGENTX_ENV), or nothing. */
function apiSettingsOf(app: PredictedResource): ReadonlyMap<string, unknown> | undefined {
  const [container] = containersOf(app);
  const settings = settingsIn(container);
  return settings.has('AGENTX_ENV') ? settings : undefined;
}

/** The API's role, as its process reads it: `all` where none is set (settings.ts). */
const roleIn = (settings: ReadonlyMap<string, unknown>): unknown => settings.get('AGENTX_ROLE') ?? 'all';

/**
 * A whole-number setting as a count: `unset` where it isn't given, nothing where it's given as anything but digits (a
 * secret's reference carries no value), so a count that can't be read is said, never summed as NaN.
 */
function countIn(settings: ReadonlyMap<string, unknown>, name: string, unset?: number): number | undefined {
  if (!settings.has(name)) return unset;
  const value = settings.get(name);
  return typeof value === 'string' && /^[0-9]+$/.test(value) ? Number(value) : undefined;
}

/** How many `web` copies the API counts its limits for: one where none is set (settings.ts). */
const copiesIn = (settings: ReadonlyMap<string, unknown>): number | undefined =>
  countIn(settings, 'AGENTX_WEB_COPIES', 1);

/**
 * The apps that may run the API, by workload: `api`, and the `jobs` app (apps.bicep `jobsApp`, 4D2e D13). Only the
 * apps apps.bicep makes: an API app nothing names could hold the jobs, or a pool nobody counted on.
 */
const API_APPS: readonly string[] = ['api', 'jobs'];

/** A size as Container Apps writes one (`1Gi`, `512Mi`), in MiB; nothing for anything else. */
function mebibytesOf(size: unknown): number | undefined {
  const [, amount = '', unit = ''] = /^([0-9]+(?:[.][0-9]+)?)(Gi|Mi)$/.exec(text(size)) ?? [];
  return amount === '' ? undefined : Number(amount) * (unit === 'Gi' ? 1024 : 1);
}

/** The flag that sets Node's heap, as the API's command gives it. */
const HEAP_FLAG = '--max-old-space-size=';

/**
 * The API's heap, set by its command (4D2e D12): between half and three quarters of its container's memory, so its
 * counters (rate-limit.ts, about 92 MB with all four full) fit with room, and Node's own default (560 MiB under 1 GiB,
 * measured on the pinned base image) isn't left to decide it.
 */
function heapProblems(container: unknown, problem: (message: string) => void): void {
  const flag = list(at(container, 'command'))
    .map(text)
    .find((part) => part.startsWith(HEAP_FLAG));
  const heap = Number(flag?.slice(HEAP_FLAG.length));
  const memory = mebibytesOf(at(container, 'resources', 'memory'));
  if (memory === undefined || !Number.isInteger(heap) || heap < memory / 2 || heap > (memory * 3) / 4) {
    problem(
      `must start node with ${HEAP_FLAG}<MiB> between half and three quarters of its memory (${String(memory)} MiB), so its rate limits' counters fit with room; it says ${String(flag)}`,
    );
  }
}

/**
 * Across the apps running the API (4D2e D12): each one listed in API_APPS, exactly one holding the jobs (`jobs` or
 * `all`: two would run the copier twice, none would run no job), and never `all` beside `web`, as `all` counts its
 * rate limits as the only copy. Each at its own role (D13): the `jobs` app at AGENTX_ROLE jobs and no other, so the
 * app the doors reach always serves, and the one with no ingress never has to. Production runs split, `web` copies
 * beside the `jobs` app (StageD-Design: roles), which is what its anchors' keeper is given to (main.bicep).
 */
function apiAppsProblems(
  found: readonly PredictedResource[],
  environment: Expectations['environment'],
  add: (problem: Problem) => void,
): void {
  const apis = found.flatMap((app) => {
    const settings = apiSettingsOf(app);
    return settings === undefined ? [] : [{ app, role: roleIn(settings) }];
  });
  const problem = (resource: string, message: string): void => {
    add({ rule: 'apps', resource, message });
  };
  for (const { app } of apis.filter((api) => !API_APPS.includes(jobWorkloadOf(api.app.name)))) {
    problem(
      app.name,
      `runs the API, which only ${API_APPS.join(' and ')} may: an app nothing names could hold the jobs`,
    );
  }
  const holders = apis.filter(({ role }) => role === 'jobs' || role === 'all').length;
  if (apis.length > 0 && holders !== 1) {
    problem(
      'the deployment',
      `needs exactly one app holding the jobs (AGENTX_ROLE jobs or all); it has ${String(holders)}`,
    );
  }
  const roles = new Set(apis.map(({ role }) => role));
  if (roles.has('all') && roles.has('web')) {
    problem('the deployment', 'runs AGENTX_ROLE all beside web: all counts its rate limits as the only copy');
  }
  for (const { app, role } of apis.filter(
    ({ app, role }) => (jobWorkloadOf(app.name) === 'jobs') !== (role === 'jobs'),
  )) {
    problem(
      app.name,
      `runs AGENTX_ROLE ${String(role)}: the jobs app runs AGENTX_ROLE jobs, and only it, as the one with no ingress`,
    );
  }
  if (environment === 'production' && apis.length > 0 && !(roles.has('web') && roles.has('jobs'))) {
    problem(
      'the deployment',
      'must run the API split in production, web copies beside the jobs app (4D2e D13), whose identity alone keeps the anchors there',
    );
  }
}

/**
 * An app running the API, scaled as its role (4D2e D12): `web` runs exactly the copies it counts its rate limits for,
 * so each allows its share and no more; `jobs` exactly one, as the lease makes a second safe for most jobs but not the
 * copier; `all` holds the jobs and counts its limits as one copy, so at most one, and none while staging sleeps.
 */
function roleScaleProblems(
  settings: ReadonlyMap<string, unknown>,
  scale: unknown,
  problem: (message: string) => void,
): void {
  const role = roleIn(settings);
  const most = at(scale, 'maxReplicas');
  const fewest = at(scale, 'minReplicas');
  const exactly = (count: number, why: string): void => {
    if (most !== count || fewest !== count) {
      problem(
        `must run exactly ${String(count)} (minReplicas and maxReplicas ${String(count)}): ${why}; it says ${String(fewest)} to ${String(most)}`,
      );
    }
  };
  if (role === 'web') {
    const copies = copiesIn(settings);
    if (copies === undefined) problem('must give AGENTX_WEB_COPIES as a whole number, which its replicas are held to');
    else exactly(copies, 'AGENTX_WEB_COPIES, which each copy shares its rate limits by');
  } else if (role === 'jobs') {
    exactly(1, "the jobs keep to one copy, which the lease alone doesn't make safe for the copier");
  } else if (role === 'all') {
    if (most !== 1) {
      problem(`must run at most one replica (maxReplicas 1): AGENTX_ROLE all holds the jobs; it says ${String(most)}`);
    }
  } else {
    problem(`sets AGENTX_ROLE to ${String(role)}, which the API doesn't take: all, web or jobs`);
  }
}

/**
 * Every app that serves traffic (ADR-002 Amendment G2d): in this deployment's
 * environment, on Consumption, running the exact image it names, and **never a
 * public door** — the doors are the route configs (G2e), so an app whose ingress
 * is external is one reachable from the internet that nothing decided to
 * publish. Plain http is refused even inside the environment. The apps that
 * hold something one replica's keep to one (`ONE_REPLICA`), Zitadel to its
 * environment's most (`ZITADEL_COPIES`), the API scales as
 * its role (`roleScaleProblems`), and every app can
 * run at least one. Together they are the three apps a deployment needs, so a
 * dropped one is caught here rather than at the first deployment.
 */
const apps: Check = (snapshot, expected, add) => {
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
    const api = apiSettingsOf(app);
    ingressProblems(
      at(app.properties, 'configuration', 'ingress'),
      api !== undefined && roleIn(api) === 'jobs',
      problem,
    );
    const scale = at(app.properties, 'template', 'scale');
    scaleProblems(scale, mostReplicasOf(workload, expected.environment), problem);
    if (api !== undefined) {
      roleScaleProblems(api, scale, problem);
      heapProblems(containersOf(app)[0], problem);
    }
    containerProblems(app, problem);
  }
  apiAppsProblems(found, expected.environment, add);
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

/** Email's settings in a load run (D2c): its seeded admins have no address, so neither the API nor its jobs send any. */
function noEmailProblems(settings: ReadonlyMap<string, unknown>, problem: (message: string) => void): void {
  for (const name of [...settings.keys()].filter((setting) => setting.startsWith('AGENTX_EMAIL_'))) {
    problem(`sets ${name} in the load run (D2c): its seeded admins have no address, so it sends no email`);
  }
}

/** The API in a load run: exactly its size, connections and limits, as three `web` copies (4D2e D13), and no email. */
function apiInLoadRunProblems(container: unknown, problem: (message: string) => void): void {
  const settings = settingsIn(container);
  if (settings.get('AGENTX_ROLE') !== 'web' || settings.get('AGENTX_WEB_COPIES') !== LOAD_RUN.webCopies) {
    problem(
      `must run as ${LOAD_RUN.webCopies} web copies in the load run (4D2e D13: AGENTX_ROLE web, AGENTX_WEB_COPIES ${LOAD_RUN.webCopies}), beside the jobs app, the split it is measured as`,
    );
  }
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
  noEmailProblems(settings, problem);
}

/**
 * The API's jobs apart from it (4D2e D13): in a load run, at their size with their six connections, the log's cap
 * the API's, and no email; out of one, none of those.
 */
function jobsLoadProblems(container: unknown, loadRun: boolean, problem: (message: string) => void): void {
  const settings = settingsIn(container);
  if (!loadRun) {
    for (const name of Object.keys(LOAD_RUN.jobsSettings).filter((setting) => settings.has(setting))) {
      problem(`sets ${name}, which only the load run's jobs do (4D2e D13): out of it they keep their own`);
    }
    if (at(container, 'resources', 'cpu') === LOAD_RUN.jobsSize.cpu) {
      problem("runs at the load run's size out of a load run (4D2e D13): apps --load-run alone sets it");
    }
    return;
  }
  if (
    at(container, 'resources', 'cpu') !== LOAD_RUN.jobsSize.cpu ||
    at(container, 'resources', 'memory') !== LOAD_RUN.jobsSize.memory
  ) {
    problem(
      `must run at ${String(LOAD_RUN.jobsSize.cpu)} CPU and ${LOAD_RUN.jobsSize.memory} in the load run (4D2e D13), the size it is measured at`,
    );
  }
  if (settings.get('AGENTX_DB_JOBS_POOL_MAX') !== LOAD_RUN.jobsPool) {
    problem(`must keep ${LOAD_RUN.jobsPool} connections in the load run (4D2e D13), the size it is measured at`);
  }
  for (const [name, wanted] of Object.entries(LOAD_RUN.jobsSettings).filter(
    ([setting, value]) => settings.get(setting) !== value,
  )) {
    problem(`must set ${name} to ${wanted} in the load run (4D2e D13), as the API's, since they log for the same run`);
  }
  noEmailProblems(settings, problem);
}

/** The API's and its jobs' containers, in a load run or out of one. */
function apiLoadProblems(
  app: PredictedResource,
  { loadRun, staging }: { readonly loadRun: boolean; readonly staging: boolean },
  problem: (message: string) => void,
): void {
  for (const container of containersOf(app)) {
    if (jobWorkloadOf(app.name) === 'jobs') jobsLoadProblems(container, loadRun, problem);
    else if (loadRun) apiInLoadRunProblems(container, problem);
    else apiOutOfLoadRunProblems(container, staging, problem);
  }
}

/**
 * The load test's run (D2c, PL-38), as `LOAD_RUN` says: on staging alone,
 * its three jobs together or none, each on the load image, and the API at the
 * load run's size and limits exactly while they are there, never otherwise.
 * The API runs split while they are there (4D2e D13), its jobs in the `jobs`
 * app; on staging out of one there is no `jobs` app, as its one API holds the
 * jobs and sleeps (StageD-Design: a `jobs` app would pass the $60 alarm).
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
  const loadRun = found.length > 0;
  const apis = ofType(snapshot, TYPES.app).filter((app) => API_APPS.includes(jobWorkloadOf(app.name)));
  for (const api of apis) {
    apiLoadProblems(api, { loadRun, staging }, (message) => {
      problem(api.name, message);
    });
  }
  jobsAppCountProblems(
    apis.filter((app) => jobWorkloadOf(app.name) === 'jobs').length,
    { loadRun, staging },
    (message) => {
      problem('the deployment', message);
    },
  );
};

/** The jobs app once in a load run (4D2e D13), and never on staging out of one, where its one API holds the jobs. */
function jobsAppCountProblems(
  count: number,
  { loadRun, staging }: { readonly loadRun: boolean; readonly staging: boolean },
  problem: (message: string) => void,
): void {
  if (loadRun && count !== 1) {
    problem(`needs the jobs app once in a load run (4D2e D13); the snapshot has ${String(count)}`);
  }
  if (!loadRun && staging && count > 0) {
    problem(
      'runs the jobs app on staging out of a load run: its one API holds the jobs and sleeps (4D2e D13), and a jobs app always running passes the $60 alarm',
    );
  }
}

/** Each database host a workload names: AGENTX_DB_HOST, and a load job's AGENTX_LOAD_DB_HOST. */
const databaseHostsOf = (workload: PredictedResource): string[] =>
  containersOf(workload).flatMap((container) =>
    list(at(container, 'env'))
      .filter((entry) => ['AGENTX_DB_HOST', 'AGENTX_LOAD_DB_HOST'].includes(text(at(entry, 'name'))))
      .map((entry) => text(at(entry, 'value'))),
  );

/** How each of Stage G's jobs runs: its script, and its part as its one argument. */
const STAGE_G_COMMAND = ['node', 'tooling/load/stageg-job.ts'];

/**
 * Stage G's throwaway copy (4D2e; tooling/load/throwaway.ts): staging's own database is never a run's target. The
 * API, its jobs app and every load job reach one database alike: staging's own server, or, in a load run only, a copy
 * named as one; every other workload staging's own. On a copy, and only there, Stage G's three jobs once each, running
 * their own script and part; the copy's own anchors container, named for that copy, its anchors' role given to the
 * jobs app alone (its settings are evidence-store's, its downloads activity-downloads', its logins workload-secrets').
 */
const loadDatabase: Check = (snapshot, _expected, add) => {
  const problem = (resource: string, message: string): void => {
    add({ rule: 'load-database', resource, message });
  };
  const servers = ofType(snapshot, TYPES.server);
  const own = servers.length === 1 ? `${servers[0]?.name ?? ''}${POSTGRES_HOST_SUFFIX}` : undefined;
  const reaching = workloadsIn(snapshot).filter(
    (workload) => runsApi(workload) || isLoadJob(jobWorkloadOf(workload.name)),
  );
  const targets = [...new Set(reaching.flatMap(databaseHostsOf))];
  const copy = stageGCopyIn(snapshot);
  if (targets.length > 1) {
    problem(
      'the deployment',
      `must reach one database from the API, its jobs app and the load jobs; they reach ${targets.join(', ')}`,
    );
  }
  for (const target of targets.filter(
    (host) => own !== undefined && host !== own && throwawayServerOfHost(host) === undefined,
  )) {
    problem(
      'the deployment',
      `reaches ${target}, which is neither staging's own server nor a Stage G copy (${THROWAWAY_NAME_RULE}${POSTGRES_HOST_SUFFIX})`,
    );
  }
  if (
    copy !== undefined &&
    !ofType(snapshot, TYPES.job).some((job) => LOAD_RUN.jobs.includes(jobWorkloadOf(job.name)))
  ) {
    problem(
      'the deployment',
      "reaches Stage G's copy out of a load run: apps --load-run --load-database alone points the API there",
    );
  }
  for (const workload of workloadsIn(snapshot).filter((each) => !reaching.includes(each))) {
    if (own !== undefined && databaseHostsOf(workload).some((host) => host !== own)) {
      problem(
        workload.name,
        `must reach staging's own server, ${own}: only the API, its jobs app and the load jobs reach Stage G's copy`,
      );
    }
  }
  stageGJobsProblems(snapshot, copy, problem);
  copyAnchorsProblems(snapshot, copy, problem);
};

/** Stage G's jobs: on a copy, each once, running its own script and part; never without one. */
function stageGJobsProblems(
  snapshot: Snapshot,
  copy: string | undefined,
  problem: (resource: string, message: string) => void,
): void {
  const found = ofType(snapshot, TYPES.job).filter((job) => isStageGJob(jobWorkloadOf(job.name)));
  if (copy === undefined && found.length > 0) {
    problem(
      'the deployment',
      "runs Stage G's jobs with no throwaway copy: they exist only on its run (apps --load-run --load-database)",
    );
  }
  for (const workload of copy === undefined ? [] : Object.keys(STAGE_G_JOBS)) {
    const count = found.filter((job) => jobWorkloadOf(job.name) === workload).length;
    if (count !== 1)
      problem('the deployment', `needs the ${workload} job once on Stage G's copy; the snapshot has ${String(count)}`);
  }
  for (const job of found) {
    const part = jobWorkloadOf(job.name).replace(/^load-/, '');
    const run = JSON.stringify([...STAGE_G_COMMAND, '|', part]);
    for (const container of containersOf(job)) {
      if (JSON.stringify([...list(at(container, 'command')), '|', ...list(at(container, 'args'))]) !== run) {
        problem(job.name, `must run ${STAGE_G_COMMAND.join(' ')} ${part} and nothing else`);
      }
    }
  }
}

/** The copy's own anchors: its container in the write-once store, its anchors' role there to the jobs app alone. */
function copyAnchorsProblems(
  snapshot: Snapshot,
  copy: string | undefined,
  problem: (resource: string, message: string) => void,
): void {
  const containers = copyAnchorsContainers(snapshot);
  const wanted = copy === undefined ? undefined : copyAnchorsOf(copy);
  for (const container of containers.filter((each) => nameOf(each) !== wanted)) {
    problem(container.name, 'must be the anchors container of the Stage G copy the API reaches, and only on its run');
  }
  if (wanted !== undefined && !containers.some((container) => nameOf(container) === wanted)) {
    problem('the deployment', `needs Stage G's copy's own anchors container, ${wanted}: never staging's audit-anchors`);
  }
  const ids = new Set(containers.map((container) => container.id));
  const role = customRoleId(groupOf(snapshot), anchorRoleName(groupOf(snapshot)));
  const given = ofType(snapshot, TYPES.roleAssignment).filter((assignment) => ids.has(scopeOf(assignment)));
  for (const assignment of given) {
    if (roleOf(assignment) !== role || workloadOf(principalOf(snapshot, assignment)?.name ?? '') !== 'jobs') {
      problem(assignment.name, "must give the anchors' role on the copy's anchors to the jobs app's identity alone");
    }
  }
  if (wanted !== undefined && given.length !== 1) {
    problem(
      'the deployment',
      `must give the anchors' role on ${wanted} once, to the jobs app; it gives ${String(given.length)}`,
    );
  }
}

/** The connections an app running the API may hold, by its role: two of each copy's pool, for a deploy's overlap. */
function apiConnections(app: PredictedResource, settings: ReadonlyMap<string, unknown>): number | string {
  const role = roleIn(settings);
  const name = role === 'jobs' ? 'AGENTX_DB_JOBS_POOL_MAX' : 'AGENTX_DB_POOL_MAX';
  const pool = countIn(settings, name);
  const copies = role === 'web' ? copiesIn(settings) : 1;
  if (pool === undefined) return `${app.name} must state ${name} as a whole number, so its connections can be counted`;
  if (copies === undefined) {
    return `${app.name} must state AGENTX_WEB_COPIES as a whole number, so its connections can be counted`;
  }
  return 2 * copies * pool;
}

/**
 * Zitadel's connections (SA3a), or why they can't be counted: its pool once for each copy it may run. In production,
 * also each copy a change to its template starts beside them: Azure starts the new revision at minReplicas while the
 * old still runs up to maxReplicas, so pool × (maxReplicas + minReplicas). Staging's one copy's overlap stays
 * uncounted: Zitadel isn't redeployed with each release, and staging's server has no room for it.
 */
function zitadelConnections(app: PredictedResource, environment: Expectations['environment']): number | string {
  const pool = countIn(settingsIn(containersOf(app)[0]), ZITADEL_POOL.setting, ZITADEL_POOL.unset);
  if (pool === undefined) {
    return `${app.name} must state ${ZITADEL_POOL.setting} as a whole number, or leave it to its image's ${String(ZITADEL_POOL.unset)}, so its connections can be counted`;
  }
  const scale = at(app.properties, 'template', 'scale');
  let copies = 0;
  for (const name of environment === 'production' ? ['maxReplicas', 'minReplicas'] : ['maxReplicas']) {
    const count = at(scale, name);
    if (!Number.isInteger(count)) {
      return `${app.name} must state ${name} as a whole number, so its connections can be counted`;
    }
    copies += Number(count);
  }
  return pool * copies;
}

/**
 * Every connection the apps may hold fits the server's (4D2e D12): two of each API copy's pool (a deploy runs the old
 * revision beside the new one), Zitadel's pool, one job and one to spare, within max_connections less what Azure keeps.
 * In a load run, the larger server's; otherwise the one this deployment states. Zitadel's pool counts once for each
 * copy it may run, and in production for each a revision swap starts beside them too (`zitadelConnections`, SA3a).
 */
const connections: Check = (snapshot, expected, add) => {
  const [server] = ofType(snapshot, TYPES.server);
  if (server === undefined) return;
  const problem = (message: string): void => {
    add({ rule: 'connections', resource: server.name, message });
  };
  const loadRun = loadJobsIn(snapshot).length > 0;
  const stated = loadRun ? LOAD_RUN.serverConnections : Number(serverSettings(snapshot, server).get('max_connections'));
  if (!Number.isInteger(stated)) {
    problem("must state max_connections, which every app's connections are counted against");
    return;
  }
  const counts = ofType(snapshot, TYPES.app).flatMap((app) => {
    const settings = apiSettingsOf(app);
    if (settings !== undefined) return [apiConnections(app, settings)];
    return jobWorkloadOf(app.name) === 'zitadel' ? [zitadelConnections(app, expected.environment)] : [];
  });
  for (const unstated of counts.filter((count) => typeof count === 'string')) problem(unstated);
  const needed = [...counts.filter((count) => typeof count === 'number'), ONE_JOB_AND_ONE_MORE].reduce(
    (sum, count) => sum + count,
    0,
  );
  const forUsers = stated - AZURE_RESERVED_CONNECTIONS;
  if (needed > forUsers) {
    problem(
      `has ${String(forUsers)} connections for users (max_connections ${String(stated)} less Azure's ${String(AZURE_RESERVED_CONNECTIONS)}), but the apps may hold ${String(needed)}: two of each API copy's pool, each Zitadel copy's, one job and one to spare`,
    );
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

/**
 * Settings a container may take only as a file from the vault, never as a value in the deployment (SA2b): which
 * accounts are ours in the login service, which this public repository must never name.
 */
const VAULT_ONLY_SETTINGS: readonly string[] = ['AGENTX_IDP_OUR_ACTORS', 'AGENTX_IDP_OUR_SERVICE_USERS'];

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
  const copy = stageGCopyIn(snapshot) !== undefined;
  for (const job of workloadsIn(snapshot)) {
    const workload = jobWorkloadOf(job.name);
    const problem = (message: string): void => {
      add({ rule: 'workload-secrets', resource: job.name, message });
    };
    const assigned = identityProblems(job, runsAsOf(workload), problem);
    const all = list(at(job.properties, 'configuration', 'secrets'));
    const held = HELD[workload];
    const holding = all.filter((secret) => text(at(secret, 'name')) === held?.name);
    if (held !== undefined) heldProblems(job, held, holding, problem);
    const declared = all.filter((secret) => !holding.includes(secret));
    const given = all.map((secret) => text(at(secret, 'name')));
    const needed = secretsNeeded(workload, loadRun, copy);
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

/**
 * What a workload is given (GRANTS), but a load job's (`LOAD_RUN.reads`, Stage G's `STAGE_G_JOBS`) and the API's and
 * its jobs' in a load run; on Stage G's copy they go without the reset token too, as the copy holds staging's resets.
 */
function secretsNeeded(workload: string, loadRun: boolean, copy: boolean): ReadonlySet<string> {
  const stageG = STAGE_G_JOBS[workload];
  if (stageG !== undefined) return stageG.reads;
  if (isLoadJob(workload)) return LOAD_RUN.reads;
  const read = secretsRead(workload);
  if (!loadRun || !API_APPS.includes(workload)) return read;
  return new Set(
    [...read].filter((secret) => !LOAD_RUN.apiLeavesOut.has(secret) && !(copy && secret === 'zitadel-reset-token')),
  );
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
    for (const name of list(at(container, 'env'))
      .map((entry) => text(at(entry, 'name')))
      .filter((setting) => VAULT_ONLY_SETTINGS.includes(setting))) {
      problem(
        `sets ${name} in the deployment, where anyone reading it sees it; mount it from the vault as ${name}_FILE`,
      );
    }
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

/**
 * How every Zitadel process gets its 16-bit machine ID (SA3e): from the API, which hands
 * them out in turn (apps/api/src/machine-ids.ts), never by its hostname's hash, where two
 * copies can collide and mint the same IDs, nor its private address, which a replica here
 * lacks. Zitadel tries private address, then hostname, then the webhook, and the first that
 * answers wins, so the two before it are off outright.
 */
const ZITADEL_MACHINE_SWITCHES: Readonly<Record<string, string>> = {
  ZITADEL_MACHINE_IDENTIFICATION_PRIVATEIP_ENABLED: 'false',
  ZITADEL_MACHINE_IDENTIFICATION_HOSTNAME_ENABLED: 'false',
  ZITADEL_MACHINE_IDENTIFICATION_WEBHOOK_ENABLED: 'true',
};

/** The API's internal host as apps.bicep writes it: `<API app>.internal.<the environment's domain>`. */
const INTERNAL_HOST = /^format\('\{0\}\.internal\.\{1\}', '([^']+)', reference\('([^']+)', '[^']+'\)\.defaultDomain\)$/;

/** The webhook's address: the machine-ID path on a host INTERNAL_HOST reads. */
const MACHINE_WEBHOOK = /^\[format\('https:\/\/\{0\}\/internal\/zitadel-machine-id', (.+)\)\]$/;

/** The host the API's AGENTX_MACHINE_IDS_HOST names, as an ARM expression, when it is its own internal host in this environment. */
function apiInternalHost(snapshot: Snapshot, api: PredictedResource): string | undefined {
  const values = containersOf(api).map((container) => settingsIn(container).get('AGENTX_MACHINE_IDS_HOST'));
  const expression =
    values.length === 1 && typeof values[0] === 'string' ? /^\[(.+)\]$/.exec(values[0])?.[1] : undefined;
  const [, app, environment] = (expression === undefined ? null : INTERNAL_HOST.exec(expression)) ?? [];
  const inThisEnvironment = ofType(snapshot, TYPES.environment).some((one) => one.id === environment);
  return app === api.name && inThisEnvironment ? expression : undefined;
}

/**
 * Every Zitadel container asks the API for its machine ID at the API's internal host
 * (SA3e), with no JSONPath (Zitadel would hash its re-serialised match, not the body the
 * API wrote); and the API hands them out on that host, the same one, and no other.
 */
/** What a Zitadel container's settings get wrong about its machine ID, asked at `host` (the API's, when it hands them out). */
function machineIdProblems(settings: ReadonlyMap<string, unknown>, host: string | undefined): string[] {
  const switches = Object.entries(ZITADEL_MACHINE_SWITCHES)
    .filter(([name, wanted]) => settings.get(name) !== wanted)
    .map(
      ([name, wanted]) =>
        `must set ${name} to ${wanted}: each process takes its machine ID from the API in turn, never its hostname's hash, where two copies can mint the same IDs (SA3e)`,
    );
  const url = settings.get('ZITADEL_MACHINE_IDENTIFICATION_WEBHOOK_URL');
  const asks = typeof url === 'string' ? MACHINE_WEBHOOK.exec(url)?.[1] : undefined;
  const where =
    asks !== undefined && asks === host
      ? []
      : [
          "must set ZITADEL_MACHINE_IDENTIFICATION_WEBHOOK_URL to https://<the API's internal host>/internal/zitadel-machine-id, the host the API hands machine IDs out on (SA3e)",
        ];
  const reshaped = [...settings.keys()]
    .filter((name) => /^ZITADEL_MACHINE_IDENTIFICATION_WEBHOOK_(?:JPATH|HEADERS)/.test(name))
    .map(
      (name) =>
        `sets ${name}: the API's answer is hashed as its body, as it is written, and needs no header of ours (Zitadel's default Metadata-Flavor header is harmless) (SA3e)`,
    );
  return [...switches, ...where, ...reshaped];
}

const zitadelMachineIds: Check = (snapshot, _expected, add) => {
  const api = ofType(snapshot, TYPES.app).find((one) => jobWorkloadOf(one.name) === 'api');
  const host = api === undefined ? undefined : apiInternalHost(snapshot, api);
  const zitadels = workloadsIn(snapshot).filter((workload) =>
    containersOf(workload).some((container) => text(at(container, 'image')).startsWith(ZITADEL_SERVER_IMAGE)),
  );
  if (api !== undefined && zitadels.length > 0 && host === undefined) {
    add({
      rule: 'zitadel-machine-ids',
      resource: api.name,
      message:
        "must set AGENTX_MACHINE_IDS_HOST to its own internal host (<app>.internal.<the environment's domain>), where Zitadel asks for its machine IDs (SA3e)",
    });
  }
  for (const workload of zitadels) {
    for (const message of containersOf(workload).flatMap((container) =>
      machineIdProblems(settingsIn(container), host),
    )) {
      add({ rule: 'zitadel-machine-ids', resource: workload.name, message });
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
  databaseDisk,
  databaseZoneAndMeasures,
  databaseNetwork,
  databaseEgress,
  appsNetwork,
  appsEgress,
  dnsWatch,
  dnsAllow,
  dnsBlockAlert,
  vault,
  evidenceStore,
  anchorEpoch,
  activityDownloads,
  workspaceAndQuota,
  loginWorkspace,
  workbooks,
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
  loginServiceAlert,
  platformFullAlert,
  anchorStoreAlert,
  dailyCheckAlert,
  fullPassAlert,
  integrityRunsAlert,
  recordsFillingAlert,
  deadManAlerts,
  agentCancelsAlert,
  agentCancelCapAlert,
  decisionsSuppressedAlert,
  ownerLoginAlert,
  refusedLoginAlert,
  loginLinesAlert,
  alertRulesWatch,
  identities,
  releaseIdentity,
  releaseAccess,
  jobWatch,
  roleActions,
  releaseWritesAlert,
  azurePolicy,
  vaultSecrets,
  secretAccess,
  jobs,
  apps,
  loadTest,
  loadDatabase,
  connections,
  publicDoors,
  doorCertificates,
  workloadSecrets,
  containerTelemetry,
  zitadelMachineIds,
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
