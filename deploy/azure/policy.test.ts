import { appendFileSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import { beforeAll, describe, expect, it } from 'vitest';

import { LOGIN_SERVICE_ALERT_EVENTS } from '../../packages/platform/src/observability/login-service-alert.ts';
import { APP_KEYS } from './app-keys.ts';
import { STAGE_G_JOB_SECONDS } from '../../tooling/load/stageg.ts';
import { DEAD_MAN_RULE } from './deploy.ts';
import {
  at,
  bicepGuid,
  describeProblem,
  ALLOWED_TYPES,
  DNS_ALLOWED,
  DNS_EXPECTED_LEFTOVERS,
  type Expectations,
  kqlStages,
  leastRestoreDays,
  paramsFileProblems,
  policyLike,
  policyProblems,
  PREVIEW_API_EXCEPTIONS,
  type RuleId,
  singleSummaryColumn,
  templateProblems,
  DECISION_HEADROOM,
  gateBusy,
  LOAD_RUN,
  LOGIN_COPIES,
  ZITADEL_COPIES,
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

/**
 * Too broad to allow: every name, a top-level zone (`com.`), or a reverse zone
 * wider than a /16 (`10.in-addr.arpa.`), each of which would let lookups of
 * names whose servers anyone can run past the rule that blocks the rest.
 */
function tooBroad(domain: string): boolean {
  // DNS ignores case, so an upper-case entry could name a shared zone past the checks below.
  if (!domain.endsWith('.') || domain !== domain.toLowerCase()) return true;
  const labels = domain.split('.').filter((label) => label !== '');
  if (labels.length < 2) return true;
  if (SHARED_ZONES.includes(domain) || SHARED_CLUSTER.test(domain)) return true;
  return `.${domain}`.endsWith('.in-addr.arpa.') && labels.length < 4;
}

/**
 * Zones any customer creates names in (S84 review of the CNAME hops): only
 * exact names there, never the zone, nor a cluster every customer's
 * endpoints share (`b01.azurefd.net.`, `d.akamaiedge.net.`, and their kin).
 */
const SHARED_ZONES = [
  'trafficmanager.net.',
  'azurefd.net.',
  'tm-azurefd.net.',
  'azureedge.net.',
  'akadns.net.',
  'akamaiedge.net.',
  'edgekey.net.',
  // Classic cloud services' names, any customer's (the metrics hops, S98).
  'cloudapp.net.',
];
const SHARED_CLUSTER = /^(?:[a-z]\d+\.azurefd|[a-z]+\.akamaiedge)\.net\.$/;

/** A copy of a snapshot (staging's unless given) with one change made to the resources `pick` selects. */
function changed(
  pick: (resource: PredictedResource) => boolean,
  change: (resource: Mutable) => void,
  from: Snapshot = staging,
): Snapshot {
  const copy = structuredClone(from) as unknown as { predictedResources: Mutable[] };
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

/** A setting of an app's one container, put in or changed. */
const setSetting = (app: Mutable, name: string, value: string): void => {
  const entries = settingsOf(app);
  const entry = entries.find((each) => each.name === name);
  if (entry === undefined) entries.push({ name, value });
  else entry.value = value;
};

/**
 * Staging's API split as production runs it (4D2e D13): `web` copies (one, sized to staging's server)
 * beside a `jobs` app, the API's own copy at AGENTX_ROLE jobs as its own identity, with no ingress, keeping the
 * anchors, which the API's identity is no longer given.
 */
function splitTheApi(from: Snapshot): Snapshot {
  const resources = from.predictedResources as unknown as Mutable[];
  const api = resources.find((resource) => APP('api')(resource as unknown as PredictedResource));
  if (api === undefined) throw new Error('no API app');
  const jobs = JSON.parse(
    JSON.stringify(api)
      .replaceAll('id-agentx-stg-api', 'id-agentx-stg-jobs')
      .replaceAll('ca-agentx-stg-api', 'ca-agentx-stg-jobs'),
  ) as Mutable;
  for (const [app, role] of [
    [api, 'web'],
    [jobs, 'jobs'],
  ] as const) {
    setSetting(app, 'AGENTX_ROLE', role);
    Object.assign(scaleOf(app), { minReplicas: 1, maxReplicas: 1 });
  }
  setSetting(api, 'AGENTX_WEB_COPIES', '1');
  setSetting(api, 'AGENTX_DB_POOL_MAX', '5');
  setSetting(jobs, 'AGENTX_DB_JOBS_POOL_MAX', '6');
  containerOf(api).env = settingsOf(api).filter(
    ({ name }) => !/^AGENTX_(?:ANCHOR_EPOCH|AUDIT_ANCHORS_)/.test(String(name)),
  );
  containerOf(jobs).name = 'jobs';
  delete inside(jobs, 'properties', 'configuration').ingress;
  const kept = [...resources, jobs].filter(
    (resource) =>
      at(resource, 'properties', 'description') !== 'api keeps audit anchors (deploy/azure/modules/evidence.bicep)',
  );
  return { ...from, predictedResources: kept as unknown as PredictedResource[] };
}

/** Azure's own refusals (AZ2) named for production, and CI's writes alert naming production's CI identity. */
function guardrailsForProduction(resource: Mutable): void {
  resource.name = String(resource.name).replace(/^agentx-staging-/, 'agentx-production-');
  resource.id = String(resource.id).replace(/\/agentx-staging-/, '/agentx-production-');
  if (resource.type === 'Microsoft.Authorization/policyAssignments') {
    const given = resource.properties as Mutable;
    given.policyDefinitionId = String(given.policyDefinitionId).replace(/\/agentx-staging-/, '/agentx-production-');
  }
  if (resource.type === 'Microsoft.Insights/scheduledQueryRules') {
    const watched = criterion(resource);
    watched.query = String(watched.query).replace('/id-agentx-stg-release"', '/id-agentx-prd-release"');
  }
}

/**
 * Production keeps two copies of Zitadel and of its login pages running (SA3a, SA3c). Counted with a revision swap's two
 * more, two connections each keep Zitadel within staging's server: 8, 32 of 35 in all; the login pages hold none.
 */
function twoSignInCopies(snapshotted: Snapshot): void {
  for (const resource of snapshotted.predictedResources as unknown as Mutable[]) {
    const app = resource as unknown as PredictedResource;
    if (APP('zitadel')(app) || APP('login')(app)) Object.assign(scaleOf(resource), { minReplicas: 2, maxReplicas: 2 });
    if (APP('zitadel')(app)) setSetting(resource, 'ZITADEL_DATABASE_POSTGRES_MAXOPENCONNS', '2');
  }
}

/**
 * Staging's resources as production's would name them: their tags and CI's
 * identity (where it is and whom its role is given to), and (unless a test
 * wants it left) CI's GitHub subject. Its API runs split, as production's must (4D2e D13).
 */
function productionLike({ subject }: { readonly subject: boolean }): Snapshot {
  const copy = splitTheApi(
    changed(
      (resource) => resource.tags !== undefined,
      (resource) => (inside(resource, 'tags').environment = 'production'),
    ),
  );
  twoSignInCopies(copy);
  for (const resource of copy.predictedResources as unknown as Mutable[]) {
    // CI's identity and the job-start watch's (S175), both named by the environment.
    for (const who of ['release', 'job-watch']) {
      resource.id = String(resource.id).replace(`/id-agentx-stg-${who}`, `/id-agentx-prd-${who}`);
      resource.name = String(resource.name).replace(new RegExp(`^id-agentx-stg-${who}`), `id-agentx-prd-${who}`);
      if (resource.type === 'Microsoft.Authorization/roleAssignments') {
        const grant = resource.properties as Mutable;
        grant.principalId = String(grant.principalId).replace(`/id-agentx-stg-${who}`, `/id-agentx-prd-${who}`);
      }
    }
    guardrailsForProduction(resource);
    // Production keeps each audit export five years, Locked, in three zones (decision 27).
    if (EVIDENCE_STORE(resource as unknown as PredictedResource)) {
      inside(resource, 'sku').name = 'Standard_ZRS';
      Object.assign(inside(resource, 'properties', 'immutableStorageWithVersioning', 'immutabilityPolicy'), {
        state: 'Locked',
        immutabilityPeriodSinceCreationInDays: 1826,
      });
    }
    // Something always runs in production: the alerts on the jobs stopping are on (4D2e D).
    if (
      ANCHOR_STOPPED_ALERT(resource as unknown as PredictedResource) ||
      JOBS_STOPPED_ALERT(resource as unknown as PredictedResource)
    ) {
      inside(resource, 'properties').enabled = true;
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
/** A list in a resource, or none. */
const list = (value: unknown): unknown[] => (Array.isArray(value) ? value : []);

/** A staging resource's id. A lookup that finds nothing fails, so no case passes on a scope or principal that isn't there. */
function idOf(pick: (resource: PredictedResource) => boolean): string {
  const found = staging.predictedResources.find(pick);
  if (found === undefined) throw new Error('the snapshot has no such resource');
  return found.id;
}

const accountProperties = (found: Mutable): Mutable => inside(found, 'properties');
const accountAcls = (found: Mutable): Mutable => inside(found, 'properties', 'networkAcls');
/**
 * Each way either Storage account could be opened (evidence-store, activity-downloads):
 * another kind, older TLS, shared keys, public blobs or copies from another tenant,
 * another way in, a wider network, no second layer of encryption.
 */
const OPENED_ACCOUNT: readonly ((found: Mutable) => unknown)[] = [
  (found: Mutable) => (found.kind = 'BlobStorage'),
  (found: Mutable) => (accountProperties(found).minimumTlsVersion = 'TLS1_0'),
  (found: Mutable) => (accountProperties(found).supportsHttpsTrafficOnly = false),
  (found: Mutable) => (accountProperties(found).allowSharedKeyAccess = true),
  (found: Mutable) => delete accountProperties(found).allowSharedKeyAccess,
  (found: Mutable) => (accountProperties(found).defaultToOAuthAuthentication = false),
  (found: Mutable) => (accountProperties(found).allowBlobPublicAccess = true),
  (found: Mutable) => (accountProperties(found).allowCrossTenantReplication = true),
  (found: Mutable) => (accountProperties(found).allowedCopyScope = 'PrivateLink'),
  (found: Mutable) => (accountProperties(found).isHnsEnabled = true),
  (found: Mutable) => (accountProperties(found).isSftpEnabled = true),
  (found: Mutable) => (accountProperties(found).isLocalUserEnabled = true),
  (found: Mutable) => (accountProperties(found).isNfsV3Enabled = true),
  (found: Mutable) => (accountAcls(found).defaultAction = 'Allow'),
  (found: Mutable) => (accountAcls(found).bypass = 'AzureServices'),
  (found: Mutable) => (accountAcls(found).ipRules = [{ value: '203.0.113.7' }]),
  (found: Mutable) => (accountAcls(found).resourceAccessRules = [{ resourceId: '/subscriptions/x/any' }]),
  (found: Mutable) => (first(accountAcls(found).virtualNetworkRules).id = '/subscriptions/x/any/subnets/other'),
  (found: Mutable) =>
    (accountAcls(found).virtualNetworkRules = [
      first(accountAcls(found).virtualNetworkRules),
      { id: '/subscriptions/x/any/subnets/other', action: 'Allow' },
    ]),
  (found: Mutable) => (accountAcls(found).virtualNetworkRules = []),
  (found: Mutable) => (inside(found, 'properties', 'encryption').requireInfrastructureEncryption = false),
];

const type = (wanted: string) => (resource: PredictedResource) => resource.type === wanted;
const named = (pattern: RegExp) => (resource: PredictedResource) => pattern.test(resource.name);
const SERVER = type('Microsoft.DBforPostgreSQL/flexibleServers');
const VAULT = type('Microsoft.KeyVault/vaults');
const WORKSPACE = type('Microsoft.OperationalInsights/workspaces');
const MAIN_WORKSPACE = (resource: PredictedResource) =>
  WORKSPACE(resource) && /^log-agentx-[a-z]+$/.test(resource.name);
const LOGIN_WORKSPACE = (resource: PredictedResource) => WORKSPACE(resource) && resource.name.endsWith('-logins');
const LOGIN_CAP_ALERT = named(/-login-logs-cap-reached$/);
const SYSTEM_LOGS_COPY = named(/^system-logs-to-login-workspace$/);
const WORKBOOK = type('Microsoft.Insights/workbooks');
const RULES = type('Microsoft.Network/networkSecurityGroups');
const DATABASE_RULES = (resource: PredictedResource) => RULES(resource) && resource.name.endsWith('-database');
const APPS_RULES = (resource: PredictedResource) => RULES(resource) && resource.name.endsWith('-apps');
const NETWORK = type('Microsoft.Network/virtualNetworks');
/** The database's private DNS zone or its link, not the blob endpoint's (AZ11). */
const DATABASE_DNS = (wanted: string) => (resource: PredictedResource) =>
  resource.type === wanted && resource.name.includes('.private.postgres.');
const DNS_POLICY = type('Microsoft.Network/dnsResolverPolicies');
const DNS_RULES = type('Microsoft.Network/dnsResolverPolicies/dnsSecurityRules');
const WATCH_RULE = (resource: PredictedResource) =>
  DNS_RULES(resource) && resource.name.endsWith('/watch-every-lookup');
const ALLOW_RULE = (resource: PredictedResource) =>
  DNS_RULES(resource) && resource.name.endsWith('/allow-needed-names');
const DNS_LINK = type('Microsoft.Network/dnsResolverPolicies/virtualNetworkLinks');
const DNS_LISTS = type('Microsoft.Network/dnsResolverDomainLists');
const EVERY_NAME_LIST = (resource: PredictedResource) => DNS_LISTS(resource) && resource.name.endsWith('-every-name');
const ALLOWED_NAMES = (resource: PredictedResource) => DNS_LISTS(resource) && resource.name.endsWith('-allowed');
const DNS_LOGS = named(/^lookups-to-workspace$/);
const DNS_BLOCKED_ALERT = named(/^alert-agentx-.+-dns-blocked$/);
const ENVIRONMENT = type('Microsoft.App/managedEnvironments');
const IDENTITIES = type('Microsoft.ManagedIdentity/userAssignedIdentities');
const APP_LOGS = named(/^app-logs-to-workspace$/);
const ERRORS_ALERT = named(/-app-errors$/);
const INTEGRITY_ALERT = named(/-audit-integrity$/);
const TOKEN_REFUSED_ALERT = named(/^alert-agentx-.+-token-refused$/);
const DENIAL_SURGE_ALERT = named(/^alert-agentx-.+-denial-surge$/);
const AGENT_CANCELS_ALERT = named(/^alert-agentx-.+-agent-cancels$/);
const AGENT_CANCEL_CAP_ALERT = named(/^alert-agentx-.+-agent-cancel-cap$/);
const DECISIONS_SUPPRESSED_ALERT = named(/^alert-agentx-.+-decisions-suppressed$/);
const HOLDINGS_CHECK_ALERT = named(/^alert-agentx-.+-holdings-check$/);
const HANDOFF_QUEUE_ALERT = named(/^alert-agentx-.+-handoff-queue$/);
const LOGIN_SERVICE_ALERT = named(/^alert-agentx-.+-login-service$/);
const PLATFORM_FULL_ALERT = named(/^alert-agentx-.+-platform-full$/);
const ANCHOR_STORE_ALERT = named(/^alert-agentx-.+-anchor-store$/);
const INTEGRITY_RUNS_ALERT = named(/^alert-agentx-.+-integrity-runs$/);
const RECORDS_FILLING_ALERT = named(/^alert-agentx-.+-records-filling$/);
const DAILY_CHECK_ALERT = named(/^alert-agentx-.+-daily-check$/);
const FULL_PASS_ALERT = named(/^alert-agentx-.+-full-pass$/);
const ANCHOR_STOPPED_ALERT = named(/^alert-agentx-.+-anchor-stopped$/);
const JOBS_STOPPED_ALERT = named(/^alert-agentx-.+-jobs-stopped$/);
const ACTION_GROUP = type('Microsoft.Insights/actionGroups');
const BUDGET = type('Microsoft.Consumption/budgets');
const COMMUNICATION = type('Microsoft.Communication/communicationServices');
const EMAIL_SERVICE = type('Microsoft.Communication/emailServices');
const EMAIL_DOMAIN = type('Microsoft.Communication/emailServices/domains');
const ALERTS = type('Microsoft.Insights/scheduledQueryRules');
const LOGIN_ALERT = named(/-privileged-login$/);
const OWNER_ALERT = named(/-owner-login$/);
const REFUSED_ALERT = named(/-privileged-login-refused$/);
const LINES_ALERT = named(/-login-lines-quiet$/);
const ACTIVITY_ALERTS = type('Microsoft.Insights/activityLogAlerts');
const RULES_CHANGED = named(/^alert-agentx-stg-alert-rules-changed$/);
const RULES_UNHEALTHY = named(/^alert-agentx-stg-alert-rules-unhealthy$/);
const CAP_ALERT = named(/-log-cap-reached$/);
const QUOTA_ALERT = named(/-log-quota$/);
const setting = (name: string) => (resource: PredictedResource) => resource.name.endsWith(`/${name}`);
const SECRETS = type('Microsoft.KeyVault/vaults/secrets');
const SECRET = (name: string) => (resource: PredictedResource) =>
  SECRETS(resource) && resource.id.endsWith(`/secrets/${name}`);
const ASSIGNMENTS = type('Microsoft.Authorization/roleAssignments');
/** The two Storage accounts and their parts, by the names their modules give them. */
const EVIDENCE_STORE = (resource: PredictedResource) =>
  resource.type === 'Microsoft.Storage/storageAccounts' && /^stagentx(?:stg|prd)/.test(resource.name);
const DOWNLOADS_STORE = (resource: PredictedResource) =>
  resource.type === 'Microsoft.Storage/storageAccounts' && resource.name.startsWith('stagentxdl');
const IN_EVIDENCE_STORE = (wanted: string) => (resource: PredictedResource) =>
  resource.type === wanted && /^stagentx(?:stg|prd)/.test(resource.name);
const IN_DOWNLOADS_STORE = (wanted: string) => (resource: PredictedResource) =>
  resource.type === wanted && resource.name.startsWith('stagentxdl');
const ROLE_DEFINITIONS = type('Microsoft.Authorization/roleDefinitions');
/** CI's custom role, not the audit exports' (modules/evidence.bicep), by the name names.bicep gives it. */
const RELEASE_ROLE = (resource: PredictedResource) =>
  ROLE_DEFINITIONS(resource) && String(at(resource.properties, 'roleName')).startsWith('Agent X release ');
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
/** A change to an alert's query, which must change it: a pattern that no longer matches fails rather than passing unchanged. */
const edited = (from: string | RegExp, to: string) => (alert: Mutable) => {
  const before = String(criterion(alert).query);
  criterion(alert).query = before.replace(from, to);
  expect(criterion(alert).query).not.toBe(before);
};
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
      'staging.access.bicepparam',
      'staging.apps.bicepparam',
      'staging.bicepparam',
      'staging.certificates.bicepparam',
      'staging.secrets.bicepparam',
    ]);
    expect([...params.values()].map((entry) => entry.deploys)).toEqual([
      'access.bicep',
      'apps.bicep',
      'main.bicep',
      'certificates.bicep',
      'secrets.bicep',
    ]);
    expect([...bicepFiles.keys()]).toEqual([
      'access.bicep',
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
      'dbOperatorPassword',
      'dbZitadelPassword',
      'zitadelMasterKey',
      'zitadelAdminPassword',
      'loginClientPrivateKey',
      'loginClientPublicKey',
      'apiOidcClientSecret',
      'directoryToken',
      'resetToken',
      'ourActors',
      'ourServiceUsers',
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
      'Microsoft.OperationalInsights/workspaces log-agentx-stg-logins',
      'Microsoft.Insights/actionGroups ag-agentx-stg',
      'Microsoft.Insights/scheduledQueryRules alert-agentx-stg-log-quota',
      'Microsoft.Insights/scheduledQueryRules alert-agentx-stg-login-logs-quota',
      'Microsoft.Insights/scheduledQueryRules alert-agentx-stg-log-cap-reached',
      'Microsoft.Insights/scheduledQueryRules alert-agentx-stg-login-logs-cap-reached',
      'Microsoft.Insights/activityLogAlerts alert-agentx-stg-alert-rules-changed',
      'Microsoft.Insights/activityLogAlerts alert-agentx-stg-alert-rules-unhealthy',
      'Microsoft.Network/networkSecurityGroups nsg-agentx-staging-apps',
      'Microsoft.Network/networkSecurityGroups nsg-agentx-staging-database',
      'Microsoft.Network/networkSecurityGroups nsg-agentx-staging-endpoints',
      'Microsoft.Network/virtualNetworks vnet-agentx-staging',
      'Microsoft.Network/privateDnsZones agentx-staging.private.postgres.database.azure.com',
      'Microsoft.Network/privateDnsZones/virtualNetworkLinks agentx-staging.private.postgres.database.azure.com/vnet-agentx-staging',
      'Microsoft.Network/privateDnsZones privatelink.blob.core.windows.net',
      'Microsoft.Network/privateDnsZones/virtualNetworkLinks privatelink.blob.core.windows.net/vnet-agentx-staging',
      'Microsoft.Network/dnsResolverPolicies dnspr-agentx-staging',
      'Microsoft.Network/dnsResolverDomainLists dnsdl-agentx-staging-every-name',
      'Microsoft.Network/dnsResolverDomainLists dnsdl-agentx-staging-allowed',
      'Microsoft.Network/dnsResolverPolicies/dnsSecurityRules dnspr-agentx-staging/allow-needed-names',
      'Microsoft.Network/dnsResolverPolicies/dnsSecurityRules dnspr-agentx-staging/watch-every-lookup',
      'Microsoft.Network/dnsResolverPolicies/virtualNetworkLinks dnspr-agentx-staging/network',
      'Microsoft.Insights/diagnosticSettings lookups-to-workspace',
      'Microsoft.Insights/scheduledQueryRules alert-agentx-stg-dns-blocked',
      expect.stringMatching(/^Microsoft\.KeyVault\/vaults kv-agentx-stg-[a-z0-9]{6}$/),
      'Microsoft.Insights/diagnosticSettings audit-to-workspace',
      expect.stringMatching(/^Microsoft\.DBforPostgreSQL\/flexibleServers psql-agentx-stg-[a-z0-9]{6}$/),
      expect.stringMatching(/\/configurations psql-agentx-stg-[a-z0-9]{6}\/require_secure_transport$/),
      expect.stringMatching(/\/configurations psql-agentx-stg-[a-z0-9]{6}\/ssl_min_protocol_version$/),
      expect.stringMatching(/\/configurations psql-agentx-stg-[a-z0-9]{6}\/log_connections$/),
      expect.stringMatching(/\/configurations psql-agentx-stg-[a-z0-9]{6}\/log_line_prefix$/),
      expect.stringMatching(/\/configurations psql-agentx-stg-[a-z0-9]{6}\/pg_qs\.query_capture_mode$/),
      expect.stringMatching(/\/configurations psql-agentx-stg-[a-z0-9]{6}\/pg_qs\.store_query_plans$/),
      expect.stringMatching(/\/configurations psql-agentx-stg-[a-z0-9]{6}\/pgms_wait_sampling\.query_capture_mode$/),
      expect.stringMatching(/\/configurations psql-agentx-stg-[a-z0-9]{6}\/track_io_timing$/),
      expect.stringMatching(/\/configurations psql-agentx-stg-[a-z0-9]{6}\/max_connections$/),
      expect.stringMatching(/\/configurations psql-agentx-stg-[a-z0-9]{6}\/log_checkpoints$/),
      expect.stringMatching(/\/configurations psql-agentx-stg-[a-z0-9]{6}\/log_lock_waits$/),
      expect.stringMatching(/\/configurations psql-agentx-stg-[a-z0-9]{6}\/deadlock_timeout$/),
      expect.stringMatching(/\/configurations psql-agentx-stg-[a-z0-9]{6}\/metrics\.collector_database_activity$/),
      'Microsoft.Insights/diagnosticSettings logs-to-workspace',
      expect.stringMatching(
        /^Microsoft\.Insights\/scheduledQueryRules alert-psql-agentx-stg-[a-z0-9]{6}-privileged-login$/,
      ),
      expect.stringMatching(
        /^Microsoft\.Insights\/scheduledQueryRules alert-psql-agentx-stg-[a-z0-9]{6}-privileged-login-refused$/,
      ),
      expect.stringMatching(
        /^Microsoft\.Insights\/scheduledQueryRules alert-psql-agentx-stg-[a-z0-9]{6}-login-lines-quiet$/,
      ),
      expect.stringMatching(/^Microsoft\.Insights\/scheduledQueryRules alert-psql-agentx-stg-[a-z0-9]{6}-owner-login$/),
      expect.stringMatching(/^Microsoft\.Insights\/metricAlerts alert-psql-agentx-stg-[a-z0-9]{6}-disk$/),
      'Microsoft.App/managedEnvironments cae-agentx-staging',
      'Microsoft.Insights/diagnosticSettings app-logs-to-workspace',
      'Microsoft.Insights/diagnosticSettings system-logs-to-login-workspace',
      // The API's jobs apart from it (4D2e D13) have their own, unused on staging out of a load run.
      ...[
        'api',
        'zitadel',
        'login',
        'jobs',
        'db-setup',
        'migrate',
        'zitadel-init',
        'zitadel-setup',
        'operator',
        'chain-restore',
        // Stage G's mark and checks (AZ3), unused out of a Stage G run.
        'stage-g',
      ].map((workload) => `Microsoft.ManagedIdentity/userAssignedIdentities id-agentx-stg-${workload}`),
      'Microsoft.OperationalInsights/workspaces/savedSearches log-agentx-stg/agentx-errors-by-type',
      'Microsoft.OperationalInsights/workspaces/savedSearches log-agentx-stg/agentx-what-broke',
      'Microsoft.Insights/scheduledQueryRules alert-agentx-stg-app-errors',
      'Microsoft.Insights/scheduledQueryRules alert-agentx-stg-daily-words',
      'Microsoft.Insights/scheduledQueryRules alert-agentx-stg-audit-integrity',
      'Microsoft.Insights/scheduledQueryRules alert-agentx-stg-token-refused',
      'Microsoft.OperationalInsights/workspaces/savedSearches log-agentx-stg/agentx-denials-by-agent',
      'Microsoft.Insights/scheduledQueryRules alert-agentx-stg-denial-surge',
      'Microsoft.Insights/scheduledQueryRules alert-agentx-stg-holdings-check',
      'Microsoft.Insights/scheduledQueryRules alert-agentx-stg-handoff-queue',
      'Microsoft.Insights/scheduledQueryRules alert-agentx-stg-login-service',
      'Microsoft.Insights/scheduledQueryRules alert-agentx-stg-platform-full',
      'Microsoft.Insights/scheduledQueryRules alert-agentx-stg-anchor-store',
      'Microsoft.Insights/scheduledQueryRules alert-agentx-stg-daily-check',
      'Microsoft.Insights/scheduledQueryRules alert-agentx-stg-full-pass',
      'Microsoft.Insights/scheduledQueryRules alert-agentx-stg-integrity-runs',
      'Microsoft.Insights/scheduledQueryRules alert-agentx-stg-records-filling',
      'Microsoft.Insights/scheduledQueryRules alert-agentx-stg-anchor-stopped',
      'Microsoft.Insights/scheduledQueryRules alert-agentx-stg-jobs-stopped',
      'Microsoft.OperationalInsights/workspaces/savedSearches log-agentx-stg/agentx-agent-cancels-by-agent',
      'Microsoft.Insights/scheduledQueryRules alert-agentx-stg-agent-cancels',
      'Microsoft.Insights/scheduledQueryRules alert-agentx-stg-agent-cancel-cap',
      'Microsoft.Insights/scheduledQueryRules alert-agentx-stg-decisions-suppressed',
      expect.stringMatching(/^Microsoft\.Storage\/storageAccounts stagentxstg[a-z0-9]{6}$/),
      expect.stringMatching(/^Microsoft\.Network\/privateEndpoints pe-stagentxstg[a-z0-9]{6}-blob$/),
      expect.stringMatching(
        /^Microsoft\.Network\/privateEndpoints\/privateDnsZoneGroups pe-stagentxstg[a-z0-9]{6}-blob\/default$/,
      ),
      expect.stringMatching(/^Microsoft\.Storage\/storageAccounts\/blobServices stagentxstg[a-z0-9]{6}\/default$/),
      expect.stringMatching(
        /^Microsoft\.Storage\/storageAccounts\/blobServices\/containers stagentxstg[a-z0-9]{6}\/default\/audit-exports$/,
      ),
      expect.stringMatching(
        /^Microsoft\.Storage\/storageAccounts\/blobServices\/containers stagentxstg[a-z0-9]{6}\/default\/audit-anchors$/,
      ),
      expect.stringMatching(
        /^Microsoft\.Authorization\/roleAssignments [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
      ),
      // The anchors' role to the API's and the jobs' identities on staging (4D2e D13).
      expect.stringMatching(
        /^Microsoft\.Authorization\/roleAssignments [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
      ),
      expect.stringMatching(
        /^Microsoft\.Authorization\/roleAssignments [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
      ),
      expect.stringMatching(
        /^Microsoft\.Authorization\/roleAssignments [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
      ),
      // 4D2e E10: the chain repair's identity adds its records and reads the anchors, with the same two roles,
      // and reads the plans with a role of its own.
      expect.stringMatching(
        /^Microsoft\.Authorization\/roleAssignments [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
      ),
      expect.stringMatching(
        /^Microsoft\.Authorization\/roleAssignments [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
      ),
      expect.stringMatching(
        /^Microsoft\.Authorization\/roleAssignments [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
      ),
      'Microsoft.Insights/diagnosticSettings blob-logs-to-workspace',
      expect.stringMatching(/^Microsoft\.Storage\/storageAccounts stagentxdlstg[a-z0-9]{6}$/),
      expect.stringMatching(/^Microsoft\.Storage\/storageAccounts\/blobServices stagentxdlstg[a-z0-9]{6}\/default$/),
      expect.stringMatching(
        /^Microsoft\.Storage\/storageAccounts\/blobServices\/containers stagentxdlstg[a-z0-9]{6}\/default\/activity-downloads$/,
      ),
      expect.stringMatching(
        /^Microsoft\.Storage\/storageAccounts\/managementPolicies stagentxdlstg[a-z0-9]{6}\/default$/,
      ),
      // The downloads' role to the API's and the jobs' identities (4D2e D13).
      expect.stringMatching(
        /^Microsoft\.Authorization\/roleAssignments [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
      ),
      expect.stringMatching(
        /^Microsoft\.Authorization\/roleAssignments [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
      ),
      'Microsoft.Insights/diagnosticSettings blob-logs-to-workspace',
      expect.stringMatching(
        /^Microsoft\.Insights\/workbooks [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
      ),
      ...['request-failures', 'decision-time', 'handoff-outcomes', 'job-gaps'].map(
        (measure) => `Microsoft.OperationalInsights/workspaces/savedSearches log-agentx-stg/agentx-measure-${measure}`,
      ),
      expect.stringMatching(/^Microsoft\.Communication\/emailServices ecs-agentx-stg-[a-z0-9]{6}$/),
      expect.stringMatching(
        /^Microsoft\.Communication\/emailServices\/domains ecs-agentx-stg-[a-z0-9]{6}\/AzureManagedDomain$/,
      ),
      expect.stringMatching(/^Microsoft\.Communication\/communicationServices acs-agentx-stg-[a-z0-9]{6}$/),
      'Microsoft.ManagedIdentity/userAssignedIdentities id-agentx-stg-release',
      'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials id-agentx-stg-release/github',
      // The alert on CI doing anything but a release (AZ2).
      'Microsoft.Insights/scheduledQueryRules alert-agentx-stg-release-writes',
      // The job-start watch (S175): its identity, its trust, and its read-only role (access's) on the group.
      'Microsoft.ManagedIdentity/userAssignedIdentities id-agentx-stg-job-watch',
      'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials id-agentx-stg-job-watch/github',
      expect.stringMatching(
        /^Microsoft\.Authorization\/roleAssignments [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
      ),
    ]);
  });

  // AZ5 (review S190): what CI's approved deploy may never write, the partner's own deployment.
  it('creates the custom roles, the guardrails, the activity log setting and the budget in access, and only them', () => {
    const role: unknown = expect.stringMatching(
      /^Microsoft\.Authorization\/roleDefinitions [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
    expect(
      stagingPart('staging.access.bicepparam').predictedResources.map(
        (resource) => `${resource.type} ${resource.name}`,
      ),
    ).toEqual([
      'Microsoft.Insights/diagnosticSettings activity-log-to-workspace',
      'Microsoft.Consumption/budgets budget-agentx-staging',
      // The evidence store's four, the activity downloads', CI's and the job watch's.
      ...Array.from({ length: 7 }, (): unknown => role),
      // The live server's delete lock (S185), which CI may neither write nor lift.
      'Microsoft.Authorization/locks keep-live-database',
      // The main workspace's (AZ5e): the access alarm reads it, so CI may not delete it.
      'Microsoft.Authorization/locks keep-log-workspace',
      // Azure's own refusals (AZ2): six rules of the subscription, each given on the group.
      ...['policyDefinitions', 'policyAssignments'].flatMap((kind) =>
        ['apps-internal', 'apps-https', 'images', 'jobs-by-hand', 'app-replicas', 'allowed-types'].map(
          (guardrail) => `Microsoft.Authorization/${kind} agentx-staging-${guardrail}`,
        ),
      ),
    ]);
    // Nothing else defines a role or a policy rule, or writes the budget or the subscription's activity log.
    const elsewhere = [...(deployed.get('staging')?.parts ?? [])]
      .filter(([file]) => file !== 'staging.access.bicepparam')
      .flatMap(([, part]) => part.predictedResources)
      .concat(stagingPart('staging.bicepparam').predictedResources)
      .filter(
        (resource) =>
          /^Microsoft\.(?:Authorization\/(?:roleDefinitions|policyDefinitions|policyAssignments)|Consumption\/budgets)$/.test(
            resource.type,
          ) || resource.name === 'activity-log-to-workspace',
      );
    expect(elsewhere).toEqual([]);
  });

  // Review S190: CI's infrastructure identity holds Contributor and conditional grants alone, which write no
  // role definition, policy, lock or exemption: a deployment CI sends holding one would fail part-way.
  it("lets nothing CI may send (foundation, secrets, apps) write Azure's authorization but a grant", () => {
    const sent = ['staging.bicepparam', 'staging.secrets.bicepparam', 'staging.apps.bicepparam'];
    for (const file of sent) {
      const authorization = stagingPart(file)
        .predictedResources.filter((resource) => resource.type.toLowerCase().startsWith('microsoft.authorization/'))
        .map((resource) => resource.type);
      expect({ file, types: [...new Set(authorization)] }).toEqual({
        file,
        types: authorization.length === 0 ? [] : ['Microsoft.Authorization/roleAssignments'],
      });
    }
    // And the locks that keep the live server and the main workspace (AZ5e) are there, in access.
    expect(
      stagingPart('staging.access.bicepparam')
        .predictedResources.filter(type('Microsoft.Authorization/locks'))
        .map((lock) => lock.name),
    ).toEqual(['keep-live-database', 'keep-log-workspace']);
  });

  it("writes the secrets, each only when given but the master key and the app's keys, and the email key copied, and lets each app and job read its own", () => {
    const part = stagingPart('staging.secrets.bicepparam').predictedResources;
    const copied = (resource: PredictedResource): boolean =>
      String(at(resource.properties, 'value')).startsWith('[listKeys(');
    const label = (resource: PredictedResource): string =>
      SECRETS(resource)
        ? `${resource.id.slice(resource.id.lastIndexOf('/') + 1)} ${resource.condition ?? (copied(resource) ? 'copied' : 'once')}`
        : String(at(resource.properties, 'description'));
    const givenOnly = (parameter: string): string => `[not(empty(parameters('${parameter}')))]`;
    expect(part.map(label)).toEqual([
      `db-admin-password ${givenOnly('postgresAdminPassword')}`,
      `db-owner-password ${givenOnly('dbOwnerPassword')}`,
      `db-app-password ${givenOnly('dbAppPassword')}`,
      `db-backup-password ${givenOnly('dbBackupPassword')}`,
      `db-operator-password ${givenOnly('dbOperatorPassword')}`,
      `db-zitadel-password ${givenOnly('dbZitadelPassword')}`,
      `zitadel-admin-password ${givenOnly('zitadelAdminPassword')}`,
      `login-client-private-key ${givenOnly('loginClientPrivateKey')}`,
      `login-client-public-key ${givenOnly('loginClientPublicKey')}`,
      `api-oidc-client-secret ${givenOnly('apiOidcClientSecret')}`,
      `zitadel-directory-token ${givenOnly('directoryToken')}`,
      `zitadel-reset-token ${givenOnly('resetToken')}`,
      `zitadel-our-actors ${givenOnly('ourActors')}`,
      `zitadel-our-service-users ${givenOnly('ourServiceUsers')}`,
      'zitadel-masterkey once',
      // B5-3: on every run, from the email service this deployment creates.
      'acs-access-key copied',
      ...APP_KEYS.map((key) => `${key} once`),
      // PL-57, E11: the operator's keys' public halves, each created once with its key, in the keys' order.
      'public-audit-rebase-v1 once',
      'public-operator-signing-v1 once',
      ...[
        'db-setup reads db-admin-password',
        'db-setup reads db-owner-password',
        'migrate reads db-owner-password',
        // 4D2e E10: the chain repair writes as the owner, the one job besides the migration.
        'chain-restore reads db-owner-password',
        // AZ3: Stage G's mark as the owner, and its checks as the app and the backup role, on its copy alone.
        'stage-g reads db-owner-password',
        'db-setup reads db-app-password',
        'api reads db-app-password',
        // The API's jobs apart from it read what the API reads (4D2e D13).
        'jobs reads db-app-password',
        'stage-g reads db-app-password',
        'db-setup reads db-backup-password',
        'stage-g reads db-backup-password',
        'db-setup reads db-operator-password',
        'operator reads db-operator-password',
        'db-setup reads db-zitadel-password',
        'zitadel-init reads db-zitadel-password',
        'zitadel-setup reads db-zitadel-password',
        'zitadel reads db-zitadel-password',
        'zitadel-setup reads zitadel-admin-password',
        'login reads login-client-private-key',
        'zitadel reads login-client-public-key',
        'api reads api-oidc-client-secret',
        'jobs reads api-oidc-client-secret',
        'api reads zitadel-directory-token',
        'jobs reads zitadel-directory-token',
        'api reads zitadel-reset-token',
        'jobs reads zitadel-reset-token',
        // SA2b: who makes our own routine changes in the login service, and for whom.
        'api reads zitadel-our-actors',
        'jobs reads zitadel-our-actors',
        'api reads zitadel-our-service-users',
        'jobs reads zitadel-our-service-users',
        'zitadel-setup reads zitadel-masterkey',
        'zitadel reads zitadel-masterkey',
        'api reads acs-access-key',
        'jobs reads acs-access-key',
        // The operator's command reads the audit chains' MAC too (B1c), and the field encryption (B4-6b), each
        // version; its own signing key and the rebase key it alone reads, and the API their public halves (PL-57, E11).
        // The chain repair (4D2e E10) the MAC alone, to check with, and the public half: never the operator's key.
        // The API's jobs apart from it read what the API reads (4D2e D13).
        ...APP_KEYS.flatMap((key) => {
          if (key.startsWith('key-operator-signing-v') || key.startsWith('key-audit-rebase-v')) {
            return [`operator reads ${key}`];
          }
          if (key.startsWith('key-audit-mac-v')) {
            return [`api reads ${key}`, `jobs reads ${key}`, `operator reads ${key}`, `chain-restore reads ${key}`];
          }
          return key.startsWith('key-field-encryption-v')
            ? [`api reads ${key}`, `jobs reads ${key}`, `operator reads ${key}`]
            : [`api reads ${key}`, `jobs reads ${key}`];
        }),
        'api reads public-audit-rebase-v1',
        'jobs reads public-audit-rebase-v1',
        'chain-restore reads public-audit-rebase-v1',
        'api reads public-operator-signing-v1',
        'jobs reads public-operator-signing-v1',
        'chain-restore reads public-operator-signing-v1',
      ].map((grant) => `${grant} (deploy/azure/secrets.bicep)`),
    ]);
  });

  it('compiles a rotation run, one secret given and every other empty, and refuses one without a master key', () => {
    const text = params.get('staging.secrets.bicepparam')?.text ?? '';
    const variables = [...text.matchAll(/readEnvironmentVariable\('([A-Z0-9_]+)'\)/g)].map((match) => match[1] ?? '');
    expect(variables).toHaveLength(16);
    // The API's login given; every other secret set but empty, so left as the vault has it; the master key a
    // fresh 32 characters and the app's keys fresh too, which Azure leaves alone once they exist. Empty values
    // reach Bicep from Node, as G3's tool sends them.
    const everyRun = ['AGENTX_AZURE_DB_APP_PASSWORD', 'AGENTX_AZURE_ZITADEL_MASTERKEY', 'AGENTX_AZURE_APP_KEYS'];
    const kept = Object.fromEntries(variables.filter((name) => !everyRun.includes(name)).map((name) => [name, '']));
    inCopy((dir) => {
      const rotation = environmentSnapshot(dir, 'staging', kept).together;
      expect(policyProblems(rotation, STAGING).map(describeProblem)).toEqual([]);
      // Sixteen written when given (our login lists among them, SA2b), each key, and the operator's keys' public
      // halves (PL-57, E11).
      expect(rotation.predictedResources.filter(SECRETS)).toHaveLength(16 + APP_KEYS.length + 2);
      // The keys must come every run too: without them the run stops before Azure.
      expect(() => environmentSnapshot(dir, 'staging', { ...kept, AGENTX_AZURE_APP_KEYS: '' })).toThrow();
      // A master key must come every run, even though only the first is kept: an empty one stops the run before Azure.
      expect(() => environmentSnapshot(dir, 'staging', { ...kept, AGENTX_AZURE_ZITADEL_MASTERKEY: '' })).toThrow(
        /minimum allowable length is 32/,
      );
    });
  });

  it('SEC-AV-06 the live database server carries a delete lock, so Azure refuses its delete and its restore points stay (S185)', () => {
    const locks = staging.predictedResources.filter(type('Microsoft.Authorization/locks'));
    expect(locks.map((lock) => [lock.name, at(lock.properties, 'level')])).toEqual([
      ['keep-live-database', 'CanNotDelete'],
      // The main workspace's (AZ5e), on the workspace alone.
      ['keep-log-workspace', 'CanNotDelete'],
    ]);
    expect(locks[1]?.id).toMatch(
      /\/providers\/Microsoft\.OperationalInsights\/workspaces\/log-agentx-stg\/providers\/Microsoft\.Authorization\/locks\/keep-log-workspace$/,
    );
    // Scoped to the server itself, not the group: Stage G's copies and the drill stay deletable.
    const server = staging.predictedResources.find(SERVER);
    expect(server).toBeDefined();
    expect(locks[0]?.id.startsWith(`${server?.id ?? 'missing'}/providers/Microsoft.Authorization/locks/`)).toBe(true);
    // Only a delete lock grants nothing; any other level, or none, is an access type no rule reads.
    const LOCK = type('Microsoft.Authorization/locks');
    expect(brokenRules(staging)).toEqual([]);
    for (const level of ['ReadOnly', undefined]) {
      expect(
        brokenRules(
          changed(LOCK, (lock) => {
            (lock.properties as Mutable).level = level;
          }),
        ),
      ).toEqual(['secret-access']);
    }
  });

  it("compiles the load run's foundation (D2c): only the server's size and its measurements change, and every rule still holds", () => {
    const load = inCopy((dir) => environmentSnapshot(dir, 'staging', { AGENTX_AZURE_DATABASE_SIZE: 'load' }));
    expect(policyProblems(load.together, STAGING).map(describeProblem)).toEqual([]);
    expect(at(load.foundation.predictedResources.find(SERVER), 'sku')).toEqual({
      name: 'Standard_D2ads_v5',
      tier: 'GeneralPurpose',
    });
    expect(at(staging.predictedResources.find(SERVER), 'sku')).toEqual({ name: 'Standard_B1ms', tier: 'Burstable' });
    // Only the foundation reads the size; the other parts carry stand-in values that differ each run.
    const normal = deployed.get('staging')?.foundation.predictedResources ?? [];
    const off: Record<string, string> = {
      'pg_qs.query_capture_mode': 'none',
      'pg_qs.store_query_plans': 'off',
      'pgms_wait_sampling.query_capture_mode': 'none',
      track_io_timing: 'off',
      max_connections: '50',
    };
    const measures = (resources: readonly PredictedResource[]): Record<string, unknown> => {
      const found: Record<string, unknown> = {};
      for (const setting of resources.filter(type('Microsoft.DBforPostgreSQL/flexibleServers/configurations'))) {
        const name = String(setting.name.split('/').at(-1));
        if (name in off) found[name] = at(setting.properties, 'value');
      }
      return found;
    };
    expect(measures(normal)).toEqual(off);
    expect(measures(load.foundation.predictedResources)).toEqual({
      'pg_qs.query_capture_mode': 'top',
      'pg_qs.store_query_plans': 'on',
      'pgms_wait_sampling.query_capture_mode': 'all',
      track_io_timing: 'on',
      max_connections: '120',
    });
    expect(at(load.foundation.predictedResources.find(SERVER)?.properties, 'availabilityZone')).toBe('2');
    const sizeless = (resource: PredictedResource) =>
      SERVER(resource)
        ? { ...resource, sku: undefined }
        : Object.keys(off).some((name) => resource.name.endsWith(`/${name}`))
          ? { ...resource, properties: undefined }
          : resource;
    expect(load.foundation.predictedResources.map(sizeless)).toEqual(normal.map(sizeless));
    // Any other value stops the run before Azure.
    expect(() =>
      inCopy((dir) => environmentSnapshot(dir, 'staging', { AGENTX_AZURE_DATABASE_SIZE: 'huge' })),
    ).toThrow();
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
    // Sent only when given (AZ5): CI's approved foundation never holds it, and the server keeps its own.
    expect(at(server?.properties, 'administratorLoginPassword')).toBe(
      "[if(empty(parameters('postgresAdminPassword')), null(), parameters('adminPassword'))]",
    );
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
      // With no server, no server's log reaches the login alerts' workspace either.
    ).toEqual(['required', 'login-workspace']);
    expect(brokenRules(without((resource) => NETWORK(resource) || RULES(resource)))).toContain('required');
    expect(brokenRules(without(WORKSPACE))).toContain('required');
    expect(brokenRules(without(MAIN_WORKSPACE))).toContain('required');
    // Without the policy, no rule of ours judges the network's lookups.
    expect(
      brokenRules(
        without((resource) => resource.type.startsWith('Microsoft.Network/dnsResolver') || DNS_LOGS(resource)),
      ),
    ).toEqual(['required', 'dns-watch']);
    expect(brokenRules(without(ACTION_GROUP))).toContain('required');
    const workspace = staging.predictedResources.find(WORKSPACE);
    // A second workspace also has no quota alerts of its own.
    expect(brokenRules(withExtra({ ...structuredClone(workspace), id: `${String(workspace?.id)}-second` }))).toContain(
      'required',
    );
    // Without the environment there is nowhere of ours for the jobs to run, no
    // platform lines for the owner-login alert to pair with, the doors and
    // their certificates belong to no environment of ours, and Zitadel asks for its
    // machine IDs at a host in none (SA3e).
    expect(brokenRules(without((resource) => ENVIRONMENT(resource) || APP_LOGS(resource)))).toEqual([
      'required',
      'login-workspace',
      'owner-login-alert',
      'jobs',
      'apps',
      'public-doors',
      'door-certificates',
      'zitadel-machine-ids',
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
    // Email's three are global too; their data location is rule `email`'s.
    for (const pick of [COMMUNICATION, EMAIL_SERVICE, EMAIL_DOMAIN]) {
      expect(brokenRules(changed(pick, (resource) => (resource.location = 'uaenorth')))).toEqual(['in-country']);
    }
    // Activity log alerts too (MO2): Azure offers them in Global and two European regions, never the UAE.
    expect(brokenRules(changed(RULES_CHANGED, (alert) => (alert.location = 'uaenorth')))).toEqual(['in-country']);
    expect(brokenRules(changed(RULES_CHANGED, (alert) => (alert.location = 'westeurope')))).toEqual(['in-country']);
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
    // Sent only when given (AZ5) is still a parameter; a value written in its place is not.
    expect(
      brokenRules(
        changed(
          SERVER,
          (server) =>
            (inside(server, 'properties').administratorLoginPassword =
              "[if(empty(parameters('postgresAdminPassword')), null(), 'written in the code')]"),
        ),
      ),
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
      // An empty default writes nothing down (AZ5: a value left out keeps the server's own password).
      const leftOut = paramsFileProblems(
        file,
        String(entry?.text).replace(assignment, `param ${parameter} = readEnvironmentVariable('${variable}', '')`),
        bicepFile(String(entry?.deploys)).secure,
      );
      expect(leftOut).toEqual([]);
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
    expect(brokenRules(without(DATABASE_DNS('Microsoft.Network/privateDnsZones/virtualNetworkLinks')))).toEqual([
      'database-private',
    ]);
    // A link kept while its zone isn't one this deployment creates, or a link to another network.
    expect(brokenRules(without(DATABASE_DNS('Microsoft.Network/privateDnsZones')))).toEqual(['database-private']);
    expect(
      brokenRules(
        changed(
          DATABASE_DNS('Microsoft.Network/privateDnsZones/virtualNetworkLinks'),
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
    for (const change of [
      ...LATE_OR_BLIND,
      // Counted by when it happened, so a line arriving after its window is missed, or over too short a stretch (MO2).
      edited('where ingestion_time() > ago(30m)', 'where TimeGenerated > ago(30m)'),
      edited('where ingestion_time() > ago(30m) | ', ''),
      // A window no longer than the runs' rhythm: a run starting late leaves a sliver unseen.
      edited('ingestion_time() > ago(30m)', 'ingestion_time() > ago(20m)'),
      edited('ingestion_time() > ago(30m)', 'ingestion_time() > ago(15m)'),
      // Reading too little back for a late line to be in view when it arrives.
      (alert: Mutable) => (inside(alert, 'properties').overrideQueryTimeRange = 'PT1H'),
      (alert: Mutable) => delete inside(alert, 'properties').overrideQueryTimeRange,
    ]) {
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
      edited('TimeGenerated + 20m);\nlet logins', 'TimeGenerated + 5m);\nlet logins'),
      edited('TimeGenerated + 20m);\nlet paired', 'TimeGenerated + 5m);\nlet paired'),
      edited('between (ago(30m) .. now())', 'between (ago(15m) .. now())'),
      edited('starts\n    | where Judged between (ago(30m)', 'starts\n    | where Judged between (ago(15m)'),
      // A late line judged by its age alone again: one over about 35 minutes late never judged (MO2).
      edited('max_of(ingestion_time(), TimeGenerated + 20m);\nlet logins', 'TimeGenerated + 20m;\nlet logins'),
      edited('max_of(ingestion_time(), TimeGenerated + 20m);\nlet paired', 'TimeGenerated + 20m;\nlet paired'),
      (alert: Mutable) => (criterion(alert).threshold = 1),
      (alert: Mutable) => (criterion(alert).operator = 'LessThan'),
      ...LATE_OR_BLIND,
      // Reading less than two days, so a late line or what it pairs with is out of view, or running less often than the band needs.
      (alert: Mutable) => (properties(alert).overrideQueryTimeRange = 'PT1H'),
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

  it('refused-login-alert: no alert on a refused privileged login, or one that misses a role, a kind of refusal or a late line, or fires too quietly (MO2)', () => {
    const properties = (alert: Mutable): Mutable => inside(alert, 'properties');
    expect(brokenRules(without(REFUSED_ALERT))).toEqual(['refused-login-alert']);
    for (const change of [
      // A role left out, or only the line's level wrong, or another level.
      edited('|agentx_owner)', ')'),
      edited('(agentx_admin|', '('),
      edited('|agentx_backup|', '|'),
      edited('FATAL:  ', 'LOG:  '),
      edited('FATAL:  ', 'FATAL: '),
      // A kind of refusal left out: a wrong password, or a connection the server's rules refuse.
      edited('password authentication failed for user|', ''),
      edited('|no pg_hba[.]conf entry for host', '|no pg_hba[.]conf entry for user'),
      edited('|pg_hba[.]conf rejects connection for host \\x22[^\\x22]*\\x22, user)', ')'),
      // Counted by when it happened, so a line arriving late falls between runs, or over too short a stretch.
      edited('where ingestion_time() > ago(30m)', 'where TimeGenerated > ago(30m)'),
      // A window no longer than the runs' rhythm: a run starting late leaves a sliver unseen.
      edited('ingestion_time() > ago(30m)', 'ingestion_time() > ago(20m)'),
      edited('ingestion_time() > ago(30m)', 'ingestion_time() > ago(15m)'),
      (alert: Mutable) => (criterion(alert).threshold = 1),
      (alert: Mutable) => (criterion(alert).operator = 'LessThan'),
      (alert: Mutable) => (criterion(alert).timeAggregation = 'Count'),
      ...LATE_OR_BLIND,
      (alert: Mutable) => (properties(alert).overrideQueryTimeRange = 'PT1H'),
      (alert: Mutable) => delete properties(alert).overrideQueryTimeRange,
      (alert: Mutable) => (properties(alert).scopes = [idOf(MAIN_WORKSPACE)]),
    ]) {
      expect(brokenRules(changed(REFUSED_ALERT, change))).toEqual(['refused-login-alert']);
    }
    expect(brokenRules(changed(REFUSED_ALERT, (alert) => (properties(alert).severity = 2)))).toEqual([
      'alert-runbook',
      'refused-login-alert',
    ]);
    expect(brokenRules(changed(REFUSED_ALERT, (alert) => (properties(alert).autoMitigate = true)))).toEqual([
      'alert-delivery',
      'refused-login-alert',
    ]);
    expect(brokenRules(changed(REFUSED_ALERT, (alert) => (properties(alert).enabled = false)))).toEqual([
      'alert-delivery',
      'refused-login-alert',
    ]);
  });

  it('login-lines-alert: no alert on the server log lines stopping, or one that waits too long, reads the wrong lines or fires too quietly (MO6)', () => {
    const properties = (alert: Mutable): Mutable => inside(alert, 'properties');
    expect(brokenRules(without(LINES_ALERT))).toEqual(['login-lines-alert']);
    for (const change of [
      // Another table, or lines counted by when they happened: a late one falls outside the hour.
      edited('union (PGSQLServerLogs |', 'union (ContainerAppSystemLogs |'),
      edited('PGSQLServerLogs | where ingestion_time() > ago(60m)', 'PGSQLServerLogs | where TimeGenerated > ago(60m)'),
      // A shorter hour fires on the server's quiet gaps; a longer one stays blind for longer.
      edited('ingestion_time() > ago(60m)', 'ingestion_time() > ago(10m)'),
      edited('ingestion_time() > ago(60m)', 'ingestion_time() > ago(180m)'),
      // The cap's word left out (it would fire whenever the workspace is over its cap), or its stretch changed.
      edited(/, \(_LogOperation .*\) \| summarize/, ' | summarize'),
      edited('or TimeGenerated > ago(60m))', 'or TimeGenerated > ago(10m))'),
      (alert: Mutable) => (criterion(alert).threshold = 0),
      (alert: Mutable) => (criterion(alert).operator = 'GreaterThan'),
      (alert: Mutable) => (criterion(alert).timeAggregation = 'Count'),
      (alert: Mutable) => (inside(criterion(alert), 'failingPeriods').minFailingPeriodsToAlert = 2),
      (alert: Mutable) => (inside(criterion(alert), 'failingPeriods').numberOfEvaluationPeriods = 2),
      (alert: Mutable) => (properties(alert).evaluationFrequency = 'PT30M'),
      (alert: Mutable) => (properties(alert).windowSize = 'PT2H'),
      (alert: Mutable) => (properties(alert).overrideQueryTimeRange = 'PT1H'),
      (alert: Mutable) => (properties(alert).scopes = [idOf(MAIN_WORKSPACE)]),
    ]) {
      expect(brokenRules(changed(LINES_ALERT, change))).toEqual(['login-lines-alert']);
    }
    expect(brokenRules(changed(LINES_ALERT, (alert) => (properties(alert).severity = 2)))).toEqual([
      'alert-runbook',
      'login-lines-alert',
    ]);
    expect(brokenRules(changed(LINES_ALERT, (alert) => (properties(alert).autoMitigate = true)))).toEqual([
      'alert-delivery',
      'login-lines-alert',
    ]);
    expect(brokenRules(changed(LINES_ALERT, (alert) => (properties(alert).enabled = false)))).toEqual([
      'alert-delivery',
      'login-lines-alert',
    ]);
  });

  it('SEC-DB-04 the refused-login alert matches the lines Postgres 18 writes for a refused privileged login, and no others (MO2)', () => {
    const query = String(criterion(staging.predictedResources.find(REFUSED_ALERT) as unknown as Mutable).query);
    const source = /matches regex @"([^"]+)"/.exec(query)?.[1];
    expect(source).toBeDefined();
    // Kusto's regular expressions are RE2; `\x22` and the rest read the same in JavaScript.
    const pattern = new RegExp(source ?? '(?!)');
    const line = (level: string, message: string, session = '6ab011c5.8f4ee') =>
      `2026-11-12 10:00:00 UTC-${session}-${level}:  ${message}`;
    // Postgres 18's own words for each refusal (src/backend/libpq/auth.c), the role in double quotes.
    const badLogin = (role: string) => `password authentication failed for user "${role}"`;
    const noEntry = (role: string) =>
      `no pg_hba.conf entry for host "10.40.0.16", user "${role}", database "agentx", no encryption`;
    const rejected = (role: string) =>
      `pg_hba.conf rejects connection for host "10.40.0.16", user "${role}", database "postgres", SSL encryption`;
    for (const role of ['agentx_owner', 'agentx_admin', 'agentx_backup']) {
      for (const refusal of [badLogin, noEntry, rejected]) {
        expect(line('FATAL', refusal(role))).toMatch(pattern);
        expect(line('FATAL', refusal(role), '6ab0abcd.1')).toMatch(pattern);
      }
    }
    for (const other of [
      line('FATAL', badLogin('agentx_app')),
      line('FATAL', badLogin('agentx_owner2')),
      line('FATAL', badLogin('azuresu')),
      line('FATAL', noEntry('agentx_app')),
      line('LOG', badLogin('agentx_owner')),
      line(
        'DETAIL',
        'Connection matched file "/datadrive/pg/data/pg_hba.conf" line 29: "host all all 0.0.0.0/0 scram-sha-256"',
      ),
      line('LOG', 'connection authorized: user=agentx_owner database=agentx'),
      line('LOG', `statement: SELECT '${badLogin('agentx_owner')}'`),
      `FATAL:  ${badLogin('agentx_owner')}`,
    ]) {
      expect(other).not.toMatch(pattern);
    }
  });

  describe('alert-rules-watch: the alert rules themselves switched off, changed, deleted or failing (MO2)', () => {
    const properties = (alert: Mutable): Mutable => inside(alert, 'properties');
    const allOf = (alert: Mutable): Mutable[] => at(alert, 'properties', 'condition', 'allOf') as Mutable[];
    const anyOf = (alert: Mutable): Mutable[] => allOf(alert).at(-1)?.anyOf as Mutable[];

    it('holds on staging, and each watch missing is refused', () => {
      expect(staging.predictedResources.filter(ACTIVITY_ALERTS)).toHaveLength(2);
      // Alert processing rules, which can mute every alert, and a deleted log setting, which empties the login
      // alerts' table while they run healthy; never the writes every foundation deploy makes to those settings.
      const operations = anyOf(
        structuredClone(staging.predictedResources.find(RULES_CHANGED)) as unknown as Mutable,
      ).map((one) => one.equals);
      expect(operations).toHaveLength(11);
      expect(operations).toEqual(
        expect.arrayContaining([
          'Microsoft.AlertsManagement/actionRules/write',
          'Microsoft.AlertsManagement/actionRules/delete',
          'Microsoft.Insights/diagnosticSettings/delete',
        ]),
      );
      expect(operations).not.toContain('Microsoft.Insights/diagnosticSettings/write');
      expect(operations).not.toContain('Microsoft.DBforPostgreSQL/flexibleServers/configurations/write');
      expect(brokenRules(without(ACTIVITY_ALERTS))).toEqual(['alert-rules-watch']);
      expect(brokenRules(without(RULES_CHANGED))).toEqual(['alert-rules-watch']);
      expect(brokenRules(without(RULES_UNHEALTHY))).toEqual(['alert-rules-watch']);
      // The two swapped for one another's conditions still leave both watched.
      const changedCondition = at(staging.predictedResources.find(RULES_CHANGED)?.properties, 'condition');
      const unhealthyCondition = at(staging.predictedResources.find(RULES_UNHEALTHY)?.properties, 'condition');
      const swapped = changed(
        RULES_CHANGED,
        (alert) => (properties(alert).condition = structuredClone(unhealthyCondition)),
      );
      expect(
        brokenRules(
          changed(
            RULES_UNHEALTHY,
            (alert) => (properties(alert).condition = structuredClone(changedCondition)),
            swapped,
          ),
        ),
      ).toEqual([]);
    });

    it('each way of switching it off, narrowing it or sending it nowhere is refused', () => {
      const either = [RULES_CHANGED, RULES_UNHEALTHY];
      const changes: readonly (readonly [(resource: PredictedResource) => boolean, (alert: Mutable) => void])[] = [
        ...either.flatMap((pick) => [
          [pick, (alert: Mutable) => (properties(alert).enabled = false)] as const,
          // Another resource group, or a resource in this one only.
          [pick, (alert: Mutable) => (properties(alert).scopes = ['/subscriptions/x/resourceGroups/other'])] as const,
          [pick, (alert: Mutable) => (properties(alert).scopes = [idOf(LOGIN_ALERT)])] as const,
          [pick, (alert: Mutable) => (properties(alert).scopes = [])] as const,
          // One more condition narrows what fires: only someone else's changes, say.
          [pick, (alert: Mutable) => allOf(alert).push({ field: 'caller', equals: 'someone@example.com' })] as const,
          [pick, (alert: Mutable) => allOf(alert).shift()] as const,
          // Not a SEV-1, or no runbook.
          [
            pick,
            (alert: Mutable) =>
              (properties(alert).description = String(properties(alert).description).replace('SEV-1.', 'SEV-2.')),
          ] as const,
          [
            pick,
            (alert: Mutable) =>
              (properties(alert).description = String(properties(alert).description).replace(/ Runbook: .*$/, '')),
          ] as const,
          // Sent nowhere, or to a group of nobody's.
          [pick, (alert: Mutable) => (inside(alert, 'properties', 'actions').actionGroups = [])] as const,
          [
            pick,
            (alert: Mutable) =>
              (inside(alert, 'properties', 'actions').actionGroups = [{ actionGroupId: '/subscriptions/x/elsewhere' }]),
          ] as const,
          // A group of nobody's beside ours: every group it names must be this deployment's (mutation 8b).
          [
            pick,
            (alert: Mutable) =>
              (inside(alert, 'properties', 'actions').actionGroups as Mutable[]).push({
                actionGroupId: '/subscriptions/x/elsewhere',
              }),
          ] as const,
        ]),
        // A kind of change left unwatched: each of the eleven, written or deleted (alert processing rules among them),
        // or a diagnostic setting deleted.
        ...Array.from(
          { length: 11 },
          (_unused, index) => [RULES_CHANGED, (alert: Mutable) => anyOf(alert).splice(index, 1)] as const,
        ),
        [
          RULES_CHANGED,
          (alert: Mutable) =>
            (anyOf(alert)[1] = { field: 'operationName', equals: 'Microsoft.Insights/scheduledQueryRules/read' }),
        ],
        // Changes that failed, or every status, or another category.
        [RULES_CHANGED, (alert: Mutable) => (allOf(alert)[1] = { field: 'status', equals: 'Failed' })],
        [RULES_CHANGED, (alert: Mutable) => (allOf(alert)[0] = { field: 'category', equals: 'Security' })],
        // A health state left out, another resource type, or another category.
        [RULES_UNHEALTHY, (alert: Mutable) => anyOf(alert).splice(0, 1)],
        [RULES_UNHEALTHY, (alert: Mutable) => anyOf(alert).splice(1, 1)],
        [
          RULES_UNHEALTHY,
          (alert: Mutable) => (allOf(alert)[1] = { field: 'resourceType', equals: 'Microsoft.Insights/metricAlerts' }),
        ],
        [RULES_UNHEALTHY, (alert: Mutable) => (allOf(alert)[0] = { field: 'category', equals: 'Administrative' })],
      ];
      for (const [pick, change] of changes) {
        expect(brokenRules(changed(pick, change))).toEqual(['alert-rules-watch']);
      }
    });
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

  it("database-size: on staging, any size but B1ms or the load run's D2ads_v5, each with its own tier", () => {
    const sized = (name: string, tier: string) => changed(SERVER, (server) => (server.sku = { name, tier }));
    expect(brokenRules(sized('Standard_D2ads_v5', 'GeneralPurpose'))).toEqual([]);
    for (const [name, tier] of [
      ['Standard_D4ads_v5', 'GeneralPurpose'],
      ['Standard_B2s', 'Burstable'],
      ['Standard_D2ads_v5', 'Burstable'],
      ['Standard_B1ms', 'GeneralPurpose'],
    ] as const) {
      expect({ name, tier, broken: brokenRules(sized(name, tier)) }).toEqual({ name, tier, broken: ['database-size'] });
    }
    // Production's size waits on the load run (PL-38): the rule names staging's alone.
    expect(
      brokenRules(sized('Standard_D4ads_v5', 'GeneralPurpose'), { region: 'uaenorth', environment: 'production' }),
    ).not.toContain('database-size');
  });

  it("database-disk: a disk that can't grow, or no alert that is on, on this server, on its fullness, reaching someone", () => {
    const DISK_ALERT = type('Microsoft.Insights/metricAlerts');
    const broken = [
      changed(SERVER, (server) => (inside(server, 'properties', 'storage').autoGrow = 'Disabled')),
      changed(DISK_ALERT, (alert) => (inside(alert, 'properties').enabled = false)),
      changed(DISK_ALERT, (alert) => (inside(alert, 'properties').scopes = ['another server'])),
      changed(DISK_ALERT, (alert) => (inside(alert, 'properties').actions = [])),
      changed(DISK_ALERT, (alert) => (inside(alert, 'properties').actions = [{ actionGroupId: 'nobody' }])),
      changed(DISK_ALERT, (alert) => (inside(alert, 'properties', 'criteria').allOf = [{ metricName: 'cpu_percent' }])),
    ];
    for (const snapshotted of broken) expect(brokenRules(snapshotted)).toEqual(['database-disk']);
  });

  it('database-zone: a server whose zone is left to Azure, or not one of the three', () => {
    for (const zone of [undefined, '', '4']) {
      const unzoned = changed(SERVER, (server) => (inside(server, 'properties').availabilityZone = zone));
      expect({ zone, broken: brokenRules(unzoned) }).toEqual({ zone, broken: ['database-zone'] });
    }
  });

  it('database-measures: any measurement on, or not stated, on a Burstable size; all on is fine on the load size', () => {
    const MEASURE = (name: string) => (resource: PredictedResource) =>
      type('Microsoft.DBforPostgreSQL/flexibleServers/configurations')(resource) && resource.name.endsWith(`/${name}`);
    const on: Record<string, string> = {
      'pg_qs.query_capture_mode': 'top',
      'pg_qs.store_query_plans': 'on',
      'pgms_wait_sampling.query_capture_mode': 'all',
      track_io_timing: 'on',
      max_connections: '120',
    };
    for (const [name, value] of Object.entries(on)) {
      const measured = changed(MEASURE(name), (setting) => (inside(setting, 'properties').value = value));
      expect({ name, broken: brokenRules(measured) }).toEqual({ name, broken: ['database-measures'] });
      // Not stated leaves the server's last value, which may be on.
      const unstated = staging.predictedResources.filter((resource) => !MEASURE(name)(resource));
      expect(unstated).toHaveLength(staging.predictedResources.length - 1);
      // An unstated limit leaves the connections rule nothing to count against either (4D2e D12).
      expect(brokenRules({ predictedResources: structuredClone(unstated), diagnostics: [] })).toEqual(
        name === 'max_connections' ? ['database-measures', 'connections'] : ['database-measures'],
      );
    }
    let everyOn = staging;
    for (const [name, value] of Object.entries(on)) {
      everyOn = changed(MEASURE(name), (setting) => (inside(setting, 'properties').value = value), everyOn);
    }
    const loadSized = changed(
      SERVER,
      (server) => (server.sku = { name: 'Standard_D2ads_v5', tier: 'GeneralPurpose' }),
      everyOn,
    );
    expect(brokenRules(loadSized)).toEqual([]);
  });

  it('database-stall-evidence: checkpoints or lock waits unlogged, lock waits logged only later, or the wait counts off, on any size (MO5)', () => {
    const SETTING = (name: string) => (resource: PredictedResource) =>
      type('Microsoft.DBforPostgreSQL/flexibleServers/configurations')(resource) && resource.name.endsWith(`/${name}`);
    const wrong: readonly (readonly [string, string])[] = [
      ['log_checkpoints', 'off'],
      ['log_lock_waits', 'off'],
      // Lock waits under 5 s go unlogged, so the soak's pause leaves no line.
      ['deadlock_timeout', '5000'],
      ['deadlock_timeout', '10s'],
      ['metrics.collector_database_activity', 'off'],
    ];
    const loadSized = (from: Snapshot) =>
      changed(SERVER, (server) => (server.sku = { name: 'Standard_D2ads_v5', tier: 'GeneralPurpose' }), from);
    for (const [name, value] of wrong) {
      const changedOne = changed(SETTING(name), (setting) => (inside(setting, 'properties').value = value));
      expect({ name, value, broken: brokenRules(changedOne) }).toEqual({
        name,
        value,
        broken: ['database-stall-evidence'],
      });
      // Not stated leaves whatever the server had.
      const unstated = staging.predictedResources.filter((resource) => !SETTING(name)(resource));
      expect(unstated).toHaveLength(staging.predictedResources.length - 1);
      expect(brokenRules({ predictedResources: structuredClone(unstated), diagnostics: [] })).toEqual([
        'database-stall-evidence',
      ]);
    }
    // The load size too: it is where a stall is most likely, and its measurements don't stand in for these.
    expect(
      brokenRules(
        loadSized(changed(SETTING('log_lock_waits'), (setting) => (inside(setting, 'properties').value = 'off'))),
      ),
    ).toContain('database-stall-evidence');
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
    ]) {
      expect(brokenRules(changed(NETWORK, change))).toEqual(['database-network']);
    }
    // A second Postgres subnet without rules: nothing keeps the network out, nor the server in (AZ8).
    expect(
      brokenRules(
        changed(NETWORK, (network) => {
          const second = structuredClone(subnet(network, 'database'));
          second.name = 'database2';
          inside(second, 'properties').addressPrefix = '10.40.2.0/24';
          delete inside(second, 'properties').networkSecurityGroup;
          (at(network, 'properties', 'subnets') as Mutable[]).push(second);
        }),
      ),
    ).toEqual(['database-network', 'database-egress']);
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

  it('evidence-store: an audit-export store anyone else can reach, change, or keep for less (E10c, decisions 27 and 28)', () => {
    const STORE = EVIDENCE_STORE;
    const BLOBS = IN_EVIDENCE_STORE('Microsoft.Storage/storageAccounts/blobServices');
    const CONTAINER = IN_EVIDENCE_STORE('Microsoft.Storage/storageAccounts/blobServices/containers');
    const group = String(staging.predictedResources.find(type('Microsoft.Resources/resourceGroups'))?.id);
    const WRITER_ROLE = (resource: PredictedResource) =>
      ROLE_DEFINITIONS(resource) && resource.name === bicepGuid(group, 'evidence-writer');
    const WRITES = (resource: PredictedResource) =>
      ASSIGNMENTS(resource) && String(at(resource.properties, 'description')).startsWith('operator adds audit exports');
    const properties = (store: Mutable): Mutable => inside(store, 'properties');
    const policy = (store: Mutable): Mutable =>
      inside(store, 'properties', 'immutableStorageWithVersioning', 'immutabilityPolicy');
    const only = (snapshotted: Snapshot, expected = STAGING): RuleId[] => brokenRules(snapshotted, expected);
    const production: Expectations = { region: 'uaenorth', environment: 'production' };

    // As staging has it: a few days, Unlocked, one copy.
    const store = staging.predictedResources.find(STORE);
    expect(at(store?.properties, 'immutableStorageWithVersioning')).toEqual({
      enabled: true,
      immutabilityPolicy: {
        immutabilityPeriodSinceCreationInDays: 3,
        state: 'Unlocked',
        allowProtectedAppendWrites: false,
      },
    });
    for (const change of [
      ...OPENED_ACCOUNT,
      (found: Mutable) => (inside(found, 'sku').name = 'Standard_GRS'),
      (found: Mutable) => (inside(found, 'properties', 'immutableStorageWithVersioning').enabled = false),
      (found: Mutable) => delete properties(found).immutableStorageWithVersioning,
      (found: Mutable) => (policy(found).allowProtectedAppendWrites = true),
      // Staging Locked would hold the account, and its resource group, for good.
      (found: Mutable) => (policy(found).state = 'Locked'),
      (found: Mutable) => (policy(found).state = 'Disabled'),
      (found: Mutable) => (policy(found).immutabilityPeriodSinceCreationInDays = 0),
      (found: Mutable) => (policy(found).immutabilityPeriodSinceCreationInDays = 8),
    ]) {
      expect(only(changed(STORE, change))).toEqual(['evidence-store']);
    }
    expect(only(changed(STORE, (found) => (policy(found).immutabilityPeriodSinceCreationInDays = 7)))).toEqual([]);
    // Production: five years exactly, Locked, three zones; anything less is refused.
    expect(only(productionLike({ subject: true }), production)).toEqual(['database-backup']);
    for (const change of [
      (found: Mutable) => (policy(found).state = 'Unlocked'),
      (found: Mutable) => (policy(found).immutabilityPeriodSinceCreationInDays = 1825),
      (found: Mutable) => (inside(found, 'sku').name = 'Standard_LRS'),
    ]) {
      const weaker = productionLike({ subject: true });
      change(weaker.predictedResources.find(STORE) as unknown as Mutable);
      expect(only(weaker, production)).toEqual(['database-backup', 'evidence-store']);
    }

    // Versioning off, a container open to anyone or named otherwise, a part
    // that isn't the store's, or any other Storage resource.
    expect(only(changed(BLOBS, (found) => (properties(found).isVersioningEnabled = false)))).toEqual([
      'evidence-store',
    ]);
    expect(only(changed(CONTAINER, (found) => (properties(found).publicAccess = 'Blob')))).toEqual(['evidence-store']);
    expect(
      only(changed(CONTAINER, (found) => (found.id = String(found.id).replace(/audit-exports$/, 'other')))),
    ).toEqual(['evidence-store']);
    // A blob service that isn't the account's default; its logs then watch nothing of the store's too.
    expect(only(changed(BLOBS, (found) => (found.id = String(found.id).replace(/default$/, 'second'))))).toEqual([
      'evidence-store',
      'resource-logs',
    ]);
    expect(
      only(
        withExtra({
          id: `${String(store?.id)}/managementPolicies/default`,
          type: 'Microsoft.Storage/storageAccounts/managementPolicies',
          name: `${String(store?.name)}/default`,
          apiVersion: '2025-01-01',
          properties: {},
        }),
      ),
    ).toEqual(['evidence-store']);
    // None, or a second, of each part.
    for (const pick of [STORE, BLOBS, CONTAINER]) {
      const found = staging.predictedResources.find(pick);
      expect(only(withExtra({ ...structuredClone(found), id: `${String(found?.id)}-second` }))).toContain('required');
    }
    // The apps subnet without its Storage endpoint, or with it in another region.
    const endpoints = (network: Mutable): Mutable[] =>
      at(subnet(network, 'apps'), 'properties', 'serviceEndpoints') as Mutable[];
    expect(
      only(
        changed(NETWORK, (network) => {
          inside(subnet(network, 'apps'), 'properties').serviceEndpoints = endpoints(network).filter(
            (endpoint) => endpoint.service !== 'Microsoft.Storage',
          );
        }),
      ),
    ).toEqual(['evidence-store']);
    expect(
      only(
        changed(NETWORK, (network) => {
          nth(endpoints(network), 1).locations = ['westeurope'];
        }),
      ),
    ).toEqual(['evidence-store']);

    // The role: one data action, add a new file; never write, read, delete or any action.
    expect(at(staging.predictedResources.find(WRITER_ROLE)?.properties, 'permissions')).toEqual([
      {
        actions: [],
        notActions: [],
        dataActions: ['Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action'],
        notDataActions: [],
      },
    ]);
    const permissionsOf = (role: Mutable): Mutable => first(at(role, 'properties', 'permissions'));
    for (const change of [
      (role: Mutable) =>
        (at(permissionsOf(role), 'dataActions') as string[]).push(
          'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write',
        ),
      (role: Mutable) =>
        (permissionsOf(role).dataActions = ['Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read']),
      (role: Mutable) => (permissionsOf(role).dataActions = []),
      (role: Mutable) => (permissionsOf(role).actions = ['Microsoft.Storage/storageAccounts/read']),
      (role: Mutable) =>
        (inside(role, 'properties').assignableScopes = ['/subscriptions/00000000-0000-0000-0000-000000000001']),
    ]) {
      expect(only(changed(WRITER_ROLE, change))).toEqual(['evidence-store']);
    }
    // A wildcard is also `role-actions`' to refuse, for every role of ours.
    expect(only(changed(WRITER_ROLE, (role) => (permissionsOf(role).dataActions = ['*'])))).toEqual([
      'evidence-store',
      'role-actions',
    ]);
    // Without the role, its one grant names a role that isn't there.
    expect(only(without(WRITER_ROLE))).toEqual(['evidence-store']);
    // The grant: on the container alone, to the operator alone, once.
    const accountScope = (grant: Mutable): void => {
      grant.id = String(grant.id).replace('/blobServices/default/containers/audit-exports', '');
    };
    for (const change of [
      accountScope,
      (grant: Mutable) =>
        (grant.id = String(grant.id).replace(/^.*(?=\/providers\/Microsoft\.Authorization\/)/, group)),
      (grant: Mutable) =>
        (inside(grant, 'properties').principalId = String(at(grant, 'properties', 'principalId')).replace(
          'id-agentx-stg-operator',
          'id-agentx-stg-api',
        )),
      (grant: Mutable) => (inside(grant, 'properties').principalType = 'User'),
    ]) {
      expect(only(changed(WRITES, change))).toEqual(['evidence-store']);
    }
    expect(only(without(WRITES))).toEqual(['evidence-store']);
    const twice = structuredClone(staging.predictedResources.find(WRITES)) as unknown as Mutable;
    twice.id = `${String(twice.id)}-second`;
    expect(only(withExtra(twice))).toEqual(['evidence-store']);
    // Its role named as the policy works it out, as Bicep's guid() does.
    expect(staging.predictedResources.find(WRITER_ROLE)?.name).toBe(bicepGuid(group, 'evidence-writer'));
  });

  it("evidence-store: the operator's job told of another store or identity, or another workload told of the store (E10c-3b-2)", () => {
    const STORE = EVIDENCE_STORE;
    const evidence = (job: Mutable): Mutable[] =>
      settingsOf(job).filter((entry) => String(entry.name).startsWith('AGENTX_EVIDENCE_'));
    const named = (job: Mutable, name: string): Mutable => evidence(job).find((entry) => entry.name === name) ?? {};
    const account = String(staging.predictedResources.find(STORE)?.name);
    const operatorId = String(
      staging.predictedResources.find(
        (resource) =>
          resource.type === 'Microsoft.ManagedIdentity/userAssignedIdentities' && resource.name.endsWith('-operator'),
      )?.id,
    );
    // As apps.bicep writes them: this deployment's store and container, as the operator's identity.
    expect(evidence(staging.predictedResources.find(JOB('operator')) as unknown as Mutable)).toEqual([
      {
        name: 'AGENTX_EVIDENCE_CONTAINER_URL',
        value: `[format('https://{0}.blob.{1}/{2}', '${account}', environment().suffixes.storage, 'audit-exports')]`,
      },
      { name: 'AGENTX_EVIDENCE_CLIENT_ID', value: `[reference('${operatorId}', '2024-11-30').clientId]` },
    ]);
    const url = (job: Mutable): Mutable => named(job, 'AGENTX_EVIDENCE_CONTAINER_URL');
    const client = (job: Mutable): Mutable => named(job, 'AGENTX_EVIDENCE_CLIENT_ID');
    for (const change of [
      (job: Mutable) => (url(job).value = String(url(job).value).replace(`'${account}'`, "'stagentxother'")),
      (job: Mutable) => (url(job).value = String(url(job).value).replace("'audit-exports'", "'other'")),
      (job: Mutable) => (url(job).value = 'https://stagentxother.blob.core.windows.net/audit-exports'),
      (job: Mutable) => (client(job).value = String(client(job).value).replace('-operator', '-api')),
      (job: Mutable) => (client(job).value = '00000000-0000-0000-0000-000000000002'),
      (job: Mutable) => (url(job).value = String(url(job).value).replace("'https://", "'http://")),
      (job: Mutable) =>
        (url(job).value = String(url(job).value).replace('environment().suffixes.storage', "'example.com'")),
      (job: Mutable) => (client(job).value = String(client(job).value).replace('.clientId]', '.principalId]')),
      // Each value whole: nothing before or after the expression.
      (job: Mutable) => (url(job).value = `x${String(url(job).value)}`),
      (job: Mutable) => (url(job).value = `${String(url(job).value)}x`),
      (job: Mutable) => (client(job).value = `x${String(client(job).value)}`),
      (job: Mutable) => (client(job).value = `${String(client(job).value)}x`),
      (job: Mutable) => {
        delete url(job).value;
        url(job).secretRef = 'operator-request';
      },
      (job: Mutable) => {
        containerOf(job).env = settingsOf(job).filter((entry) => entry.name !== 'AGENTX_EVIDENCE_CLIENT_ID');
      },
      (job: Mutable) => settingsOf(job).push(structuredClone(url(job))),
      (job: Mutable) => settingsOf(job).push({ name: 'AGENTX_EVIDENCE_DIR', value: '/mnt/evidence' }),
    ]) {
      expect(brokenRules(changed(JOB('operator'), change))).toContain('evidence-store');
    }
    // An app named as the operator is not its job, so the job's own settings still refuse it.
    const operatorSettings = evidence(staging.predictedResources.find(JOB('operator')) as unknown as Mutable);
    expect(
      brokenRules(
        changed(APP('api'), (app) => {
          app.name = 'ca-agentx-stg-operator';
          settingsOf(app).push(...structuredClone(operatorSettings));
        }),
      ),
    ).toContain('evidence-store');
    // No other workload, job or app, is pointed at the store, or at a folder in its place.
    for (const pick of [APP('api'), JOB('migrate')]) {
      for (const name of ['AGENTX_EVIDENCE_CONTAINER_URL', 'AGENTX_EVIDENCE_DIR']) {
        const told = changed(pick, (resource) => settingsOf(resource).push({ name, value: 'x' }));
        expect({ name, rules: brokenRules(told) }).toEqual({ name, rules: ['evidence-store'] });
      }
    }
    expect(
      policyProblems(
        changed(APP('api'), (app) => settingsOf(app).push({ name: 'AGENTX_EVIDENCE_DIR', value: '/mnt/evidence' })),
        STAGING,
      ),
    ).toEqual([
      {
        rule: 'evidence-store',
        resource: 'ca-agentx-stg-api',
        message: "sets AGENTX_EVIDENCE_DIR: only the operator's and the chain repair's jobs write to the store",
      },
    ]);
  });

  it('evidence-store: the store back on the public route, or its private endpoint, zone or subnet opened (AZ11, PL-43)', () => {
    const ENDPOINT = type('Microsoft.Network/privateEndpoints');
    const ZONE_GROUP = type('Microsoft.Network/privateEndpoints/privateDnsZoneGroups');
    const BLOB_ZONE = (resource: PredictedResource) =>
      type('Microsoft.Network/privateDnsZones')(resource) && resource.name.startsWith('privatelink.blob.');
    const BLOB_LINK = (resource: PredictedResource) =>
      type('Microsoft.Network/privateDnsZones/virtualNetworkLinks')(resource) &&
      resource.name.startsWith('privatelink.blob.');
    const ENDPOINTS_RULES = (resource: PredictedResource) => RULES(resource) && resource.name.endsWith('-endpoints');
    const connection = (endpoint: Mutable): Mutable =>
      inside(first(at(endpoint, 'properties', 'privateLinkServiceConnections')), 'properties');
    const rules = (group: Mutable): Mutable[] => at(group, 'properties', 'securityRules') as Mutable[];
    const rule = (group: Mutable, name: string): Mutable =>
      inside(
        rules(group).find((each) => each.name === name),
        'properties',
      );
    const only = (snapshotted: Snapshot): RuleId[] => brokenRules(snapshotted);

    expect(at(staging.predictedResources.find(EVIDENCE_STORE)?.properties, 'publicNetworkAccess')).toBe('Disabled');
    for (const change of [
      (store: Mutable) => (inside(store, 'properties').publicNetworkAccess = 'Enabled'),
      (store: Mutable) => delete inside(store, 'properties').publicNetworkAccess,
    ]) {
      expect(only(changed(EVIDENCE_STORE, change))).toEqual(['evidence-store']);
    }
    // No endpoint, or a second.
    expect(only(without(ENDPOINT))).toEqual(['evidence-store']);
    const endpoint = staging.predictedResources.find(ENDPOINT);
    expect(only(withExtra({ ...structuredClone(endpoint), id: `${String(endpoint?.id)}-second` }))).toEqual([
      'evidence-store',
    ]);
    // To another account or service, by hand, or in another subnet.
    const downloads = idOf(DOWNLOADS_STORE);
    for (const change of [
      (found: Mutable) => (connection(found).privateLinkServiceId = downloads),
      (found: Mutable) => (connection(found).groupIds = ['file']),
      (found: Mutable) => (connection(found).groupIds = ['blob', 'file']),
      // A second connection, even one alike.
      (found: Mutable) => {
        const connections = at(found, 'properties', 'privateLinkServiceConnections') as Mutable[];
        inside(found, 'properties').privateLinkServiceConnections = [
          ...connections,
          structuredClone(first(connections)),
        ];
      },
      (found: Mutable) =>
        (inside(found, 'properties').manualPrivateLinkServiceConnections = [
          { name: 'other', properties: { privateLinkServiceId: downloads, groupIds: ['blob'] } },
        ]),
      (found: Mutable) =>
        (inside(found, 'properties', 'subnet').id = String(at(found, 'properties', 'subnet', 'id')).replace(
          /\/endpoints$/,
          '/apps',
        )),
    ]) {
      expect(only(changed(ENDPOINT, change))).toEqual(['evidence-store']);
    }
    // Its address kept nowhere, in the database's zone, or in a zone not linked to the network.
    expect(only(without(ZONE_GROUP))).toEqual(['evidence-store']);
    expect(
      only(
        changed(
          ZONE_GROUP,
          (group) =>
            (inside(first(at(group, 'properties', 'privateDnsZoneConfigs')), 'properties').privateDnsZoneId = idOf(
              DATABASE_DNS('Microsoft.Network/privateDnsZones'),
            )),
        ),
      ),
    ).toEqual(['evidence-store']);
    // A second zone config, even one alike.
    expect(
      only(
        changed(ZONE_GROUP, (group) => {
          const configs = at(group, 'properties', 'privateDnsZoneConfigs') as Mutable[];
          inside(group, 'properties').privateDnsZoneConfigs = [...configs, structuredClone(first(configs))];
        }),
      ),
    ).toEqual(['evidence-store']);
    // The link without its fallback to public names: other accounts behind private endpoints stop resolving.
    for (const change of [
      (link: Mutable) => delete inside(link, 'properties').resolutionPolicy,
      (link: Mutable) => (inside(link, 'properties').resolutionPolicy = 'Default'),
    ]) {
      expect(only(changed(BLOB_LINK, change))).toEqual(['evidence-store']);
    }
    expect(only(without(BLOB_LINK))).toEqual(['evidence-store']);
    expect(only(without(BLOB_ZONE))).toEqual(['evidence-store']);
    expect(
      only(
        changed(
          BLOB_LINK,
          (link) => (inside(link, 'properties', 'virtualNetwork').id = '/subscriptions/x/virtualNetworks/other'),
        ),
      ),
    ).toEqual(['evidence-store']);
    // A second link to another network, or one registering names (review S192).
    const link = staging.predictedResources.find(BLOB_LINK);
    for (const extra of [
      { virtualNetwork: { id: '/subscriptions/x/virtualNetworks/other' } },
      { registrationEnabled: true },
    ]) {
      const copy = structuredClone(link) as unknown as Mutable;
      copy.id = `${String(link?.id)}-second`;
      Object.assign(inside(copy, 'properties'), extra);
      expect(only(withExtra(copy))).toEqual(['evidence-store']);
    }
    // The endpoints subnet left out of the network's own list (written apart, its rules unread): fails closed;
    // the apps' door to it then matches no subnet either.
    expect(
      only(
        changed(NETWORK, (network) => {
          const properties = inside(network, 'properties');
          properties.subnets = (properties.subnets as Mutable[]).filter((each) => each.name !== 'endpoints');
        }),
      ),
    ).toEqual(['apps-egress', 'evidence-store']);
    // The endpoints subnet delegated, skipping its rules, or letting in more, or anything out.
    for (const change of [
      (network: Mutable) =>
        (inside(subnet(network, 'endpoints'), 'properties').delegations = [
          { name: 'x', properties: { serviceName: 'Microsoft.App/environments' } },
        ]),
      (network: Mutable) =>
        (inside(subnet(network, 'endpoints'), 'properties').privateEndpointNetworkPolicies = 'Disabled'),
    ]) {
      expect(only(changed(NETWORK, change))).toEqual(['evidence-store']);
    }
    for (const change of [
      (group: Mutable) => (rule(group, 'allow-https-from-apps').sourceAddressPrefix = 'VirtualNetwork'),
      (group: Mutable) => (rule(group, 'allow-https-from-apps').destinationPortRange = '*'),
      (group: Mutable) => (rule(group, 'allow-https-from-apps').protocol = '*'),
      (group: Mutable) => (rule(group, 'deny-rest-of-network').access = 'Allow'),
      // The backstop gone, or a Deny placed before the allow, so it is no backstop.
      (group: Mutable) => {
        group.properties = { securityRules: rules(group).filter((each) => each.name !== 'deny-rest-of-network') };
      },
      (group: Mutable) => (rule(group, 'deny-rest-of-network').priority = 90),
      (group: Mutable) => (rule(group, 'deny-out-rest').access = 'Allow'),
      (group: Mutable) => {
        group.properties = { securityRules: rules(group).filter((each) => each.name !== 'allow-https-from-apps') };
      },
    ]) {
      expect(only(changed(ENDPOINTS_RULES, change))).toEqual(['evidence-store']);
    }
    // The apps without their door to it.
    expect(
      only(
        changed(APPS_RULES, (group) => {
          group.properties = { securityRules: rules(group).filter((each) => each.name !== 'allow-out-endpoints') };
        }),
      ),
    ).toEqual(['apps-egress']);
  });

  describe("evidence-store: the chains' anchors (4D2e E, PL-58)", () => {
    const ACTIONS_OF = 'Microsoft.Storage/storageAccounts/blobServices/containers/blobs';
    const ANCHORS = (resource: PredictedResource) =>
      IN_EVIDENCE_STORE('Microsoft.Storage/storageAccounts/blobServices/containers')(resource) &&
      resource.id.endsWith('/audit-anchors');
    const ROLE = (resource: PredictedResource) =>
      ROLE_DEFINITIONS(resource) &&
      resource.name ===
        bicepGuid(
          String(staging.predictedResources.find(type('Microsoft.Resources/resourceGroups'))?.id),
          'audit-anchors',
        );
    const KEEPS = (resource: PredictedResource) =>
      ASSIGNMENTS(resource) && String(at(resource.properties, 'description')).startsWith('api keeps audit anchors');
    const WRITES = (resource: PredictedResource) =>
      ASSIGNMENTS(resource) && String(at(resource.properties, 'description')).startsWith('operator adds audit exports');
    const permissionsOf = (role: Mutable): Mutable => first(at(role, 'properties', 'permissions'));

    it("a second container in the write-once account, private, kept by the account's own policy", () => {
      expect(staging.predictedResources.filter(ANCHORS)).toHaveLength(1);
      expect(brokenRules(changed(ANCHORS, (found) => (inside(found, 'properties').publicAccess = 'Blob')))).toEqual([
        'evidence-store',
      ]);
      expect(brokenRules(without(ANCHORS))).toEqual(['required', 'evidence-store']);
      // A third of any name, or a container of another name in its place.
      const third = structuredClone(staging.predictedResources.find(ANCHORS)) as unknown as Mutable;
      third.id = String(third.id).replace(/audit-anchors$/, 'audit-other');
      expect(brokenRules(withExtra(third))).toEqual(['required', 'evidence-store']);
      expect(
        brokenRules(changed(ANCHORS, (found) => (found.id = String(found.id).replace(/audit-anchors$/, 'other')))),
      ).toEqual(['evidence-store']);
      // In the downloads' account instead, it is that account's second container.
      expect(
        brokenRules(changed(ANCHORS, (found) => (found.id = String(found.id).replace(/stagentxstg/, 'stagentxdlstg')))),
      ).toContain('evidence-store');
    });

    it('its role adds a new file and reads, and can never overwrite or delete', () => {
      expect(at(staging.predictedResources.find(ROLE)?.properties, 'permissions')).toEqual([
        {
          actions: [],
          notActions: [],
          dataActions: [`${ACTIONS_OF}/add/action`, `${ACTIONS_OF}/read`],
          notDataActions: [],
        },
      ]);
      for (const change of [
        (role: Mutable) => (at(permissionsOf(role), 'dataActions') as string[]).push(`${ACTIONS_OF}/write`),
        (role: Mutable) => (at(permissionsOf(role), 'dataActions') as string[]).push(`${ACTIONS_OF}/delete`),
        (role: Mutable) => (permissionsOf(role).dataActions = [`${ACTIONS_OF}/read`]),
        (role: Mutable) => (permissionsOf(role).dataActions = [`${ACTIONS_OF}/add/action`]),
        (role: Mutable) => (permissionsOf(role).actions = ['Microsoft.Storage/storageAccounts/read']),
        (role: Mutable) =>
          (inside(role, 'properties').assignableScopes = ['/subscriptions/00000000-0000-0000-0000-000000000001']),
      ]) {
        expect(brokenRules(changed(ROLE, change))).toEqual(['evidence-store']);
      }
      // A wildcard is also `role-actions`' to refuse, for every role of ours.
      expect(brokenRules(changed(ROLE, (role) => (permissionsOf(role).dataActions = ['*'])))).toEqual([
        'evidence-store',
        'role-actions',
      ]);
      expect(brokenRules(without(ROLE))).toEqual(['evidence-store']);
    });

    it('given once, on its own container alone, to the API alone; the exports role stays on the exports', () => {
      const replaced = (grant: Mutable): void => {
        grant.id = String(grant.id).replace('/containers/audit-anchors', '/containers/audit-exports');
      };
      for (const change of [
        replaced,
        (grant: Mutable) => (grant.id = String(grant.id).replace('/blobServices/default/containers/audit-anchors', '')),
        (grant: Mutable) =>
          (inside(grant, 'properties').principalId = String(at(grant, 'properties', 'principalId')).replace(
            'id-agentx-stg-api',
            'id-agentx-stg-operator',
          )),
        (grant: Mutable) => (inside(grant, 'properties').principalType = 'User'),
      ]) {
        expect(brokenRules(changed(KEEPS, change))).toEqual(['evidence-store']);
      }
      expect(brokenRules(without(KEEPS))).toEqual(['evidence-store']);
      const twice = structuredClone(staging.predictedResources.find(KEEPS)) as unknown as Mutable;
      twice.id = `${String(twice.id)}-second`;
      expect(brokenRules(withExtra(twice))).toEqual(['evidence-store']);
      // The operator's role moved onto the anchors: it could then add a file a restart reads.
      expect(
        brokenRules(
          changed(WRITES, (grant) => {
            grant.id = String(grant.id).replace('/containers/audit-exports', '/containers/audit-anchors');
          }),
        ),
      ).toEqual(['evidence-store']);
    });

    it('the app holding the jobs alone is told of it, with its own identity (4D2e D13)', () => {
      const STORE_NAME = String(staging.predictedResources.find(EVIDENCE_STORE)?.name);
      const anchorSettings = (app: Mutable): Mutable[] =>
        settingsOf(app).filter((entry) => String(entry.name).startsWith('AGENTX_AUDIT_ANCHORS_'));
      const apiId = String(
        staging.predictedResources.find(
          (resource) =>
            resource.type === 'Microsoft.ManagedIdentity/userAssignedIdentities' && resource.name.endsWith('-api'),
        )?.id,
      );
      expect(anchorSettings(staging.predictedResources.find(APP('api')) as unknown as Mutable)).toEqual([
        {
          name: 'AGENTX_AUDIT_ANCHORS_URL',
          value: `[format('https://{0}.blob.{1}/{2}', '${STORE_NAME}', environment().suffixes.storage, 'audit-anchors')]`,
        },
        { name: 'AGENTX_AUDIT_ANCHORS_CLIENT_ID', value: `[reference('${apiId}', '2024-11-30').clientId]` },
      ]);
      const url = (app: Mutable): Mutable =>
        anchorSettings(app).find((entry) => entry.name === 'AGENTX_AUDIT_ANCHORS_URL') ?? {};
      for (const change of [
        (app: Mutable) => (url(app).value = String(url(app).value).replace("'audit-anchors'", "'audit-exports'")),
        (app: Mutable) => (url(app).value = String(url(app).value).replace(`'${STORE_NAME}'`, "'stagentxother'")),
        (app: Mutable) => settingsOf(app).push({ name: 'AGENTX_AUDIT_ANCHORS_DIR', value: '/mnt/anchors' }),
        (app: Mutable) => {
          containerOf(app).env = settingsOf(app).filter((entry) => entry.name !== 'AGENTX_AUDIT_ANCHORS_CLIENT_ID');
        },
        // The operator holds the same role (E11): the API told of the operator's identity is still refused.
        (app: Mutable) => {
          const clientId = anchorSettings(app).find((entry) => entry.name === 'AGENTX_AUDIT_ANCHORS_CLIENT_ID') ?? {};
          clientId.value = String(clientId.value).replace(apiId, apiId.replace(/-api$/, '-operator'));
        },
      ]) {
        expect(brokenRules(changed(APP('api'), change))).toEqual(['evidence-store']);
      }
      const told = changed(JOB('migrate'), (job) =>
        settingsOf(job).push({ name: 'AGENTX_AUDIT_ANCHORS_URL', value: 'x' }),
      );
      expect(policyProblems(told, STAGING)).toEqual([
        {
          rule: 'evidence-store',
          resource: 'job-agentx-stg-migrate',
          message:
            "sets AGENTX_AUDIT_ANCHORS_URL: only the app that holds the jobs and the operator's job keep the chains' anchors and the chain repair's job reads them",
        },
      ]);
    });

    it("in production the jobs app's identity alone keeps them, and a web copy is never told of them (4D2e D13)", () => {
      const production = { region: 'uaenorth', environment: 'production' } as const;
      const split = productionLike({ subject: true });
      const anchorRules = (snapshotted: Snapshot) =>
        policyProblems(snapshotted, production).filter(({ rule }) => rule === 'evidence-store');
      expect(anchorRules(split)).toEqual([]);
      const jobsKeeps = (resource: PredictedResource) =>
        ASSIGNMENTS(resource) &&
        at(resource.properties, 'description') === 'jobs keeps audit anchors (deploy/azure/modules/evidence.bicep)';
      const apiId = String(
        split.predictedResources.find(
          (resource) =>
            resource.type === 'Microsoft.ManagedIdentity/userAssignedIdentities' && resource.name.endsWith('-api'),
        )?.id,
      );
      // The API's identity given the role beside the jobs', as staging's is: production's web copies may not hold it.
      const apiKeeps = structuredClone(split.predictedResources.find(jobsKeeps)) as unknown as Mutable;
      apiKeeps.id = `${String(apiKeeps.id)}-api`;
      inside(apiKeeps, 'properties').principalId = String(at(apiKeeps, 'properties', 'principalId')).replace(
        'id-agentx-stg-jobs',
        'id-agentx-stg-api',
      );
      expect(
        anchorRules({
          ...split,
          predictedResources: [...split.predictedResources, apiKeeps as unknown as PredictedResource],
        }),
      ).not.toEqual([]);
      // Its role taken from the jobs app's identity, or the jobs app told the API's identity.
      expect(
        anchorRules({
          ...split,
          predictedResources: split.predictedResources.filter((resource) => !jobsKeeps(resource)),
        }),
      ).not.toEqual([]);
      const asApi = changed(
        APP('jobs'),
        (app) => {
          const clientId = settingsOf(app).find((entry) => entry.name === 'AGENTX_AUDIT_ANCHORS_CLIENT_ID') ?? {};
          clientId.value = `[reference('${apiId}', '2024-11-30').clientId]`;
        },
        split,
      );
      expect(anchorRules(asApi).map(({ resource }) => resource)).toEqual(['ca-agentx-stg-jobs']);
      // A web copy told where they are, even as its own identity, which has no role there in production.
      const webTold = changed(
        APP('api'),
        (app) =>
          settingsOf(app).push(
            ...settingsOf(split.predictedResources.find(APP('jobs')) as unknown as Mutable)
              .filter((entry) => String(entry.name).startsWith('AGENTX_AUDIT_ANCHORS_'))
              .map((entry) => ({
                ...entry,
                value: String(entry.value).replace('id-agentx-stg-jobs', 'id-agentx-stg-api'),
              })),
          ),
        split,
      );
      expect(anchorRules(webTold)).toEqual([
        {
          rule: 'evidence-store',
          resource: 'ca-agentx-stg-api',
          message:
            "sets AGENTX_AUDIT_ANCHORS_URL, AGENTX_AUDIT_ANCHORS_CLIENT_ID: only the app that holds the jobs and the operator's job keep the chains' anchors and the chain repair's job reads them",
        },
      ]);
    });

    /** An identity's resource ID, by the work it does. */
    const identityId = (workload: string): string =>
      String(
        staging.predictedResources.find(
          (resource) =>
            resource.type === 'Microsoft.ManagedIdentity/userAssignedIdentities' &&
            resource.name.endsWith(`-${workload}`),
        )?.id,
      );

    describe("the operator's hold on it, for a chain recovery plan (4D2e E9) and its rebases (E11)", () => {
      // The chain repair's read-only role (4D2e E10); the operator holds the API's own role instead.
      const READER = (resource: PredictedResource) =>
        ROLE_DEFINITIONS(resource) &&
        resource.name ===
          bicepGuid(
            String(staging.predictedResources.find(type('Microsoft.Resources/resourceGroups'))?.id),
            'audit-anchors-reader',
          );
      const READS = (resource: PredictedResource) =>
        ASSIGNMENTS(resource) &&
        String(at(resource.properties, 'description')).startsWith('operator reads and adds audit anchors');
      const roleIdOf = (find: (resource: PredictedResource) => boolean): unknown =>
        at(staging.predictedResources.find(find)?.properties, 'roleDefinitionId');

      it("holds the API's role, to read, list and add a rebase; the read-only role, given to it, is refused", () => {
        expect(roleIdOf(READS)).toEqual(roleIdOf(KEEPS));
        const readOnly = changed(READS, (grant: Mutable) => {
          inside(grant, 'properties').roleDefinitionId = String(roleIdOf(READS)).replace(
            String(staging.predictedResources.find(ROLE)?.name),
            String(staging.predictedResources.find(READER)?.name),
          );
        });
        expect(brokenRules(readOnly)).toEqual(['evidence-store']);
      });

      it("the chain repair's role reads and lists, and can add, overwrite or delete nothing", () => {
        expect(at(staging.predictedResources.find(READER)?.properties, 'permissions')).toEqual([
          { actions: [], notActions: [], dataActions: [`${ACTIONS_OF}/read`], notDataActions: [] },
        ]);
        for (const change of [
          (role: Mutable) => (at(permissionsOf(role), 'dataActions') as string[]).push(`${ACTIONS_OF}/add/action`),
          (role: Mutable) => (at(permissionsOf(role), 'dataActions') as string[]).push(`${ACTIONS_OF}/write`),
          (role: Mutable) => (at(permissionsOf(role), 'dataActions') as string[]).push(`${ACTIONS_OF}/delete`),
          (role: Mutable) => (permissionsOf(role).actions = ['Microsoft.Storage/storageAccounts/read']),
        ]) {
          expect(brokenRules(changed(READER, change))).toEqual(['evidence-store']);
        }
        expect(brokenRules(without(READER))).toEqual(['evidence-store']);
      });

      it('given once, on the anchors container alone, to the operator alone', () => {
        for (const change of [
          (grant: Mutable) => {
            grant.id = String(grant.id).replace('/containers/audit-anchors', '/containers/audit-exports');
          },
          (grant: Mutable) =>
            (inside(grant, 'properties').principalId = String(at(grant, 'properties', 'principalId')).replace(
              'id-agentx-stg-operator',
              'id-agentx-stg-api',
            )),
          (grant: Mutable) => (inside(grant, 'properties').principalType = 'User'),
        ]) {
          expect(brokenRules(changed(READS, change))).toEqual(['evidence-store']);
        }
        expect(brokenRules(without(READS))).toEqual(['evidence-store']);
        const twice = structuredClone(staging.predictedResources.find(READS)) as unknown as Mutable;
        twice.id = `${String(twice.id)}-second`;
        expect(brokenRules(withExtra(twice))).toEqual(['evidence-store']);
      });

      it("the operator's job is told of it as its own identity, and of the public key staging's API logged (S173)", () => {
        const STORE_NAME = String(staging.predictedResources.find(EVIDENCE_STORE)?.name);
        const operator = staging.predictedResources.find(JOB('operator')) as unknown as Mutable;
        expect(settingsOf(operator).filter((entry) => String(entry.name).startsWith('AGENTX_AUDIT_ANCHOR'))).toEqual([
          {
            name: 'AGENTX_AUDIT_ANCHORS_URL',
            value: `[format('https://{0}.blob.{1}/{2}', '${STORE_NAME}', environment().suffixes.storage, 'audit-anchors')]`,
          },
          {
            name: 'AGENTX_AUDIT_ANCHORS_CLIENT_ID',
            value: `[reference('${identityId('operator')}', '2024-11-30').clientId]`,
          },
          { name: 'AGENTX_AUDIT_ANCHOR_PUBLIC_KEYS', value: '1:YGJbtqiqwcHQT32ByJhe-28JTKwrMacr8rHCj_S91No' },
        ]);
        // Told the API's identity, it would ask for a token it holds no role as.
        const asApi = changed(JOB('operator'), (job) => {
          const clientId = settingsOf(job).find((entry) => entry.name === 'AGENTX_AUDIT_ANCHORS_CLIENT_ID') ?? {};
          clientId.value = `[reference('${identityId('api')}', '2024-11-30').clientId]`;
        });
        expect(brokenRules(asApi)).toEqual(['evidence-store']);
      });
    });

    describe("the chain repair's reads and records (4D2e E10), as its own identity alone", () => {
      const restorerGrant = (what: string) => (resource: PredictedResource) =>
        ASSIGNMENTS(resource) && String(at(resource.properties, 'description')).startsWith(`chain-restore ${what}`);

      it('is told of both stores as its own identity: named the operator’s, it is refused', () => {
        const restorer = staging.predictedResources.find(JOB('chain-restore')) as unknown as Mutable;
        const clientIds = settingsOf(restorer).filter((entry) => String(entry.name).endsWith('_CLIENT_ID'));
        expect(clientIds).toEqual([
          {
            name: 'AGENTX_EVIDENCE_CLIENT_ID',
            value: `[reference('${identityId('chain-restore')}', '2024-11-30').clientId]`,
          },
          {
            name: 'AGENTX_AUDIT_ANCHORS_CLIENT_ID',
            value: `[reference('${identityId('chain-restore')}', '2024-11-30').clientId]`,
          },
        ]);
        for (const setting of ['AGENTX_EVIDENCE_CLIENT_ID', 'AGENTX_AUDIT_ANCHORS_CLIENT_ID']) {
          const asOperator = changed(JOB('chain-restore'), (job) => {
            const clientId = settingsOf(job).find((entry) => entry.name === setting) ?? {};
            clientId.value = `[reference('${identityId('operator')}', '2024-11-30').clientId]`;
          });
          expect({ setting, rules: brokenRules(asOperator) }).toEqual({ setting, rules: ['evidence-store'] });
        }
      });

      it('its read of the plans reads alone, on the exports alone', () => {
        const READER = (resource: PredictedResource) =>
          ROLE_DEFINITIONS(resource) &&
          resource.name ===
            bicepGuid(
              String(staging.predictedResources.find(type('Microsoft.Resources/resourceGroups'))?.id),
              'evidence-plan-reader',
            );
        expect(at(staging.predictedResources.find(READER)?.properties, 'permissions')).toEqual([
          { actions: [], notActions: [], dataActions: [`${ACTIONS_OF}/read`], notDataActions: [] },
        ]);
        for (const change of [
          (role: Mutable) => (at(permissionsOf(role), 'dataActions') as string[]).push(`${ACTIONS_OF}/write`),
          (role: Mutable) => (at(permissionsOf(role), 'dataActions') as string[]).push(`${ACTIONS_OF}/delete`),
        ]) {
          expect(brokenRules(changed(READER, change))).toEqual(['evidence-store']);
        }
        const onAnchors = changed(restorerGrant('reads recovery plans'), (grant: Mutable) => {
          grant.id = String(grant.id).replace('/containers/audit-exports', '/containers/audit-anchors');
        });
        expect(brokenRules(onAnchors)).toEqual(['evidence-store']);
      });

      it('each of its three roles given once, to its identity: gone, or given to the API instead, is refused', () => {
        for (const what of ['adds chain repair records', 'reads audit anchors', 'reads recovery plans']) {
          expect({ what, rules: brokenRules(without(restorerGrant(what))) }).toEqual({
            what,
            rules: ['evidence-store'],
          });
          const toApi = changed(restorerGrant(what), (grant: Mutable) => {
            inside(grant, 'properties').principalId = String(at(grant, 'properties', 'principalId')).replace(
              'id-agentx-stg-chain-restore',
              'id-agentx-stg-api',
            );
          });
          expect({ what, rules: brokenRules(toApi) }).toEqual({ what, rules: ['evidence-store'] });
        }
      });
    });
  });

  it("anchor-epoch: the operator told another epoch than the API's, or none, or another workload told one (4D2e E9)", () => {
    const epochOf = (workload: Mutable): unknown[] =>
      settingsOf(workload)
        .filter((entry) => entry.name === 'AGENTX_ANCHOR_EPOCH')
        .map((entry) => entry.value);
    const api = epochOf(staging.predictedResources.find(APP('api')) as unknown as Mutable);
    expect(api).toHaveLength(1);
    expect(epochOf(staging.predictedResources.find(JOB('operator')) as unknown as Mutable)).toEqual(api);
    const epoch = (job: Mutable): Mutable =>
      settingsOf(job).find((entry) => entry.name === 'AGENTX_ANCHOR_EPOCH') ?? {};
    for (const change of [
      (job: Mutable) => (epoch(job).value = '2'),
      (job: Mutable) => {
        containerOf(job).env = settingsOf(job).filter((entry) => entry.name !== 'AGENTX_ANCHOR_EPOCH');
      },
      (job: Mutable) => settingsOf(job).push({ name: 'AGENTX_ANCHOR_EPOCH', value: api[0] }),
    ]) {
      expect(brokenRules(changed(JOB('operator'), change))).toEqual(['anchor-epoch']);
    }
    expect(brokenRules(changed(APP('api'), (app) => (epoch(app).value = '3')))).toEqual(['anchor-epoch']);
    const told = changed(JOB('migrate'), (job) => settingsOf(job).push({ name: 'AGENTX_ANCHOR_EPOCH', value: api[0] }));
    expect(policyProblems(told, STAGING)).toEqual([
      {
        rule: 'anchor-epoch',
        resource: 'job-agentx-stg-migrate',
        message:
          "sets AGENTX_ANCHOR_EPOCH: only the app that holds the jobs, the operator's job and the chain repair's",
      },
    ]);
  });

  it('activity-downloads: a downloads store anyone else can reach, that keeps a file past its week, or that another identity uses (L5c, decision 31)', () => {
    const BLOBS = IN_DOWNLOADS_STORE('Microsoft.Storage/storageAccounts/blobServices');
    const CONTAINER = IN_DOWNLOADS_STORE('Microsoft.Storage/storageAccounts/blobServices/containers');
    const LIFECYCLE = IN_DOWNLOADS_STORE('Microsoft.Storage/storageAccounts/managementPolicies');
    const group = String(staging.predictedResources.find(type('Microsoft.Resources/resourceGroups'))?.id);
    const ROLE = (resource: PredictedResource) =>
      ROLE_DEFINITIONS(resource) && resource.name === bicepGuid(group, 'activity-downloads');
    const KEEPS = (resource: PredictedResource) =>
      ASSIGNMENTS(resource) &&
      String(at(resource.properties, 'description')).startsWith('api keeps activity downloads');
    const properties = (found: Mutable): Mutable => inside(found, 'properties');
    const only = (snapshotted: Snapshot): RuleId[] => brokenRules(snapshotted);

    // As the module makes it: within Azure's 24 characters, one copy, not write-once.
    const store = staging.predictedResources.find(DOWNLOADS_STORE);
    expect(store?.name).toMatch(/^stagentxdlstg[a-z0-9]{6}$/);
    expect(String(store?.name).length).toBeLessThanOrEqual(24);
    expect(at(store?.properties, 'immutableStorageWithVersioning')).toBeUndefined();
    for (const change of [
      ...OPENED_ACCOUNT,
      (found: Mutable) => (inside(found, 'sku').name = 'Standard_ZRS'),
      // Write-once would refuse a month built again over its own name, and keep it past its week.
      (found: Mutable) =>
        (properties(found).immutableStorageWithVersioning = {
          enabled: true,
          immutabilityPolicy: { immutabilityPeriodSinceCreationInDays: 1, state: 'Unlocked' },
        }),
      (found: Mutable) =>
        (properties(found).immutableStorageWithVersioning = {
          immutabilityPolicy: { immutabilityPeriodSinceCreationInDays: 1, state: 'Unlocked' },
        }),
    ]) {
      expect(only(changed(DOWNLOADS_STORE, change))).toEqual(['activity-downloads']);
    }

    // Versions or soft delete kept, a container open to anyone or named otherwise, or a blob service not the default.
    for (const change of [
      (found: Mutable) => (properties(found).isVersioningEnabled = true),
      (found: Mutable) => delete properties(found).isVersioningEnabled,
      (found: Mutable) => (properties(found).deleteRetentionPolicy = { enabled: true, days: 7 }),
      (found: Mutable) => delete properties(found).deleteRetentionPolicy,
    ]) {
      expect(only(changed(BLOBS, change))).toEqual(['activity-downloads']);
    }
    expect(only(changed(CONTAINER, (found) => (properties(found).publicAccess = 'Blob')))).toEqual([
      'activity-downloads',
    ]);
    expect(
      only(changed(CONTAINER, (found) => (found.id = String(found.id).replace(/activity-downloads$/, 'other')))),
    ).toEqual(['activity-downloads']);
    expect(only(changed(BLOBS, (found) => (found.id = String(found.id).replace(/default$/, 'second'))))).toEqual([
      'activity-downloads',
      'resource-logs',
    ]);

    // The lifecycle rule: every file in the container, deleted within 14 days of its making (decision 32e).
    expect(at(staging.predictedResources.find(LIFECYCLE)?.properties, 'policy', 'rules')).toEqual([
      {
        name: 'delete-after-two-weeks',
        enabled: true,
        type: 'Lifecycle',
        definition: {
          filters: { blobTypes: ['blockBlob'], prefixMatch: ['activity-downloads/'] },
          actions: { baseBlob: { delete: { daysAfterCreationGreaterThan: 14 } } },
        },
      },
    ]);
    const rule = (found: Mutable): Mutable => first(at(found, 'properties', 'policy', 'rules'));
    const filters = (found: Mutable): Mutable => inside(rule(found), 'definition', 'filters');
    const deletion = (found: Mutable): Mutable => inside(rule(found), 'definition', 'actions', 'baseBlob', 'delete');
    expect(only(without(LIFECYCLE))).toEqual(['activity-downloads']);
    for (const change of [
      (found: Mutable) => (rule(found).enabled = false),
      (found: Mutable) => (rule(found).type = 'Other'),
      (found: Mutable) => (filters(found).blobTypes = ['appendBlob']),
      (found: Mutable) => (filters(found).prefixMatch = ['other/']),
      (found: Mutable) => (filters(found).prefixMatch = ['activity-downloads/', 'activity-downloads/x']),
      (found: Mutable) => (filters(found).blobIndexMatch = [{ name: 'keep', op: '==', value: 'yes' }]),
      (found: Mutable) => (deletion(found).daysAfterCreationGreaterThan = 15),
      (found: Mutable) => (deletion(found).daysAfterCreationGreaterThan = 30),
      (found: Mutable) => (deletion(found).daysAfterCreationGreaterThan = '14'),
      (found: Mutable) => {
        delete deletion(found).daysAfterCreationGreaterThan;
        deletion(found).daysAfterModificationGreaterThan = 14;
      },
      (found: Mutable) => (inside(found, 'properties', 'policy').rules = []),
      (found: Mutable) => (found.id = String(found.id).replace(/default$/, 'second')),
    ]) {
      expect(only(changed(LIFECYCLE, change))).toEqual(['activity-downloads']);
    }
    // Sooner, or every file in the account, is no weaker.
    expect(only(changed(LIFECYCLE, (found) => (deletion(found).daysAfterCreationGreaterThan = 7)))).toEqual([]);
    expect(only(changed(LIFECYCLE, (found) => delete filters(found).prefixMatch))).toEqual([]);
    // A second rule, or any other Storage resource in the store.
    const lifecycle = staging.predictedResources.find(LIFECYCLE);
    expect(only(withExtra({ ...structuredClone(lifecycle), id: `${String(lifecycle?.id)}-second` }))).toEqual([
      'activity-downloads',
    ]);
    expect(
      only(
        withExtra({
          id: `${String(store?.id)}/fileServices/default`,
          type: 'Microsoft.Storage/storageAccounts/fileServices',
          name: `${String(store?.name)}/default`,
          apiVersion: '2025-01-01',
          properties: {},
        }),
      ),
    ).toEqual(['activity-downloads']);
    // A second store, or a Storage account named as neither.
    expect(only(withExtra({ ...structuredClone(store), id: `${String(store?.id)}-second` }))).toEqual([
      'required',
      'activity-downloads',
    ]);
    expect(
      only(
        withExtra({
          ...structuredClone(store),
          id: String(store?.id).replace(/stagentxdl/, 'stagentxother'),
          name: String(store?.name).replace(/stagentxdl/, 'stagentxother'),
        }),
      ),
    ).toEqual(['required', 'evidence-store']);
    expect(only(without(DOWNLOADS_STORE))).toContain('activity-downloads');

    // The role: read and write a file, nothing more; never delete, list keys or any action.
    expect(at(staging.predictedResources.find(ROLE)?.properties, 'permissions')).toEqual([
      {
        actions: [],
        notActions: [],
        dataActions: [
          'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read',
          'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write',
        ],
        notDataActions: [],
      },
    ]);
    const permissionsOf = (role: Mutable): Mutable => first(at(role, 'properties', 'permissions'));
    for (const change of [
      (role: Mutable) =>
        (at(permissionsOf(role), 'dataActions') as string[]).push(
          'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete',
        ),
      (role: Mutable) =>
        (permissionsOf(role).dataActions = ['Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read']),
      (role: Mutable) => (permissionsOf(role).dataActions = []),
      (role: Mutable) => (permissionsOf(role).actions = ['Microsoft.Storage/storageAccounts/read']),
      (role: Mutable) =>
        (inside(role, 'properties').assignableScopes = ['/subscriptions/00000000-0000-0000-0000-000000000001']),
    ]) {
      expect(only(changed(ROLE, change))).toEqual(['activity-downloads']);
    }
    // A wildcard is also `role-actions`' to refuse, for every role of ours.
    expect(only(changed(ROLE, (role) => (permissionsOf(role).dataActions = ['*'])))).toEqual([
      'activity-downloads',
      'role-actions',
    ]);
    expect(only(without(ROLE))).toEqual(['activity-downloads']);
    expect(staging.predictedResources.find(ROLE)?.name).toBe(bicepGuid(group, 'activity-downloads'));

    // The grant: on the container alone, to the API alone, once.
    for (const change of [
      (grant: Mutable) =>
        (grant.id = String(grant.id).replace('/blobServices/default/containers/activity-downloads', '')),
      (grant: Mutable) =>
        (grant.id = String(grant.id).replace(/^.*(?=\/providers\/Microsoft\.Authorization\/)/, group)),
      (grant: Mutable) =>
        (inside(grant, 'properties').principalId = String(at(grant, 'properties', 'principalId')).replace(
          'id-agentx-stg-api',
          'id-agentx-stg-operator',
        )),
      (grant: Mutable) => (inside(grant, 'properties').principalType = 'User'),
    ]) {
      expect(only(changed(KEEPS, change))).toEqual(['activity-downloads']);
    }
    expect(only(without(KEEPS))).toEqual(['activity-downloads']);
    const twice = structuredClone(staging.predictedResources.find(KEEPS)) as unknown as Mutable;
    twice.id = `${String(twice.id)}-second`;
    expect(only(withExtra(twice))).toEqual(['activity-downloads']);
    // Nor is the audit exports' role given on the downloads container.
    const exports = String(
      staging.predictedResources.find(IN_EVIDENCE_STORE('Microsoft.Storage/storageAccounts/blobServices/containers'))
        ?.id,
    );
    const downloads = String(staging.predictedResources.find(CONTAINER)?.id);
    expect(
      only(
        changed(
          (resource) =>
            ASSIGNMENTS(resource) &&
            String(at(resource.properties, 'description')).startsWith('operator adds audit exports'),
          (grant) => (grant.id = String(grant.id).replace(exports, downloads)),
        ),
      ),
    ).toEqual(['evidence-store']);
  });

  it('activity-downloads: the API told of another store or identity, or another workload told of the store (L5c)', () => {
    const downloads = (workload: Mutable): Mutable[] =>
      settingsOf(workload).filter((entry) => String(entry.name).startsWith('AGENTX_ACTIVITY_DOWNLOADS_'));
    const named = (workload: Mutable, name: string): Mutable =>
      downloads(workload).find((entry) => entry.name === name) ?? {};
    const account = String(staging.predictedResources.find(DOWNLOADS_STORE)?.name);
    const exports = String(staging.predictedResources.find(EVIDENCE_STORE)?.name);
    const apiId = String(
      staging.predictedResources.find((resource) => IDENTITIES(resource) && resource.name.endsWith('-api'))?.id,
    );
    // As apps.bicep writes them: this deployment's downloads store and container, as the API's identity.
    expect(downloads(staging.predictedResources.find(APP('api')) as unknown as Mutable)).toEqual([
      {
        name: 'AGENTX_ACTIVITY_DOWNLOADS_URL',
        value: `[format('https://{0}.blob.{1}/{2}', '${account}', environment().suffixes.storage, 'activity-downloads')]`,
      },
      { name: 'AGENTX_ACTIVITY_DOWNLOADS_CLIENT_ID', value: `[reference('${apiId}', '2024-11-30').clientId]` },
    ]);
    const url = (app: Mutable): Mutable => named(app, 'AGENTX_ACTIVITY_DOWNLOADS_URL');
    const client = (app: Mutable): Mutable => named(app, 'AGENTX_ACTIVITY_DOWNLOADS_CLIENT_ID');
    for (const change of [
      // The audit exports' store, which the API's role isn't given on.
      (app: Mutable) => (url(app).value = String(url(app).value).replace(`'${account}'`, `'${exports}'`)),
      (app: Mutable) => (url(app).value = String(url(app).value).replace("'activity-downloads'", "'audit-exports'")),
      (app: Mutable) => (url(app).value = 'https://stagentxother.blob.core.windows.net/activity-downloads'),
      (app: Mutable) => (client(app).value = String(client(app).value).replace('-api', '-operator')),
      // The jobs' identity, which the role is given to too, but which the API doesn't run as (4D2e D13).
      (app: Mutable) => (client(app).value = String(client(app).value).replace('-api', '-jobs')),
      (app: Mutable) => (client(app).value = '00000000-0000-0000-0000-000000000002'),
      (app: Mutable) =>
        (url(app).value = String(url(app).value).replace('environment().suffixes.storage', "'example.com'")),
      (app: Mutable) => (client(app).value = String(client(app).value).replace('.clientId]', '.principalId]')),
      (app: Mutable) => (url(app).value = `${String(url(app).value)}x`),
      (app: Mutable) => (client(app).value = `x${String(client(app).value)}`),
      (app: Mutable) => {
        containerOf(app).env = settingsOf(app).filter((entry) => entry.name !== 'AGENTX_ACTIVITY_DOWNLOADS_URL');
      },
      (app: Mutable) => settingsOf(app).push(structuredClone(client(app))),
      // Deployed, never a folder in the store's place.
      (app: Mutable) => settingsOf(app).push({ name: 'AGENTX_ACTIVITY_DOWNLOADS_DIR', value: '/mnt/downloads' }),
    ]) {
      expect(brokenRules(changed(APP('api'), change))).toEqual(['activity-downloads']);
    }
    // A job named as the API is not the app, so its settings are still refused.
    const apiSettings = downloads(staging.predictedResources.find(APP('api')) as unknown as Mutable);
    expect(
      brokenRules(
        changed(JOB('migrate'), (job) => {
          job.name = 'job-agentx-stg-api';
          settingsOf(job).push(...structuredClone(apiSettings));
        }),
      ),
    ).toContain('activity-downloads');
    // No other workload, job or app, is pointed at the store.
    for (const pick of [JOB('operator'), JOB('migrate'), APP('zitadel')]) {
      const told = changed(pick, (resource) =>
        settingsOf(resource).push({ name: 'AGENTX_ACTIVITY_DOWNLOADS_URL', value: 'x' }),
      );
      expect(brokenRules(told)).toEqual(['activity-downloads']);
    }
    expect(
      policyProblems(
        changed(JOB('operator'), (job) =>
          settingsOf(job).push({ name: 'AGENTX_ACTIVITY_DOWNLOADS_DIR', value: '/mnt/downloads' }),
        ),
        STAGING,
      ),
    ).toEqual([
      {
        rule: 'activity-downloads',
        resource: 'job-agentx-stg-operator',
        message: 'sets AGENTX_ACTIVITY_DOWNLOADS_DIR: only the apps that run the API keep the activity downloads',
      },
    ]);
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
    expect(brokenRules(changed(MAIN_WORKSPACE, (workspace) => delete properties(workspace).workspaceCapping))).toEqual([
      'workspace',
    ]);
    expect(
      brokenRules(
        changed(MAIN_WORKSPACE, (workspace) => (inside(workspace, 'properties', 'workspaceCapping').dailyQuotaGb = 0)),
      ),
    ).toEqual(['workspace']);
    // The login alerts' workspace is held to the same, and to its own 1 GB besides.
    expect(brokenRules(changed(LOGIN_WORKSPACE, (workspace) => (properties(workspace).retentionInDays = 90)))).toEqual([
      'workspace',
    ]);
    expect(brokenRules(changed(LOGIN_WORKSPACE, (workspace) => delete properties(workspace).workspaceCapping))).toEqual(
      ['workspace', 'login-workspace'],
    );
  });

  it('SEC-AV-09 log-quota-alerts: the 80% alert off its threshold or its query, or the cap alert inverted or gone', () => {
    // Either workspace's cap moved without its alert.
    expect(
      brokenRules(
        changed(LOGIN_WORKSPACE, (workspace) => (inside(workspace, 'properties', 'workspaceCapping').dailyQuotaGb = 2)),
      ),
    ).toEqual(['log-quota-alerts', 'login-workspace']);
    expect(brokenRules(without(LOGIN_CAP_ALERT))).toEqual(['log-quota-alerts', 'login-workspace']);
    expect(
      brokenRules(
        changed(MAIN_WORKSPACE, (workspace) => (inside(workspace, 'properties', 'workspaceCapping').dailyQuotaGb = 2)),
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

  it('alert-counts-only: an alert split by anything but our own plain words, cut to 300 characters', () => {
    const query = (from: string, to: string) => (alert: Mutable) =>
      (criterion(alert).query = String(criterion(alert).query).replace(from, to));
    for (const change of [
      // Zitadel's lines, or its login pages', could carry anything in a `says` field.
      query('"ca-agentx-stg-api"', '"ca-agentx-stg-zitadel"'),
      query('"ca-agentx-stg-api"', '"ca-agentx-stg-login"'),
      query(', 0, 300)', ', 0, 3000)'),
      query('parse_json(Log).says', 'parse_json(Log).orgId'),
      query('in (', '!in ('),
      // A stage before the words could rewrite the line they are read from, or the container's name.
      query(
        'ContainerAppConsoleLogs |',
        'ContainerAppConsoleLogs | extend Log = strcat("{\\"says\\": \\"", tostring(parse_json(Log).orgId), "\\"}") |',
      ),
      query('ContainerAppConsoleLogs |', 'ContainerAppConsoleLogs | extend ContainerAppName = "ca-agentx-stg-api" |'),
      query('by Says', 'by Says, OrgId = tostring(parse_json(Log).orgId)'),
      query('"A warning or error with no plain words', '"A warning or error with no plain words " + Log + "'),
      (alert: Mutable) =>
        (criterion(alert).dimensions = [
          { name: 'Says', operator: 'Include', values: ['*'] },
          { name: 'OrgId', operator: 'Include', values: ['*'] },
        ]),
      (alert: Mutable) => (criterion(alert).dimensions = []),
      (alert: Mutable) => (criterion(alert).metricMeasureColumn = 'Says'),
    ]) {
      expect(brokenRules(changed(ERRORS_ALERT, change))).toContain('alert-counts-only');
    }
    // Another alert can't borrow the split for a table of its own.
    const errors = criterion(
      staging.predictedResources.find((resource) => ERRORS_ALERT(resource)) as unknown as Mutable,
    );
    const borrowed = (alert: Mutable) =>
      Object.assign(criterion(alert), {
        query: String(errors.query).replace('ContainerAppConsoleLogs', '_LogOperation'),
        dimensions: errors.dimensions,
        metricMeasureColumn: errors.metricMeasureColumn,
      });
    expect(brokenRules(changed(CAP_ALERT, borrowed))).toContain('alert-counts-only');
  });

  it('alert-window: a look-back Azure refuses at deploy (S171: 20 minutes)', () => {
    const windowOf = (size: string) => (alert: Mutable) => (inside(alert, 'properties').windowSize = size);
    for (const size of ['PT20M', 'PT25M', 'PT90M', 'PT1D', 'P3D']) {
      expect(brokenRules(changed(CAP_ALERT, windowOf(size)))).toContain('alert-window');
    }
    for (const size of ['PT5M', 'PT45M', 'PT1H', 'PT12H', 'P1D', 'P2D']) {
      expect(brokenRules(changed(CAP_ALERT, windowOf(size)))).not.toContain('alert-window');
    }
  });

  it("alert-runbook: no runbook, or a SEV its severity doesn't match", () => {
    const properties = (alert: Mutable): Mutable => inside(alert, 'properties');
    expect(brokenRules(changed(CAP_ALERT, (alert) => (properties(alert).description = 'Something happened.')))).toEqual(
      ['alert-runbook'],
    );
    expect(brokenRules(changed(CAP_ALERT, (alert) => (properties(alert).severity = 3)))).toEqual(['alert-runbook']);
    // The playbook's alert sections run from A to S, then W (a blocked DNS lookup, AZ1); T to V answer workflows.
    const inSection = (section: string) => (alert: Mutable) => {
      const before = String(properties(alert).description);
      properties(alert).description = before.replace(/section [A-Z]\.$/, `section ${section}.`);
      expect(properties(alert).description).not.toBe(before);
    };
    expect(brokenRules(changed(CAP_ALERT, inSection('A')))).toEqual([]);
    expect(brokenRules(changed(CAP_ALERT, inSection('S')))).toEqual([]);
    expect(brokenRules(changed(CAP_ALERT, inSection('W')))).toEqual([]);
    for (const workflow of ['T', 'U', 'V', 'X'])
      expect(brokenRules(changed(CAP_ALERT, inSection(workflow))), workflow).toEqual(['alert-runbook']);
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
    // The watches on the alert rules (MO2) send to the same group.
    expect(brokenRules(changed(ACTION_GROUP, (group) => (properties(group).enabled = false)))).toEqual([
      'database-disk',
      'alert-delivery',
      'alert-rules-watch',
    ]);
    expect(
      brokenRules(
        changed(ACTION_GROUP, (group) => {
          properties(group).emailReceivers = [];
          properties(group).azureAppPushReceivers = [];
        }),
      ),
    ).toEqual(['database-disk', 'alert-delivery', 'alert-rules-watch']);
    // A SEV-1 alert muted after it fires tells nobody of the next window; a
    // SEV-2 one may be. The log cap is a SEV-1 since S183: every alert is blind over it.
    for (const sev1 of [LOGIN_ALERT, OWNER_ALERT, INTEGRITY_ALERT, CAP_ALERT]) {
      expect(brokenRules(changed(sev1, (alert) => (properties(alert).muteActionsDuration = 'PT1H')))).toEqual([
        'alert-delivery',
      ]);
    }
    expect(
      brokenRules(changed(DENIAL_SURGE_ALERT, (alert) => (properties(alert).muteActionsDuration = 'PT1H'))),
    ).toEqual([]);
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

  it("resource-logs: a vault, server, DNS policy or audit-export store whose logs stay out of this deployment's workspace", () => {
    const elsewhere = '/subscriptions/x/resourceGroups/y/providers/Microsoft.OperationalInsights/workspaces/elsewhere';
    expect(brokenRules(without(named(/^audit-to-workspace$/)))).toEqual(['resource-logs']);
    expect(brokenRules(without(DNS_LOGS))).toEqual(['resource-logs']);
    // The store's reads, writes and deletes, each of the three.
    const BLOB_LOGS = named(/^blob-logs-to-workspace$/);
    expect(brokenRules(without(BLOB_LOGS))).toEqual(['resource-logs']);
    for (const index of [0, 1, 2]) {
      expect(
        brokenRules(changed(BLOB_LOGS, (entry) => (nth(at(entry, 'properties', 'logs'), index).enabled = false))),
      ).toEqual(['resource-logs']);
    }
    expect(
      brokenRules(changed(BLOB_LOGS, (entry) => (inside(entry, 'properties').logAnalyticsDestinationType = undefined))),
    ).toEqual(['resource-logs']);
    expect(
      brokenRules(changed(DNS_LOGS, (entry) => (first(at(entry, 'properties', 'logs')).category = 'Other'))),
    ).toEqual(['resource-logs']);
    for (const change of [
      (entry: Mutable) => (inside(entry, 'properties').logAnalyticsDestinationType = 'AzureDiagnostics'),
      (entry: Mutable) => (first(at(entry, 'properties', 'logs')).enabled = false),
      (entry: Mutable) => (first(at(entry, 'properties', 'logs')).category = 'PostgreSQLFlexSessions'),
    ]) {
      // The server's log is what the login alerts' workspace is for, so its rule objects too.
      expect(brokenRules(changed(named(/^logs-to-workspace$/), change))).toEqual(['login-workspace', 'resource-logs']);
    }
    for (const change of [
      (entry: Mutable) => (inside(entry, 'properties').logAnalyticsDestinationType = 'AzureDiagnostics'),
      (entry: Mutable) => (first(at(entry, 'properties', 'logs')).enabled = false),
    ]) {
      expect(brokenRules(changed(DNS_LOGS, change))).toEqual(['resource-logs']);
    }
    expect(
      brokenRules(
        changed(named(/^logs-to-workspace$/), (entry) => (inside(entry, 'properties').workspaceId = elsewhere)),
      ),
    ).toEqual(['login-workspace', 'resource-logs', 'log-destinations']);
  });

  it("login-workspace: the login alerts' workspace missing, doubled, over its cap, without what they read, holding more, or its cap reached told quietly", () => {
    const properties = (entry: Mutable): Mutable => inside(entry, 'properties');
    const logs = (setting: Mutable): Mutable[] => at(setting, 'properties', 'logs') as Mutable[];
    const loginWorkspace = staging.predictedResources.find(LOGIN_WORKSPACE);
    // Gone, every login alert goes with it; two, and which one do the alerts read?
    expect(brokenRules(without(LOGIN_WORKSPACE))).toEqual(
      expect.arrayContaining(['required', 'login-workspace', 'database-logins', 'owner-login-alert']),
    );
    expect(
      brokenRules(withExtra({ ...structuredClone(loginWorkspace), id: `${String(loginWorkspace?.id)}-second` })),
    ).toEqual(expect.arrayContaining(['required', 'login-workspace']));
    // A larger cap costs more on a flood's day, and a smaller one fills sooner.
    for (const cap of [2, 0.5]) {
      expect(
        brokenRules(
          changed(LOGIN_WORKSPACE, (workspace) => {
            inside(workspace, 'properties', 'workspaceCapping').dailyQuotaGb = cap;
          }),
        ),
      ).toContain('login-workspace');
    }
    // The server's log sent to the main workspace instead: the main cap blinds the login alerts again.
    const mainId = String(staging.predictedResources.find(MAIN_WORKSPACE)?.id);
    expect(
      brokenRules(changed(named(/^logs-to-workspace$/), (setting) => (properties(setting).workspaceId = mainId))),
    ).toEqual(['login-workspace']);
    // The platform's lines missing, sent to the shared table, or switched off: the owner-login pairing can't see starts.
    for (const change of [
      (setting: Mutable) => (properties(setting).workspaceId = mainId),
      (setting: Mutable) => (properties(setting).logAnalyticsDestinationType = 'AzureDiagnostics'),
      (setting: Mutable) => (first(logs(setting)).enabled = false),
    ]) {
      expect(brokenRules(changed(SYSTEM_LOGS_COPY, change))).toEqual(['login-workspace']);
    }
    expect(brokenRules(without(SYSTEM_LOGS_COPY))).toEqual(['login-workspace']);
    // The apps' console sent there too: their volume could fill its cap.
    expect(
      brokenRules(
        changed(SYSTEM_LOGS_COPY, (setting) =>
          logs(setting).push({ category: 'ContainerAppConsoleLogs', enabled: true }),
        ),
      ),
    ).toEqual(['login-workspace']);
    // A category group brings every category: the apps' rule refuses it on the environment too.
    expect(
      brokenRules(
        changed(SYSTEM_LOGS_COPY, (setting) => logs(setting).push({ categoryGroup: 'allLogs', enabled: true })),
      ),
    ).toEqual(['login-workspace', 'apps-logs']);
    expect(
      brokenRules(changed(DNS_LOGS, (setting) => (properties(setting).workspaceId = String(loginWorkspace?.id)))),
    ).toEqual(['login-workspace']);
    // Its cap reached only a SEV-2, or one that resolves itself and stays quiet: each refused.
    expect(brokenRules(changed(LOGIN_CAP_ALERT, (alert) => (properties(alert).severity = 2)))).toEqual([
      'login-workspace',
      'alert-runbook',
    ]);
    expect(brokenRules(changed(LOGIN_CAP_ALERT, (alert) => (properties(alert).autoMitigate = true)))).toEqual([
      'login-workspace',
      'alert-delivery',
    ]);
  });

  it('workbook: content unreadable, reading another workspace, kept in a storage account, or naming who', () => {
    const properties = (entry: Mutable): Mutable => inside(entry, 'properties');
    const elsewhere = '/subscriptions/x/resourceGroups/y/providers/Microsoft.OperationalInsights/workspaces/elsewhere';
    const content = (workbook: Mutable): Mutable => JSON.parse(String(properties(workbook).serializedData)) as Mutable;
    const rewritten = (edit: (data: Mutable) => void) => (workbook: Mutable) => {
      const data = content(workbook);
      edit(data);
      properties(workbook).serializedData = JSON.stringify(data);
    };
    // As built: one workbook, on the main workspace, its charts counting by event, level and outcome alone.
    const built = staging.predictedResources.find(WORKBOOK);
    expect(at(built?.properties, 'sourceId')).toBe(staging.predictedResources.find(MAIN_WORKSPACE)?.id);
    expect(at(built, 'location')).toBe('uaenorth');
    for (const change of [
      (workbook: Mutable) => (properties(workbook).serializedData = '{ not json'),
      (workbook: Mutable) => (properties(workbook).sourceId = elsewhere),
      rewritten((data) => (data.fallbackResourceIds = [elsewhere])),
      rewritten((data) => (first(data.items).crossComponentResources = [elsewhere])),
      (workbook: Mutable) => (properties(workbook).storageUri = '/subscriptions/x/storageAccounts/elsewhere/blobs/c'),
      rewritten((data) => {
        const decisions = (data.items as Mutable[]).find((item) => item.name === 'decisions');
        inside(decisions ?? {}, 'content').query =
          'ContainerAppConsoleLogs | summarize count() by tostring(parse_json(Log).orgId)';
      }),
    ]) {
      expect(brokenRules(changed(WORKBOOK, change))).toEqual(['workbook']);
    }
    // Outside the region, the general rule refuses it too.
    expect(brokenRules(changed(WORKBOOK, (workbook) => (workbook.location = 'westeurope')))).toEqual(['in-country']);
  });

  it("every alert on the apps' lines, and the workbook, reading the login alerts' workspace, where no console line arrives", () => {
    const loginId = String(staging.predictedResources.find(LOGIN_WORKSPACE)?.id);
    const onLogins = (alert: Mutable) => (inside(alert, 'properties').scopes = [loginId]);
    for (const [pick, rule] of [
      [ERRORS_ALERT, 'app-errors-alert'],
      [named(/-daily-words$/), 'daily-words-alert'],
      [INTEGRITY_ALERT, 'audit-integrity-alert'],
      [TOKEN_REFUSED_ALERT, 'token-refused-alert'],
      [DENIAL_SURGE_ALERT, 'denial-surge-alert'],
      [AGENT_CANCELS_ALERT, 'agent-cancels-alert'],
      [AGENT_CANCEL_CAP_ALERT, 'agent-cancel-cap-alert'],
      [HOLDINGS_CHECK_ALERT, 'holdings-check-alert'],
      [HANDOFF_QUEUE_ALERT, 'handoff-queue-alert'],
      [LOGIN_SERVICE_ALERT, 'login-service-alert'],
      [PLATFORM_FULL_ALERT, 'platform-full-alert'],
      [ANCHOR_STORE_ALERT, 'anchor-store-alert'],
      [INTEGRITY_RUNS_ALERT, 'integrity-runs-alert'],
      [RECORDS_FILLING_ALERT, 'records-filling-alert'],
      [ANCHOR_STOPPED_ALERT, 'dead-man-alerts'],
      [JOBS_STOPPED_ALERT, 'dead-man-alerts'],
    ] as const) {
      expect(brokenRules(changed(pick, onLogins))).toEqual([rule]);
    }
    expect(brokenRules(changed(WORKBOOK, (workbook) => (inside(workbook, 'properties').sourceId = loginId)))).toEqual([
      'workbook',
    ]);
  });

  it('database-logins and owner-login-alert: either login alert reading the main workspace, which its cap can blind', () => {
    const mainId = String(staging.predictedResources.find(MAIN_WORKSPACE)?.id);
    const onMain = (alert: Mutable) => (inside(alert, 'properties').scopes = [mainId]);
    expect(brokenRules(changed(LOGIN_ALERT, onMain))).toEqual(['database-logins']);
    expect(brokenRules(changed(OWNER_ALERT, onMain))).toEqual(['owner-login-alert']);
  });

  it('dns-watch: a network no policy of ours watches, or whose every-name rule is off, allows, only alerts, or covers less', () => {
    const elsewhere = '/subscriptions/x/resourceGroups/y/providers/Microsoft.Network/dnsResolverDomainLists/elsewhere';
    const properties = (resource: Mutable): Mutable => inside(resource, 'properties');
    for (const broken of [
      without(DNS_LINK),
      changed(DNS_LINK, (link) => (inside(link, 'properties', 'virtualNetwork').id = `${String(link.id)}-other`)),
      // Linked to a policy this deployment doesn't create.
      changed(DNS_LINK, (link) => (link.id = String(link.id).replace('/dnspr-agentx-staging/', '/elsewhere/'))),
    ]) {
      expect(brokenRules(broken)).toEqual(['dns-watch']);
    }
    // The policy no longer blocking every name: nothing is refused, so its alert counts nothing either.
    for (const broken of [
      without(WATCH_RULE),
      changed(WATCH_RULE, (rule) => (properties(rule).dnsSecurityRuleState = 'Disabled')),
      changed(WATCH_RULE, (rule) => (properties(rule).dnsSecurityRuleState = 'disabled')),
      changed(WATCH_RULE, (rule) => delete inside(rule, 'properties', 'action').actionType),
      // The rule sits under a policy the network isn't linked to.
      changed(WATCH_RULE, (rule) => (rule.id = String(rule.id).replace('/dnspr-agentx-staging/', '/elsewhere/'))),
      changed(WATCH_RULE, (rule) => (first(at(rule, 'properties', 'dnsResolverDomainLists')).id = elsewhere)),
      changed(EVERY_NAME_LIST, (names) => (properties(names).domains = ['example.com.'])),
      // Alerting alone answers every name (the rule before AZ1, S188).
      changed(WATCH_RULE, (rule) => (inside(rule, 'properties', 'action').actionType = 'Alert')),
      changed(WATCH_RULE, (rule) => (inside(rule, 'properties', 'action').actionType = 'alert')),
    ]) {
      expect(brokenRules(broken)).toEqual(['dns-watch', 'dns-block-alert']);
    }
    // Turned to Allow, it blocks nothing and allows every name.
    expect(
      brokenRules(changed(WATCH_RULE, (rule) => (inside(rule, 'properties', 'action').actionType = 'Allow'))),
    ).toEqual(['dns-watch', 'dns-allow', 'dns-block-alert']);
    // A rule above it that allows every name lets each lookup through first.
    const rule = staging.predictedResources.find(WATCH_RULE);
    const allowAll = structuredClone(rule) as unknown as Mutable;
    allowAll.id = `${String(rule?.id)}-allow`;
    inside(allowAll, 'properties').priority = 100;
    inside(allowAll, 'properties', 'action').actionType = 'Allow';
    expect(brokenRules(withExtra(allowAll))).toEqual(['dns-watch', 'dns-allow']);
    inside(allowAll, 'properties', 'action').actionType = 'allow';
    expect(brokenRules(withExtra(allowAll))).toEqual(['dns-watch', 'dns-allow']);
    // Staging blocks every name.
    expect(inside(staging.predictedResources.find(WATCH_RULE), 'properties', 'action').actionType).toBe('Block');
    // Azure reads the action and the state without regard to case.
    expect(
      brokenRules(
        changed(WATCH_RULE, (entry) => {
          inside(entry, 'properties', 'action').actionType = 'block';
          properties(entry).dnsSecurityRuleState = 'enabled';
        }),
      ),
    ).toEqual([]);
    expect(brokenRules(changed(DNS_POLICY, (policy) => (policy.location = 'westeurope')))).toEqual(['in-country']);
  });

  it('dns-allow: an Allow rule naming a name off the reviewed list, or a list it does not create', () => {
    const properties = (resource: Mutable): Mutable => inside(resource, 'properties');
    for (const extra of ['example.com.', 'com.', 'io.', 'in-addr.arpa.']) {
      const broken = changed(ALLOWED_NAMES, (names) => (properties(names).domains = [...DNS_ALLOWED, extra]));
      expect(brokenRules(broken), extra).toEqual(['dns-allow']);
    }
    // Allowing every name also lets each lookup past the rule that watches them.
    expect(brokenRules(changed(ALLOWED_NAMES, (names) => (properties(names).domains = [...DNS_ALLOWED, '.'])))).toEqual(
      ['dns-watch', 'dns-allow'],
    );
    const elsewhere = changed(
      ALLOW_RULE,
      (rule) => (first(at(rule, 'properties', 'dnsResolverDomainLists')).id = 'elsewhere'),
    );
    expect(brokenRules(elsewhere)).toEqual(['dns-allow']);
    // Azure reads the action and the state without regard to case.
    const lowerCase = (rule: Mutable): void => {
      inside(rule, 'properties', 'action').actionType = 'allow';
      properties(rule).dnsSecurityRuleState = 'enabled';
    };
    expect(brokenRules(changed(ALLOW_RULE, lowerCase))).toEqual([]);
    // Off, or alerting rather than allowing, it lets nothing through first.
    const wide = (names: Mutable): void => {
      properties(names).domains = ['example.com.'];
    };
    expect(brokenRules(changed(ALLOWED_NAMES, wide))).toEqual(['dns-allow']);
    for (const harmless of [
      (rule: Mutable) => (properties(rule).dnsSecurityRuleState = 'Disabled'),
      (rule: Mutable) => (inside(rule, 'properties', 'action').actionType = 'Alert'),
    ]) {
      const snapshot = changed(ALLOWED_NAMES, wide);
      const rule = snapshot.predictedResources.find(ALLOW_RULE);
      expect(rule).toBeDefined();
      harmless(rule as unknown as Mutable);
      expect(brokenRules(snapshot)).toEqual([]);
    }
  });

  it('dns-allow: the reviewed list holds nothing too broad, and staging allows exactly it', () => {
    expect([...DNS_ALLOWED].filter(tooBroad)).toEqual([]);
    for (const broad of [
      '.',
      'com.',
      'io.',
      'example.com',
      'arpa.',
      'in-addr.arpa.',
      '10.in-addr.arpa.',
      ...SHARED_ZONES,
      'b01.azurefd.net.',
      'a01.azurefd.net.',
      'd.akamaiedge.net.',
      'dscb.akamaiedge.net.',
      'B01.azurefd.net.',
    ])
      expect(tooBroad(broad), broad).toBe(true);
    for (const narrow of [
      'microsoft.com.',
      '40.10.in-addr.arpa.',
      'mcr.trafficmanager.net.',
      'x.b01.azurefd.net.',
      'shoebox2-red.cloudapp.net.',
      // Under Microsoft's own Akamai traffic domain, and a Microsoft-only edge zone (S188).
      'aadg.akadns.net.',
      'fb-t-msedge.net.',
    ])
      expect(tooBroad(narrow), narrow).toBe(false);
    const allowedList = staging.predictedResources.find(ALLOWED_NAMES);
    expect(at(allowedList?.properties, 'domains')).toEqual([...DNS_ALLOWED]);
  });

  it("dns-block-alert (AZ1): no alert on a lookup the catch-all blocks, or one that counts another list, hides more than the expected leftovers, can't fire, fires late or quietly", () => {
    const properties = (alert: Mutable): Mutable => inside(alert, 'properties');
    const everyName = String(staging.predictedResources.find(EVERY_NAME_LIST)?.name);
    const counted =
      (...filters: readonly string[]) =>
      (alert: Mutable) =>
        (criterion(alert).query = ['DNSQueryLogs', ...filters, 'summarize Lookups = count()'].join(' | '));
    const catchAll = (name: string): string => `where ResolverPolicyDomainListId endswith "/${name}"`;
    // Staging's rule reads exactly the catch-all's list, past exactly the leftovers.
    expect(
      String(at(staging.predictedResources.find(DNS_BLOCKED_ALERT)?.properties, 'criteria', 'allOf', '0', 'query')),
    ).toBe(`DNSQueryLogs | ${catchAll(everyName)} | ${DNS_EXPECTED_LEFTOVERS} | summarize Lookups = count()`);
    expect(brokenRules(without(DNS_BLOCKED_ALERT))).toEqual(['dns-block-alert']);
    const loginId = String(staging.predictedResources.find(LOGIN_WORKSPACE)?.id);
    for (const change of [
      // Another list: the allowed names, or a name merely ending like the catch-all's.
      counted(catchAll(String(staging.predictedResources.find(ALLOWED_NAMES)?.name)), DNS_EXPECTED_LEFTOVERS),
      counted(`where ResolverPolicyDomainListId endswith "${everyName}"`, DNS_EXPECTED_LEFTOVERS),
      // Hiding more than the leftovers: every reverse lookup (a public address's owner reads its labels), any type of
      // two-number name, the answered ones; or nothing hidden, or the list not named.
      counted(catchAll(everyName), DNS_EXPECTED_LEFTOVERS.replace('".10.in-addr.arpa."', '".in-addr.arpa."')),
      counted(catchAll(everyName), DNS_EXPECTED_LEFTOVERS.replace('QueryType == "HINFO" and ', '')),
      counted(catchAll(everyName), DNS_EXPECTED_LEFTOVERS, 'where ResponseCode != 0'),
      counted(catchAll(everyName)),
      counted(DNS_EXPECTED_LEFTOVERS),
      (alert: Mutable) => (criterion(alert).threshold = 1),
      ...LATE_OR_BLIND,
      (alert: Mutable) => (criterion(alert).operator = 'LessThan'),
      (alert: Mutable) => (criterion(alert).timeAggregation = 'Count'),
      (alert: Mutable) => (properties(alert).scopes = ['/subscriptions/x/workspaces/y']),
      (alert: Mutable) => (properties(alert).scopes = [loginId]),
    ]) {
      expect(brokenRules(changed(DNS_BLOCKED_ALERT, change))).toEqual(['dns-block-alert']);
    }
    expect(brokenRules(changed(DNS_BLOCKED_ALERT, (alert) => (properties(alert).severity = 2)))).toEqual([
      'dns-block-alert',
      'alert-runbook',
    ]);
    for (const quiet of [
      (alert: Mutable) => (properties(alert).autoMitigate = true),
      (alert: Mutable) => (properties(alert).enabled = false),
    ]) {
      expect(brokenRules(changed(DNS_BLOCKED_ALERT, quiet))).toEqual(['dns-block-alert', 'alert-delivery']);
    }
    // The catch-all's list renamed, the alert left reading the old name, which no lookup will carry.
    expect(brokenRules(changed(EVERY_NAME_LIST, (names) => (names.name = `${String(names.name)}-renamed`)))).toEqual([
      'dns-block-alert',
    ]);
    expect(String(at(staging.predictedResources.find(DNS_BLOCKED_ALERT)?.properties, 'description'))).toMatch(
      /^SEV-1\. .+ Runbook: Incident-Response-Playbook\.md section W\.$/,
    );
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

  it("email: data kept outside the UAE or not said, opens and clicks tracked, or a domain that isn't ours", () => {
    const properties = (resource: Mutable): Mutable => inside(resource, 'properties');
    for (const [pick, change] of [
      // Another geography, another spelling of the UAE, or none said, on either resource.
      [COMMUNICATION, (service: Mutable) => (properties(service).dataLocation = 'Europe')],
      [COMMUNICATION, (service: Mutable) => (properties(service).dataLocation = 'United Arab Emirates')],
      [COMMUNICATION, (service: Mutable) => delete properties(service).dataLocation],
      [EMAIL_SERVICE, (service: Mutable) => (properties(service).dataLocation = 'United States')],
      [EMAIL_SERVICE, (service: Mutable) => delete properties(service).dataLocation],
      // Opens and clicks tracked, or tracking not said, which leaves it to Azure.
      [EMAIL_DOMAIN, (domain: Mutable) => (properties(domain).userEngagementTracking = 'Enabled')],
      [EMAIL_DOMAIN, (domain: Mutable) => delete properties(domain).userEngagementTracking],
      // Sending from a domain another deployment holds, beside ours or instead.
      [
        COMMUNICATION,
        (service: Mutable) =>
          (properties(service).linkedDomains = [
            ...(properties(service).linkedDomains as string[]),
            '/subscriptions/x/resourceGroups/y/providers/Microsoft.Communication/emailServices/e/domains/AzureManagedDomain',
          ]),
      ],
      [COMMUNICATION, (service: Mutable) => (properties(service).linkedDomains = ['elsewhere'])],
    ] as const) {
      expect(brokenRules(changed(pick, change))).toEqual(['email']);
    }
    // The service linked to the domain this deployment creates, which the rule compares by id.
    const domain = staging.predictedResources.find(EMAIL_DOMAIN);
    expect(at(staging.predictedResources.find(COMMUNICATION)?.properties, 'linkedDomains')).toEqual([domain?.id]);
    // Without the domain, the service's link points at nothing of ours.
    expect(brokenRules(without(EMAIL_DOMAIN))).toEqual(['email']);
    // A service linked to no domain sends nothing, so breaks nothing.
    expect(brokenRules(changed(COMMUNICATION, (service) => (properties(service).linkedDomains = [])))).toEqual([]);
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
    // No apps subnet at all: the database's rule refuses it too, and the vault,
    // the audit-export store and the environment point at a subnet that isn't there.
    expect(
      brokenRules(
        changed(NETWORK, (network) => {
          inside(network, 'properties').subnets = [subnet(network, 'database')];
        }),
      ),
    ).toEqual([
      'database-network',
      'apps-network',
      'apps-egress',
      'vault',
      'evidence-store',
      'activity-downloads',
      'apps-environment',
    ]);
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
      (group: Mutable) => {
        dropRule(group, 'allow-out-communication');
      },
      (group: Mutable) => {
        dropRule(group, 'allow-out-storage');
      },
      // The audit exports' door to every region's accounts, or another country's.
      (group: Mutable) => (out(group, 'storage').destinationAddressPrefix = 'Storage'),
      (group: Mutable) => (out(group, 'storage').destinationAddressPrefix = 'Storage.westeurope'),
      (group: Mutable) => (out(group, 'storage').destinationPortRange = '*'),
      // Email's door widened to every Azure address, or to the whole of Front Door's.
      (group: Mutable) => (out(group, 'communication').destinationAddressPrefix = 'AzureCloud'),
      (group: Mutable) => (out(group, 'communication').destinationAddressPrefix = 'AzureFrontDoor'),
      (group: Mutable) => (out(group, 'communication').destinationPortRange = '*'),
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

  it("database-egress (AZ8): the server let out anywhere but its own subnet, DNS and its region's Storage", () => {
    const out = (group: Mutable, name: string): Mutable => ruleNamed(group, `allow-out-${name}`);
    const deny = (group: Mutable): Mutable => ruleNamed(group, 'deny-out-rest');
    for (const change of [
      // A door widened, or pointed elsewhere, is a door nothing needs and the one it replaced gone.
      (group: Mutable) => (out(group, 'within-subnet').destinationPortRange = '*'),
      (group: Mutable) => (out(group, 'within-subnet').protocol = '*'),
      (group: Mutable) => (out(group, 'within-subnet').destinationAddressPrefix = 'VirtualNetwork'),
      (group: Mutable) => (out(group, 'azure-dns').destinationPortRange = '*'),
      (group: Mutable) => (out(group, 'azure-dns').destinationAddressPrefix = 'Internet'),
      // Every region's accounts, another country's, or any port.
      (group: Mutable) => (out(group, 'storage').destinationAddressPrefix = 'Storage'),
      (group: Mutable) => (out(group, 'storage').destinationAddressPrefix = 'Storage.westeurope'),
      (group: Mutable) => (out(group, 'storage').destinationPortRange = '*'),
      (group: Mutable) => (out(group, 'storage').protocol = '*'),
      // Each door simply missing.
      (group: Mutable) => {
        dropRule(group, 'allow-out-within-subnet');
      },
      (group: Mutable) => {
        dropRule(group, 'allow-out-azure-dns');
      },
      (group: Mutable) => {
        dropRule(group, 'allow-out-storage');
      },
      // A door open to traffic from somewhere other than the subnet.
      (group: Mutable) => (out(group, 'storage').sourceAddressPrefix = '*'),
      (group: Mutable) => (out(group, 'azure-dns').sourceAddressPrefix = '10.40.9.0/24'),
      // The backstop weakened: any of its parts, or moved above a door it must follow.
      (group: Mutable) => (deny(group).access = 'Allow'),
      (group: Mutable) => (deny(group).protocol = 'Tcp'),
      (group: Mutable) => (deny(group).sourceAddressPrefix = '10.40.9.0/24'),
      (group: Mutable) => (deny(group).destinationAddressPrefix = 'Internet'),
      (group: Mutable) => (deny(group).destinationPortRange = '443'),
      (group: Mutable) => (deny(group).priority = 205),
      (group: Mutable) => {
        dropRule(group, 'deny-out-rest');
      },
    ]) {
      expect(brokenRules(changed(DATABASE_RULES, change))).toEqual(['database-egress']);
    }
    // A door added as a resource of its own under the group counts with the group's.
    expect(brokenRules(withExtra(separateRule(DATABASE_RULES, 'Outbound', '10.40.9.0/24', 'Internet', '443')))).toEqual(
      ['database-egress'],
    );
    // Azure reads direction and access without case (AZ8e): written in lower case, every door and backstop still
    // counts, so the groups pass as they are, and a door nothing needs is still caught.
    const lowerCase = (group: Mutable): void => {
      for (const rule of rules(group)) {
        const properties = inside(rule, 'properties');
        properties.direction = String(properties.direction).toLowerCase();
        properties.access = String(properties.access).toLowerCase();
      }
    };
    expect(brokenRules(changed(DATABASE_RULES, lowerCase))).toEqual([]);
    expect(brokenRules(changed(APPS_RULES, lowerCase))).toEqual([]);
    const quietDoor = separateRule(DATABASE_RULES, 'Outbound', '10.40.9.0/24', 'Internet', '443');
    const quietProperties = inside(quietDoor, 'properties');
    quietProperties.direction = 'outbound';
    quietProperties.access = 'allow';
    expect(brokenRules(withExtra(quietDoor))).toEqual(['database-egress']);
    // Each problem is said apart, naming the subnet: a door missing and one nothing needs.
    const problems = policyProblems(
      changed(DATABASE_RULES, (group) => (out(group, 'storage').destinationAddressPrefix = 'Storage')),
      STAGING,
    ).filter((problem) => problem.rule === 'database-egress');
    expect(problems.map((problem) => problem.message)).toEqual([
      'its database subnet must let out Tcp to Storage.uaenorth on 443, for the write-ahead log and backups, in this region alone',
      'its database subnet lets out Tcp to Storage on 443, which nothing it runs needs',
    ]);
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
    // PL-41: a higher bar would let one refused record's error through unseen.
    expect(brokenRules(changed(ERRORS_ALERT, (alert) => (criterion(alert).threshold = 1)))).toEqual([
      'app-errors-alert',
    ]);
    const query = (from: string, to: string) => (alert: Mutable) =>
      (criterion(alert).query = String(criterion(alert).query).replace(from, to));
    expect(brokenRules(without(ERRORS_ALERT))).toEqual(['app-errors-alert']);
    const levels = 'in~ ("error", "fatal", "panic")';
    // Its query is the one shape a split by plain words may take, so a changed one breaks both rules.
    for (const change of [
      query(levels, '== "error"'),
      // Case-sensitive: it would miss Zitadel's "ERROR" lines (code review, S14).
      query(levels, 'in ("error", "fatal", "panic")'),
      query('ContainerAppConsoleLogs', 'ContainerAppSystemLogs'),
      query(levels, `${levels} | where ContainerAppName == "ca-agentx-stg-api"`),
    ]) {
      expect(brokenRules(changed(ERRORS_ALERT, change))).toEqual(['alert-counts-only', 'app-errors-alert']);
    }
    for (const change of [
      // Warnings too: still our own words, but the error alert would then page on every warning.
      query(levels, 'in~ ("warn", "warning", "error", "fatal", "panic")'),
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
  });

  it("daily-words-alert: no daily alert on the warnings and errors, or one that can't notify each day", () => {
    const DAILY = named(/-daily-words$/);
    const query = (from: string, to: string) => (alert: Mutable) =>
      (criterion(alert).query = String(criterion(alert).query).replace(from, to));
    expect(brokenRules(without(DAILY))).toEqual(['daily-words-alert']);
    for (const change of [
      // Errors alone would leave out every warning.
      query('("warn", "warning", "error", "fatal", "panic")', '("error", "fatal", "panic")'),
    ]) {
      expect(brokenRules(changed(DAILY, change))).toEqual(['daily-words-alert']);
    }
    for (const change of [
      (alert: Mutable) => (inside(alert, 'properties').evaluationFrequency = 'PT1H'),
      (alert: Mutable) => (inside(alert, 'properties').windowSize = 'PT1H'),
      // Hourly, both together: every window watched, but not the daily email.
      (alert: Mutable) =>
        Object.assign(inside(alert, 'properties'), { evaluationFrequency: 'PT1H', windowSize: 'PT1H' }),
      // Stateful, it would notify once and stay quiet while the same warning went on day after day.
      (alert: Mutable) => (inside(alert, 'properties').autoMitigate = true),
      (alert: Mutable) => (criterion(alert).threshold = 5),
      (alert: Mutable) => (criterion(alert).operator = 'LessThan'),
      (alert: Mutable) => (criterion(alert).timeAggregation = 'Count'),
      // One number for the day, counts only: allowed for any alert, but it wouldn't name each kind.
      (alert: Mutable) =>
        Object.assign(criterion(alert), {
          query: String(criterion(alert).query).replace('count() by Says', 'count()'),
          dimensions: [],
        }),
      (alert: Mutable) =>
        (criterion(alert).failingPeriods = { numberOfEvaluationPeriods: 2, minFailingPeriodsToAlert: 2 }),
    ]) {
      expect(brokenRules(changed(DAILY, change))).toEqual(['daily-words-alert']);
    }
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

  it("login-service-alert (SA2): no alert on a change made in the login service behind Agent X, or one that leaves a line out, can't fire, fires late or quietly", () => {
    const properties = (alert: Mutable): Mutable => inside(alert, 'properties');
    const counted = (filter: string) => (alert: Mutable) =>
      (criterion(alert).query = `ContainerAppConsoleLogs | ${filter} | summarize Events = count()`);
    const listed = (events: readonly string[]) =>
      `where tostring(parse_json(Log).event) in (${events.map((event) => JSON.stringify(event)).join(', ')})`;
    expect(brokenRules(without(LOGIN_SERVICE_ALERT))).toEqual(['login-service-alert']);
    // The rule's query names exactly the copier's list, every line of it.
    expect(
      String(at(staging.predictedResources.find(LOGIN_SERVICE_ALERT)?.properties, 'criteria', 'allOf', '0', 'query')),
    ).toBe(`ContainerAppConsoleLogs | ${listed(LOGIN_SERVICE_ALERT_EVENTS)} | summarize Events = count()`);
    for (const change of [
      ...LOGIN_SERVICE_ALERT_EVENTS.map((left) =>
        counted(listed(LOGIN_SERVICE_ALERT_EVENTS.filter((event) => event !== left))),
      ),
      counted(`${listed(LOGIN_SERVICE_ALERT_EVENTS)} | where tostring(parse_json(Log).level) == "error"`),
      (alert: Mutable) => (criterion(alert).threshold = 1),
      ...LATE_OR_BLIND,
      (alert: Mutable) => (criterion(alert).operator = 'LessThan'),
      (alert: Mutable) => (criterion(alert).timeAggregation = 'Count'),
      (alert: Mutable) => (properties(alert).scopes = ['/subscriptions/x/workspaces/y']),
    ]) {
      expect(brokenRules(changed(LOGIN_SERVICE_ALERT, change))).toEqual(['login-service-alert']);
    }
    expect(brokenRules(changed(LOGIN_SERVICE_ALERT, (alert) => (properties(alert).severity = 2)))).toEqual([
      'alert-runbook',
      'login-service-alert',
    ]);
    expect(brokenRules(changed(LOGIN_SERVICE_ALERT, (alert) => (properties(alert).autoMitigate = true)))).toEqual([
      'alert-delivery',
      'login-service-alert',
    ]);
    expect(String(at(staging.predictedResources.find(LOGIN_SERVICE_ALERT)?.properties, 'description'))).toMatch(
      / Runbook: Incident-Response-Playbook\.md section B\.$/,
    );
  });

  it("token-refused-alert: no alert on a refused token, or one that counts something else, can't fire or fires too late", () => {
    const properties = (alert: Mutable): Mutable => inside(alert, 'properties');
    const query = (text: string) => (alert: Mutable) => (criterion(alert).query = text);
    expect(brokenRules(without(TOKEN_REFUSED_ALERT))).toEqual(['token-refused-alert']);
    for (const change of [
      // Another error type, or an event's name where the type belongs.
      query(
        'ContainerAppConsoleLogs | where tostring(parse_json(Log).err.type) == "LoginSessionsUnavailable" | summarize Events = count()',
      ),
      query(
        'ContainerAppConsoleLogs | where tostring(parse_json(Log).event) == "LoginTokenRefused" | summarize Events = count()',
      ),
      query(
        'ContainerAppConsoleLogs | where tostring(parse_json(Log).err.type) == "LoginTokenRefused" | where ContainerAppName == "api" | summarize Events = count()',
      ),
      query(
        'ContainerAppSystemLogs | where tostring(parse_json(Log).err.type) == "LoginTokenRefused" | summarize Events = count()',
      ),
      // One line is enough, seen in any minute.
      (alert: Mutable) => (criterion(alert).threshold = 1),
      ...LATE_OR_BLIND,
      (alert: Mutable) => (criterion(alert).operator = 'LessThan'),
      (alert: Mutable) => (criterion(alert).timeAggregation = 'Count'),
      (alert: Mutable) => (properties(alert).scopes = ['/subscriptions/x/workspaces/y']),
    ]) {
      expect(brokenRules(changed(TOKEN_REFUSED_ALERT, change))).toEqual(['token-refused-alert']);
    }
    // Off: the general alert rules object too.
    expect(brokenRules(changed(TOKEN_REFUSED_ALERT, (alert) => (properties(alert).enabled = false)))).toEqual([
      'alert-delivery',
      'token-refused-alert',
    ]);
    // Its runbook is the playbook's section M.
    expect(String(at(staging.predictedResources.find(TOKEN_REFUSED_ALERT)?.properties, 'description'))).toMatch(
      / Runbook: Incident-Response-Playbook\.md section M\.$/,
    );
  });

  it("agent-cancel-cap-alert: no alert on a cancel the agent's cap refused, or one that counts something else, can't fire", () => {
    const properties = (alert: Mutable): Mutable => inside(alert, 'properties');
    const query = (text: string) => (alert: Mutable) => (criterion(alert).query = text);
    const SPENT =
      'ContainerAppConsoleLogs | where tostring(parse_json(Log).event) == "spend_request.agent_cancels_spent"';
    expect(brokenRules(without(AGENT_CANCEL_CAP_ALERT))).toEqual(['agent-cancel-cap-alert']);
    for (const change of [
      query(`${SPENT.replace('agent_cancels_spent', 'cancelled')} | summarize Events = count()`),
      query(`${SPENT.replace('ContainerAppConsoleLogs', 'ContainerAppSystemLogs')} | summarize Events = count()`),
      (alert: Mutable) => (criterion(alert).threshold = 1),
      ...LATE_OR_BLIND,
      (alert: Mutable) => (criterion(alert).operator = 'LessThan'),
      (alert: Mutable) => (properties(alert).scopes = ['/subscriptions/x/workspaces/y']),
    ]) {
      expect(brokenRules(changed(AGENT_CANCEL_CAP_ALERT, change))).toEqual(['agent-cancel-cap-alert']);
    }
    expect(String(at(staging.predictedResources.find(AGENT_CANCEL_CAP_ALERT)?.properties, 'description'))).toMatch(
      / Runbook: Incident-Response-Playbook\.md section F\.$/,
    );
  });

  it("agent-cancels-alert: no alert on one agent's own cancels, or one that counts something else, can't fire or fires too late", () => {
    const properties = (alert: Mutable): Mutable => inside(alert, 'properties');
    const query = (text: string) => (alert: Mutable) => (criterion(alert).query = text);
    const CANCELS =
      'ContainerAppConsoleLogs | where tostring(parse_json(Log).event) == "spend_request.cancelled" | where tostring(parse_json(Log)["by"]) == "agent"';
    const PER_AGENT = 'summarize Cancels = count() by Agent = tostring(parse_json(Log).agentId)';
    expect(brokenRules(without(AGENT_CANCELS_ALERT))).toEqual(['agent-cancels-alert']);
    for (const change of [
      // Every cancel, a person's too; or another event.
      query(
        `ContainerAppConsoleLogs | where tostring(parse_json(Log).event) == "spend_request.cancelled" | ${PER_AGENT} | summarize Highest = max(Cancels)`,
      ),
      query(
        `${CANCELS.replace('spend_request.cancelled', 'spend_request.decided')} | ${PER_AGENT} | summarize Highest = max(Cancels)`,
      ),
      // The organisation's total, not one agent's; or the agents' total again; or per organisation.
      query(`${CANCELS} | summarize Highest = count()`),
      query(`${CANCELS} | ${PER_AGENT} | summarize Highest = sum(Cancels)`),
      query(
        `${CANCELS} | summarize Cancels = count() by Agent = tostring(parse_json(Log).orgId) | summarize Highest = max(Cancels)`,
      ),
      query(
        `${CANCELS.replace('ContainerAppConsoleLogs', 'ContainerAppSystemLogs')} | ${PER_AGENT} | summarize Highest = max(Cancels)`,
      ),
      // Its threshold, neither higher nor lower.
      (alert: Mutable) => (criterion(alert).threshold = 6),
      (alert: Mutable) => (criterion(alert).threshold = 0),
      ...LATE_OR_BLIND,
      (alert: Mutable) => (criterion(alert).operator = 'LessThan'),
      (alert: Mutable) => (criterion(alert).timeAggregation = 'Count'),
      (alert: Mutable) => (properties(alert).scopes = ['/subscriptions/x/workspaces/y']),
    ]) {
      expect(brokenRules(changed(AGENT_CANCELS_ALERT, change))).toEqual(['agent-cancels-alert']);
    }
    expect(brokenRules(changed(AGENT_CANCELS_ALERT, (alert) => (properties(alert).enabled = false)))).toEqual([
      'alert-delivery',
      'agent-cancels-alert',
    ]);
    // One number: the per-agent stage left last returns a row an agent.
    expect(brokenRules(changed(AGENT_CANCELS_ALERT, query(`${CANCELS} | ${PER_AGENT}`)))).toEqual([
      'alert-counts-only',
      'agent-cancels-alert',
    ]);
    // Its runbook is the playbook's section F (an agent behaving strangely).
    expect(String(at(staging.predictedResources.find(AGENT_CANCELS_ALERT)?.properties, 'description'))).toMatch(
      / Runbook: Incident-Response-Playbook\.md section F\.$/,
    );
  });

  it("denial-surge-alert: no alert on one agent's denials, or one that counts something else, can't fire or fires too late", () => {
    const properties = (alert: Mutable): Mutable => inside(alert, 'properties');
    const query = (text: string) => (alert: Mutable) => (criterion(alert).query = text);
    const DENIALS =
      'ContainerAppConsoleLogs | where tostring(parse_json(Log).event) == "spend_request.decided" | where tostring(parse_json(Log).decision) in ("DENY", "REQUIRE_NEW_MANDATE")';
    expect(brokenRules(without(DENIAL_SURGE_ALERT))).toEqual(['denial-surge-alert']);
    for (const change of [
      // Every decision, or denials alone without a new mandate's, or another event.
      query(
        'ContainerAppConsoleLogs | where tostring(parse_json(Log).event) == "spend_request.decided" | summarize Denials = count() by Agent = tostring(parse_json(Log).agentId) | summarize Highest = max(Denials)',
      ),
      query(
        'ContainerAppConsoleLogs | where tostring(parse_json(Log).event) == "spend_request.decided" | where tostring(parse_json(Log).decision) in ("DENY") | summarize Denials = count() by Agent = tostring(parse_json(Log).agentId) | summarize Highest = max(Denials)',
      ),
      query(
        `${DENIALS.replace('spend_request.decided', 'http.request_completed')} | summarize Denials = count() by Agent = tostring(parse_json(Log).agentId) | summarize Highest = max(Denials)`,
      ),
      // The organisation's total, not one agent's; or the agents' total again.
      query(`${DENIALS} | summarize Highest = count()`),
      query(
        `${DENIALS} | summarize Denials = count() by Agent = tostring(parse_json(Log).agentId) | summarize Highest = sum(Denials)`,
      ),
      query(
        `${DENIALS} | summarize Denials = count() by Agent = tostring(parse_json(Log).orgId) | summarize Highest = max(Denials)`,
      ),
      query(
        `${DENIALS.replace('ContainerAppConsoleLogs', 'ContainerAppSystemLogs')} | summarize Denials = count() by Agent = tostring(parse_json(Log).agentId) | summarize Highest = max(Denials)`,
      ),
      // Its threshold, neither higher nor lower.
      (alert: Mutable) => (criterion(alert).threshold = 11),
      (alert: Mutable) => (criterion(alert).threshold = 0),
      ...LATE_OR_BLIND,
      (alert: Mutable) => (criterion(alert).operator = 'LessThan'),
      (alert: Mutable) => (criterion(alert).timeAggregation = 'Count'),
      (alert: Mutable) => (properties(alert).scopes = ['/subscriptions/x/workspaces/y']),
    ]) {
      expect(brokenRules(changed(DENIAL_SURGE_ALERT, change))).toEqual(['denial-surge-alert']);
    }
    expect(brokenRules(changed(DENIAL_SURGE_ALERT, (alert) => (properties(alert).enabled = false)))).toEqual([
      'alert-delivery',
      'denial-surge-alert',
    ]);
    // One number: the per-agent stage left last returns a row an agent.
    expect(
      brokenRules(
        changed(
          DENIAL_SURGE_ALERT,
          query(`${DENIALS} | summarize Denials = count() by Agent = tostring(parse_json(Log).agentId)`),
        ),
      ),
    ).toEqual(['alert-counts-only', 'denial-surge-alert']);
    // Its runbook is the playbook's section F (an agent behaving strangely).
    expect(String(at(staging.predictedResources.find(DENIAL_SURGE_ALERT)?.properties, 'description'))).toMatch(
      / Runbook: Incident-Response-Playbook\.md section F\.$/,
    );
  });

  it("holdings-check-alert: no alert on a failed page of the holdings check, or one that counts something else, can't fire or fires too late", () => {
    const properties = (alert: Mutable): Mutable => inside(alert, 'properties');
    const query = (text: string) => (alert: Mutable) => (criterion(alert).query = text);
    expect(brokenRules(without(HOLDINGS_CHECK_ALERT))).toEqual(['holdings-check-alert']);
    for (const change of [
      query(
        'ContainerAppConsoleLogs | where tostring(parse_json(Log).event) == "holdings_check.paused" | summarize Events = count()',
      ),
      query(
        'ContainerAppConsoleLogs | where tostring(parse_json(Log).err.type) == "holdings_check.failed" | summarize Events = count()',
      ),
      query(
        'ContainerAppSystemLogs | where tostring(parse_json(Log).event) == "holdings_check.failed" | summarize Events = count()',
      ),
      (alert: Mutable) => (criterion(alert).threshold = 1),
      ...LATE_OR_BLIND,
      (alert: Mutable) => (criterion(alert).operator = 'LessThan'),
      (alert: Mutable) => (criterion(alert).timeAggregation = 'Count'),
      (alert: Mutable) => (properties(alert).scopes = ['/subscriptions/x/workspaces/y']),
    ]) {
      expect(brokenRules(changed(HOLDINGS_CHECK_ALERT, change))).toEqual(['holdings-check-alert']);
    }
    expect(brokenRules(changed(HOLDINGS_CHECK_ALERT, (alert) => (properties(alert).enabled = false)))).toEqual([
      'alert-delivery',
      'holdings-check-alert',
    ]);
    // Its runbook is the playbook's section N.
    expect(String(at(staging.predictedResources.find(HOLDINGS_CHECK_ALERT)?.properties, 'description'))).toMatch(
      / Runbook: Incident-Response-Playbook\.md section N\.$/,
    );
  });

  it("decisions-suppressed-alert: no alert on decision lines held back (PL-52), or one that counts something else, can't fire or fires too late", () => {
    const properties = (alert: Mutable): Mutable => inside(alert, 'properties');
    const query = (text: string) => (alert: Mutable) => (criterion(alert).query = text);
    expect(brokenRules(without(DECISIONS_SUPPRESSED_ALERT))).toEqual(['decisions-suppressed-alert']);
    for (const change of [
      // Any held-back count, not the decision line's.
      query(
        'ContainerAppConsoleLogs | where tostring(parse_json(Log).event) == "log.suppressed" | summarize Events = count()',
      ),
      query(
        'ContainerAppConsoleLogs | where tostring(parse_json(Log).event) == "log.suppressed" | where tostring(parse_json(Log).suppressedEvent) == "spend_request.created" | summarize Events = count()',
      ),
      query(
        'ContainerAppSystemLogs | where tostring(parse_json(Log).event) == "log.suppressed" | where tostring(parse_json(Log).suppressedEvent) == "spend_request.decided" | summarize Events = count()',
      ),
      (alert: Mutable) => (criterion(alert).threshold = 1),
      ...LATE_OR_BLIND,
      (alert: Mutable) => (criterion(alert).operator = 'LessThan'),
      (alert: Mutable) => (criterion(alert).timeAggregation = 'Count'),
      (alert: Mutable) => (properties(alert).scopes = ['/subscriptions/x/workspaces/y']),
    ]) {
      expect(brokenRules(changed(DECISIONS_SUPPRESSED_ALERT, change))).toEqual(['decisions-suppressed-alert']);
    }
    expect(String(at(staging.predictedResources.find(DECISIONS_SUPPRESSED_ALERT)?.properties, 'description'))).toMatch(
      / Runbook: Incident-Response-Playbook\.md section J\.$/,
    );
  });

  it("records-filling-alert: no alert on an organisation's records filling, or one that counts something else, can't fire or fires too late", () => {
    const properties = (alert: Mutable): Mutable => inside(alert, 'properties');
    const query = (text: string) => (alert: Mutable) => (criterion(alert).query = text);
    expect(brokenRules(without(RECORDS_FILLING_ALERT))).toEqual(['records-filling-alert']);
    for (const change of [
      query(
        'ContainerAppConsoleLogs | where tostring(parse_json(Log).event) == "identity.records_full" | summarize Events = count()',
      ),
      query(
        'ContainerAppConsoleLogs | where tostring(parse_json(Log).says) == "identity.records_filling" | summarize Events = count()',
      ),
      query(
        'ContainerAppSystemLogs | where tostring(parse_json(Log).event) == "identity.records_filling" | summarize Events = count()',
      ),
      (alert: Mutable) => (criterion(alert).threshold = 1),
      ...LATE_OR_BLIND,
      (alert: Mutable) => (criterion(alert).operator = 'LessThan'),
      (alert: Mutable) => (criterion(alert).timeAggregation = 'Count'),
      (alert: Mutable) => (properties(alert).scopes = ['/subscriptions/x/workspaces/y']),
    ]) {
      expect(brokenRules(changed(RECORDS_FILLING_ALERT, change))).toEqual(['records-filling-alert']);
    }
    expect(brokenRules(changed(RECORDS_FILLING_ALERT, (alert) => (properties(alert).enabled = false)))).toEqual([
      'alert-delivery',
      'records-filling-alert',
    ]);
    // SEV-2, stateful: nothing is broken yet, and the line repeats with each add or clearing.
    const built = staging.predictedResources.find(RECORDS_FILLING_ALERT);
    expect([at(built?.properties, 'severity'), at(built?.properties, 'autoMitigate')]).toEqual([2, true]);
    // Its runbook is the playbook's section S.
    expect(String(at(built?.properties, 'description'))).toMatch(
      / Runbook: Incident-Response-Playbook\.md section S\.$/,
    );
  });

  it("platform-full-alert: no alert on the whole platform full (PL-63), or one that counts something else, can't fire or fires too late", () => {
    const properties = (alert: Mutable): Mutable => inside(alert, 'properties');
    const query = (text: string) => (alert: Mutable) => (criterion(alert).query = text);
    expect(brokenRules(without(PLATFORM_FULL_ALERT))).toEqual(['platform-full-alert']);
    for (const change of [
      query(
        'ContainerAppConsoleLogs | where tostring(parse_json(Log).event) == "spend_request.organisation_busy" | summarize Events = count()',
      ),
      query(
        'ContainerAppSystemLogs | where tostring(parse_json(Log).event) in ("spend_request.platform_full", "db.pool_wait_ran_out") | summarize Events = count()',
      ),
      query(
        'ContainerAppConsoleLogs | where tostring(parse_json(Log).event) == "spend_request.platform_full" | summarize Events = count()',
      ),
      (alert: Mutable) => (criterion(alert).threshold = 1),
      ...LATE_OR_BLIND,
      (alert: Mutable) => (criterion(alert).operator = 'LessThan'),
      (alert: Mutable) => (criterion(alert).timeAggregation = 'Count'),
      (alert: Mutable) => (properties(alert).scopes = ['/subscriptions/x/workspaces/y']),
    ]) {
      expect(brokenRules(changed(PLATFORM_FULL_ALERT, change))).toEqual(['platform-full-alert']);
    }
    expect(String(at(staging.predictedResources.find(PLATFORM_FULL_ALERT)?.properties, 'description'))).toMatch(
      / Runbook: Incident-Response-Playbook\.md section Q\.$/,
    );
  });

  it("anchor-store-alert: no alert on the anchors' store (PL-58), or one that counts something else, can't fire or fires too late", () => {
    const properties = (alert: Mutable): Mutable => inside(alert, 'properties');
    const query = (text: string) => (alert: Mutable) => (criterion(alert).query = text);
    expect(brokenRules(without(ANCHOR_STORE_ALERT))).toEqual(['anchor-store-alert']);
    for (const change of [
      query(
        'ContainerAppConsoleLogs | where tostring(parse_json(Log).event) == "audit.anchor_store_write_failed" | summarize Events = count()',
      ),
      query(
        'ContainerAppSystemLogs | where tostring(parse_json(Log).event) in ("audit.anchor_store_unreadable", "audit.anchor_store_unwritable", "audit.anchor_store_read_failing", "audit.anchor_store_not_set", "audit.anchor_store_beyond_memory", "audit.anchor_store_near_memory", "audit.anchor_check_behind", "audit.anchor_check_over_size", "audit.anchor_store_moved_on") | summarize Events = count()',
      ),
      query(
        'ContainerAppConsoleLogs | where tostring(parse_json(Log).event) in ("audit.anchor_store_unreadable", "audit.anchor_store_unwritable") | summarize Events = count()',
      ),
      query(
        'ContainerAppConsoleLogs | where tostring(parse_json(Log).event) in ("audit.anchor_store_unreadable", "audit.anchor_store_unwritable", "audit.anchor_store_read_failing") | summarize Events = count()',
      ),
      query(
        'ContainerAppConsoleLogs | where tostring(parse_json(Log).event) in ("audit.anchor_store_unreadable", "audit.anchor_store_unwritable", "audit.anchor_store_not_set") | summarize Events = count()',
      ),
      query(
        'ContainerAppConsoleLogs | where tostring(parse_json(Log).event) == "audit.anchor_store_unreadable" | summarize Events = count()',
      ),
      query(
        'ContainerAppConsoleLogs | where tostring(parse_json(Log).event) == "audit.anchor_store_unwritable" | summarize Events = count()',
      ),
      (alert: Mutable) => (criterion(alert).threshold = 1),
      ...LATE_OR_BLIND,
      (alert: Mutable) => (criterion(alert).operator = 'LessThan'),
      (alert: Mutable) => (criterion(alert).timeAggregation = 'Count'),
      (alert: Mutable) => (properties(alert).scopes = ['/subscriptions/x/workspaces/y']),
    ]) {
      expect(brokenRules(changed(ANCHOR_STORE_ALERT, change))).toEqual(['anchor-store-alert']);
    }
    const description = String(at(staging.predictedResources.find(ANCHOR_STORE_ALERT)?.properties, 'description'));
    expect(description).toMatch(/^SEV-2\. /);
    expect(description).toMatch(/ Runbook: Incident-Response-Playbook\.md section H\.$/);
  });

  it.each([
    ['daily-check-alert', DAILY_CHECK_ALERT, 'audit.daily_check_overdue', 'audit.full_pass_overdue'],
    ['full-pass-alert', FULL_PASS_ALERT, 'audit.full_pass_overdue', 'audit.daily_check_overdue'],
  ] as const)(
    "%s: no alert on the anchor check's rotation running late (4D2e E7), or one that counts something else, can't fire or fires too late",
    (rule, alert, event, other) => {
      const properties = (found: Mutable): Mutable => inside(found, 'properties');
      const query = (text: string) => (found: Mutable) => (criterion(found).query = text);
      expect(brokenRules(without(alert))).toEqual([rule]);
      for (const change of [
        query(
          `ContainerAppConsoleLogs | where tostring(parse_json(Log).event) == "${other}" | summarize Events = count()`,
        ),
        query(
          `ContainerAppSystemLogs | where tostring(parse_json(Log).event) == "${event}" | summarize Events = count()`,
        ),
        (found: Mutable) => (criterion(found).threshold = 1),
        ...LATE_OR_BLIND,
        (found: Mutable) => (criterion(found).operator = 'LessThan'),
        (found: Mutable) => (criterion(found).timeAggregation = 'Count'),
        (found: Mutable) => (properties(found).scopes = ['/subscriptions/x/workspaces/y']),
      ]) {
        expect(brokenRules(changed(alert, change))).toEqual([rule]);
      }
      const description = String(at(staging.predictedResources.find(alert)?.properties, 'description'));
      expect(description).toMatch(/^SEV-2\. /);
      expect(description).toContain(event);
      expect(description).toMatch(/ Runbook: Incident-Response-Playbook\.md section H\.$/);
    },
  );

  it('database-backup: production keeps twice the days an old audit edit may go unfound, 35 at least (4D2e decision 3)', () => {
    expect(leastRestoreDays('production')).toBe(35);
    expect(leastRestoreDays('production', 20)).toBe(40);
    expect(leastRestoreDays('production', 17)).toBe(35);
    expect(leastRestoreDays('staging', 20)).toBe(7);
  });

  it("handoff-queue-alert: no alert on approved payments left standing (gate H8), or one that counts something else, can't fire or fires too late", () => {
    const properties = (alert: Mutable): Mutable => inside(alert, 'properties');
    const query = (text: string) => (alert: Mutable) => (criterion(alert).query = text);
    expect(brokenRules(without(HANDOFF_QUEUE_ALERT))).toEqual(['handoff-queue-alert']);
    for (const change of [
      query(
        'ContainerAppConsoleLogs | where tostring(parse_json(Log).event) == "handoff.queue_unread" | summarize Events = count()',
      ),
      query(
        'ContainerAppConsoleLogs | where tostring(parse_json(Log).err.type) == "handoff.queue_stale" | summarize Events = count()',
      ),
      query(
        'ContainerAppSystemLogs | where tostring(parse_json(Log).event) == "handoff.queue_stale" | summarize Events = count()',
      ),
      (alert: Mutable) => (criterion(alert).threshold = 1),
      ...LATE_OR_BLIND,
      (alert: Mutable) => (criterion(alert).operator = 'LessThan'),
      (alert: Mutable) => (criterion(alert).timeAggregation = 'Count'),
      (alert: Mutable) => (properties(alert).scopes = ['/subscriptions/x/workspaces/y']),
    ]) {
      expect(brokenRules(changed(HANDOFF_QUEUE_ALERT, change))).toEqual(['handoff-queue-alert']);
    }
    expect(brokenRules(changed(HANDOFF_QUEUE_ALERT, (alert) => (properties(alert).enabled = false)))).toEqual([
      'alert-delivery',
      'handoff-queue-alert',
    ]);
    // Its runbook is the playbook's section E.
    expect(String(at(staging.predictedResources.find(HANDOFF_QUEUE_ALERT)?.properties, 'description'))).toMatch(
      / Runbook: Incident-Response-Playbook\.md section E\.$/,
    );
  });

  describe('dead-man-alerts (4D2e D, PL-33): the jobs having stopped, seen from outside', () => {
    const properties = (alert: Mutable): Mutable => inside(alert, 'properties');
    const RULES = [
      [ANCHOR_STOPPED_ALERT, 'audit.anchor_check_done', 'Done', 1, 30],
      [JOBS_STOPPED_ALERT, 'jobs.pulse', 'Pulses', 2, 15],
    ] as const;
    /** The workspace's own word that its cap stopped collection (S183): silence then is no sign. */
    const overCap = (minutes: number) =>
      `(_LogOperation | where Category =~ "Ingestion" | where Detail contains "Ingestion status" | summarize arg_max(TimeGenerated, Detail) | where Detail contains "OverQuota" or TimeGenerated > ago(${String(minutes)}m))`;
    const deadMan = (event: string, column: string, minutes: number, cap = overCap(minutes)) =>
      `union (ContainerAppConsoleLogs | where TimeGenerated > ago(${String(minutes)}m) | where tostring(parse_json(Log).event) == "${event}"), ${cap} | summarize ${column} = count()`;

    it.each(RULES)(
      '%#: is off on staging, which sleeps, and all else stands',
      (rule, event, column, severity, minutes) => {
        const alert = staging.predictedResources.find(rule);
        expect(at(alert?.properties, 'enabled')).toBe(false);
        expect(at(alert?.properties, 'severity')).toBe(severity);
        const only = first(at(alert?.properties, 'criteria', 'allOf'));
        expect(at(only, 'query')).toBe(deadMan(event, column, minutes));
        expect(at(alert?.properties, 'overrideQueryTimeRange')).toBe('P1D');
        expect(brokenRules(staging)).toEqual([]);
      },
    );

    it.each(RULES)('%#: on staging it may be on, for a keep-running window', (rule) => {
      expect(brokenRules(changed(rule, (alert) => (properties(alert).enabled = true)))).toEqual([]);
    });

    it.each(RULES)(
      '%#: gone, or changed so it could not fire, breaks the rule',
      (rule, event, column, _severity, minutes) => {
        expect(brokenRules(without(rule))).toEqual(['dead-man-alerts']);
        for (const change of [
          (alert: Mutable) => (criterion(alert).operator = 'GreaterThan'),
          (alert: Mutable) => (criterion(alert).threshold = 0),
          (alert: Mutable) => (criterion(alert).timeAggregation = 'Count'),
          (alert: Mutable) => (properties(alert).windowSize = 'P1D'),
          (alert: Mutable) => (properties(alert).scopes = ['/subscriptions/x/workspaces/y']),
          (alert: Mutable) => (inside(criterion(alert), 'failingPeriods').numberOfEvaluationPeriods = 2),
          (alert: Mutable) => (inside(criterion(alert), 'failingPeriods').minFailingPeriodsToAlert = 2),
          (alert: Mutable) =>
            (criterion(alert).query =
              `ContainerAppSystemLogs | where tostring(parse_json(Log).event) == "${event}" | summarize N = count()`),
          (alert: Mutable) =>
            (criterion(alert).query =
              `ContainerAppConsoleLogs | where tostring(parse_json(Log).event) == "${event}.x" | summarize N = count()`),
          // Its old form, which a full log store would set off for nothing (S183).
          (alert: Mutable) =>
            (criterion(alert).query =
              `ContainerAppConsoleLogs | where tostring(parse_json(Log).event) == "${event}" | summarize ${column} = count()`),
          // Looking further back than its window: a line from an hour ago would hide jobs stopped since.
          (alert: Mutable) => (criterion(alert).query = deadMan(event, column, minutes * 2)),
          // Quiet whenever the cap was ever reached, not only while it is over.
          (alert: Mutable) =>
            (criterion(alert).query = deadMan(
              event,
              column,
              minutes,
              overCap(minutes).replace(' | summarize arg_max(TimeGenerated, Detail)', ''),
            )),
          // Quiet a day after the cap's word, not one window: a stop after the reset would go unseen.
          (alert: Mutable) => (criterion(alert).query = deadMan(event, column, minutes, overCap(24 * 60))),
          (alert: Mutable) => delete properties(alert).overrideQueryTimeRange,
        ]) {
          expect(brokenRules(changed(rule, change))).toContain('dead-man-alerts');
        }
      },
    );

    it.each(RULES)('%#: in production it must be on', (rule) => {
      const production = { region: 'uaenorth', environment: 'production' } as const;
      const on = productionLike({ subject: true });
      const off = changed(rule, (alert) => (properties(alert).enabled = false), on);
      const rulesOf = (snapshotted: Snapshot) => brokenRules(snapshotted, production);
      expect(rulesOf(on)).not.toContain('dead-man-alerts');
      expect(rulesOf(on)).not.toContain('alert-delivery');
      expect(rulesOf(off)).toContain('dead-man-alerts');
      expect(rulesOf(off)).toContain('alert-delivery');
    });

    it.each(RULES)('%#: points at the runbook for the jobs having stopped', (rule) => {
      expect(String(at(staging.predictedResources.find(rule)?.properties, 'description'))).toMatch(
        / Runbook: Incident-Response-Playbook\.md section R\.$/,
      );
    });

    it('the tool reads the rule the deployment makes', () => {
      expect(staging.predictedResources.find(ANCHOR_STOPPED_ALERT)?.name).toBe(DEAD_MAN_RULE);
    });

    it('the anchor rule is the SEV-1 and stateless, the pulse the SEV-2', () => {
      expect(brokenRules(changed(ANCHOR_STOPPED_ALERT, (alert) => (properties(alert).severity = 2)))).toContain(
        'dead-man-alerts',
      );
      expect(brokenRules(changed(ANCHOR_STOPPED_ALERT, (alert) => (properties(alert).autoMitigate = true)))).toContain(
        'dead-man-alerts',
      );
      expect(brokenRules(changed(JOBS_STOPPED_ALERT, (alert) => (properties(alert).severity = 1)))).toContain(
        'dead-man-alerts',
      );
      expect(brokenRules(changed(JOBS_STOPPED_ALERT, (alert) => (properties(alert).autoMitigate = false)))).toContain(
        'dead-man-alerts',
      );
    });

    it('another alert off on staging is still refused: only these two', () => {
      expect(brokenRules(changed(INTEGRITY_RUNS_ALERT, (alert) => (properties(alert).enabled = false)))).toContain(
        'alert-delivery',
      );
    });
  });

  it("integrity-runs-alert: no alert on an integrity job's skipped run, or one that counts something else or misses a job, can't fire or fires too late", () => {
    const properties = (alert: Mutable): Mutable => inside(alert, 'properties');
    const query =
      (events: string, table = 'ContainerAppConsoleLogs') =>
      (alert: Mutable) =>
        (criterion(alert).query =
          `${table} | where tostring(parse_json(Log).event) in (${events}) | summarize Events = count()`);
    const JOBS = [
      'access_log_seal',
      'access_log_seal_check',
      'hold_history',
      'holdings_check',
      'mandate_expiry',
      'request_expiry',
      'request_void',
      'waiting_rejection',
    ].map((job) => `"${job}.run_failed"`);
    const EVERY_JOB = JOBS.join(', ');
    expect(brokenRules(without(INTEGRITY_RUNS_ALERT))).toEqual(['integrity-runs-alert']);
    for (const change of [
      // Each job left out in turn.
      ...JOBS.map((left) => query(JOBS.filter((job) => job !== left).join(', '))),
      query(EVERY_JOB.replace('"hold_history.run_failed"', '"hold_history.failed"')),
      query(EVERY_JOB, 'ContainerAppSystemLogs'),
      (alert: Mutable) => (criterion(alert).threshold = 1),
      ...LATE_OR_BLIND,
      (alert: Mutable) => (criterion(alert).operator = 'LessThan'),
      (alert: Mutable) => (criterion(alert).timeAggregation = 'Count'),
      (alert: Mutable) => (properties(alert).scopes = ['/subscriptions/x/workspaces/y']),
    ]) {
      expect(brokenRules(changed(INTEGRITY_RUNS_ALERT, change))).toEqual(['integrity-runs-alert']);
    }
    expect(brokenRules(changed(INTEGRITY_RUNS_ALERT, query(EVERY_JOB)))).toEqual([]);
    expect(brokenRules(changed(INTEGRITY_RUNS_ALERT, (alert) => (properties(alert).enabled = false)))).toEqual([
      'alert-delivery',
      'integrity-runs-alert',
    ]);
    // Its runbook is the playbook's section O.
    expect(String(at(staging.predictedResources.find(INTEGRITY_RUNS_ALERT)?.properties, 'description'))).toMatch(
      / Runbook: Incident-Response-Playbook\.md section O\.$/,
    );
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
    const ANY_TRUST = type('Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials');
    // CI's trust alone: the watch's is `job-watch`'s.
    const TRUST = (resource: PredictedResource): boolean =>
      ANY_TRUST(resource) && resource.name.startsWith('id-agentx-stg-release/');
    const ROLE = RELEASE_ROLE;
    const RELEASE = named(/^id-agentx-stg-release$/);
    const subject = 'repo:shahbaz242630@205810405/agent-x@1368211207:environment:staging';
    const trust = 'id-agentx-stg-release/github';
    const trustIn = (resource: Mutable): Mutable => inside(resource, 'properties');
    const permissionsOf = (role: Mutable): Mutable => first(at(role, 'properties', 'permissions'));
    const role = String(staging.predictedResources.find(ROLE)?.name);
    const group = String(staging.predictedResources.find(type('Microsoft.Resources/resourceGroups'))?.id);

    const trusted = {
      issuer: 'https://token.actions.githubusercontent.com',
      subject,
      audiences: ['api://AzureADTokenExchange'],
    };
    // CI's, and the job-start watch's (S175) for main's own subject, which `job-watch` checks.
    const mainSubject = 'repo:shahbaz242630@205810405/agent-x@1368211207:ref:refs/heads/main';
    expect(staging.predictedResources.filter(ANY_TRUST).map((found) => [found.name, found.properties])).toEqual([
      [trust, trusted],
      ['id-agentx-stg-job-watch/github', { ...trusted, subject: mainSubject }],
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
    // Staging's watch isn't production's either, so its trust is one more on no known identity.
    const watchTrust = 'id-agentx-stg-job-watch/github';
    expect(releaseProblems(staging, production)).toEqual([
      'the deployment: needs an identity for CI (id-agentx-prd-release)',
      `${trust}: must be on CI's identity: no other identity is signed in to from outside Azure`,
      `${trust}: must trust ${subject.replace(/staging$/, 'production')} alone (a job in this environment's GitHub environment); it trusts ${JSON.stringify(subject)}`,
      `${watchTrust}: must be on CI's identity: no other identity is signed in to from outside Azure`,
      `${watchTrust}: must trust ${subject.replace(/staging$/, 'production')} alone (a job in this environment's GitHub environment); it trusts ${JSON.stringify(mainSubject)}`,
      "the deployment: needs one trust, for CI's identity; the snapshot has 2",
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

  it('SEC-OPS-12 release-access: CI given its role on anything but the API app and the migration job, to anyone else, or not once', () => {
    // The rule's own messages, so a condition another one also catches can't hide.
    const accessProblems = (snapshotted: Snapshot): string[] =>
      policyProblems(snapshotted, STAGING)
        .filter((problem) => problem.rule === 'release-access')
        .map((problem) => `${problem.resource}: ${problem.message}`);
    const group = idOf(type('Microsoft.Resources/resourceGroups'));
    const subscription = group.slice(0, group.indexOf('/resourceGroups/'));
    const role = String(staging.predictedResources.find(RELEASE_ROLE)?.name);
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
      `[reference('${idOf(named(new RegExp('^' + identity + '$')))}', '2024-11-30').principalId]`;
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
      (resource) => RELEASE_ROLE(resource) || GIVES_ROLE(resource),
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
    expect(brokenRules(asOwner)).toEqual(['release-identity', 'release-access', 'role-actions', 'secret-access']);
    // A second custom role, wider, given to CI on the API in place of CI's own.
    const wider = structuredClone(staging.predictedResources.find(RELEASE_ROLE));
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
    expect(brokenRules(widened)).toEqual(['release-identity', 'release-access', 'role-actions', 'secret-access']);
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

  it('SEC-OPS-14 job-watch: the job-start watch trusted for another subject, allowed more than reading the jobs, or given its role anywhere but the group, to anyone else (S175)', () => {
    // The rule's own messages, so a condition another one also catches can't hide.
    const watchProblems = (snapshotted: Snapshot, expected = STAGING): string[] =>
      policyProblems(snapshotted, expected)
        .filter((problem) => problem.rule === 'job-watch')
        .map((problem) => `${problem.resource}: ${problem.message}`);
    const WATCH = named(/^id-agentx-stg-job-watch$/);
    const TRUST = (resource: PredictedResource): boolean =>
      type('Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials')(resource) &&
      resource.name === 'id-agentx-stg-job-watch/github';
    const ROLE = (resource: PredictedResource): boolean =>
      ROLE_DEFINITIONS(resource) && String(at(resource.properties, 'roleName')).startsWith('Agent X job watch ');
    const GRANT = (resource: PredictedResource): boolean =>
      ASSIGNMENTS(resource) &&
      at(resource.properties, 'description') ===
        'The job-start watch reads the jobs and their runs (deploy/azure/modules/job-watch.bicep)';
    const group = idOf(type('Microsoft.Resources/resourceGroups'));
    const subscription = group.slice(0, group.indexOf('/resourceGroups/'));
    const role = String(staging.predictedResources.find(ROLE)?.name);
    const grant = String(staging.predictedResources.find(GRANT)?.name);
    const marker = '/providers/Microsoft.Authorization/roleAssignments/';
    const permissionsOf = (found: Mutable): Mutable => first(at(found, 'properties', 'permissions'));
    const grantProperties = (found: Mutable): Mutable => inside(found, 'properties');
    const principal = (identity: string): string =>
      `[reference('${idOf(named(new RegExp('^' + identity + '$')))}', '2024-11-30').principalId]`;
    const wanted = [
      'Microsoft.App/jobs/read',
      'Microsoft.App/jobs/executions/read',
      'Microsoft.App/jobs/execution/read',
    ];
    const alone = `${grant}: must give the job-start watch's role to the watch's identity (principalType ServicePrincipal) on this deployment's resource group alone`;

    // As deployed: read-only, on the group, to the watch, named by names.bicep, trusted for main's own subject.
    expect(role).toBe(bicepGuid(group, 'job-watch'));
    expect(staging.predictedResources.filter(WATCH).map((found) => found.properties)).toEqual([
      { isolationScope: 'Regional' },
    ]);
    expect(at(staging.predictedResources.find(ROLE)?.properties, 'permissions')).toEqual([
      { actions: wanted, notActions: [], dataActions: [], notDataActions: [] },
    ]);
    expect(
      staging.predictedResources.filter(GRANT).map((found) => [found.id.split(marker)[0], found.properties]),
    ).toEqual([
      [
        group,
        {
          description: 'The job-start watch reads the jobs and their runs (deploy/azure/modules/job-watch.bicep)',
          roleDefinitionId: `${subscription}/providers/Microsoft.Authorization/roleDefinitions/${role}`,
          principalId: principal('id-agentx-stg-job-watch'),
          principalType: 'ServicePrincipal',
        },
      ],
    ]);
    expect(watchProblems(staging)).toEqual([]);
    expect(watchProblems(productionLike({ subject: true }), { region: 'uaenorth', environment: 'production' })).toEqual(
      [],
    );

    // No identity, no trust, two, or a trust for another subject.
    // Without its identity, its grant names no one the deployment creates.
    expect(watchProblems(without(WATCH))).toEqual([
      'the deployment: needs an identity for the job-start watch (id-agentx-stg-job-watch)',
      alone,
    ]);
    expect(watchProblems(without(TRUST))).toEqual([
      "the deployment: needs one trust for the job-start watch's identity; the snapshot has 0",
    ]);
    const second = structuredClone(staging.predictedResources.find(TRUST)) as unknown as Mutable;
    expect(watchProblems(withExtra(second))).toEqual([
      "the deployment: needs one trust for the job-start watch's identity; the snapshot has 2",
    ]);
    // Main's own subject alone: never CI's environment subject (which would let any job in `staging` sign in as the
    // watch), another branch, a pull request, or the old form without IDs.
    const mainSubject = 'repo:shahbaz242630@205810405/agent-x@1368211207:ref:refs/heads/main';
    expect(at(staging.predictedResources.find(TRUST)?.properties, 'subject')).toBe(mainSubject);
    for (const other of [
      'repo:shahbaz242630@205810405/agent-x@1368211207:environment:staging',
      'repo:shahbaz242630@205810405/agent-x@1368211207:ref:refs/heads/other',
      'repo:shahbaz242630@205810405/agent-x@1368211207:pull_request',
      'repo:shahbaz242630/agent-x:ref:refs/heads/main',
    ]) {
      expect(watchProblems(changed(TRUST, (found) => (inside(found, 'properties').subject = other)))).toEqual([
        `id-agentx-stg-job-watch/github: must trust ${mainSubject} alone (a job on main, in no GitHub environment); it trusts ${JSON.stringify(other)}`,
      ]);
    }
    // An app or a job running as the watch would read with the watch's role.
    const running = changed(JOB('migrate'), (job) => {
      inside(job, 'identity', 'userAssignedIdentities')[idOf(WATCH).toUpperCase()] = {};
    });
    expect(watchProblems(running)).toEqual([
      "job-agentx-stg-migrate: must not run as the job-start watch's identity, whose role is the watch's alone",
    ]);

    // The role: starting, a secret's list, a write, a shell, every action, or one read less.
    for (const actions of [
      [...wanted, 'Microsoft.App/jobs/start/action'],
      [...wanted, 'Microsoft.App/jobs/listsecrets/action'],
      [...wanted, 'Microsoft.App/jobs/write'],
      [...wanted, 'Microsoft.App/jobs/exec/action'],
      ['*'],
      wanted.slice(1),
    ]) {
      expect(watchProblems(changed(ROLE, (found) => (permissionsOf(found).actions = actions)))).toEqual([
        `${role}: must allow exactly ${wanted.join(', ')}; it allows ${actions.join(', ')}`,
      ]);
    }
    const secretValue = 'Microsoft.KeyVault/vaults/secrets/getSecret/action';
    expect(watchProblems(changed(ROLE, (found) => (permissionsOf(found).dataActions = [secretValue])))).toEqual([
      `${role}: must allow no data action, which could read a secret's value; it allows ${secretValue}`,
    ]);
    expect(
      watchProblems(changed(ROLE, (found) => (inside(found, 'properties').assignableScopes = [subscription]))),
    ).toEqual([
      `${role}: must be assignable in this deployment's resource group alone; it says ${JSON.stringify([subscription])}`,
    ]);
    expect(watchProblems(without(ROLE))).toEqual([
      'the deployment: needs one custom role for the job-start watch; the snapshot has 0',
    ]);

    // Given at the subscription or on one job, to the API's identity, as a user, or not once.
    for (const scope of [subscription, idOf(JOB('operator'))]) {
      expect(watchProblems(changed(GRANT, (found) => (found.id = `${scope}${marker}${grant}`)))).toEqual([alone]);
    }
    for (const change of [
      (found: Mutable) => (grantProperties(found).principalId = principal('id-agentx-stg-api')),
      (found: Mutable) => (grantProperties(found).principalType = 'User'),
    ]) {
      expect(watchProblems(changed(GRANT, change))).toEqual([alone]);
    }
    expect(watchProblems(without(GRANT))).toEqual([
      "the deployment: must give the job-start watch's role once; it gives it 0 times",
    ]);
    const twice = structuredClone(staging.predictedResources.find(GRANT)) as unknown as Mutable;
    expect(watchProblems(withExtra(twice))).toEqual([
      "the deployment: must give the job-start watch's role once; it gives it 2 times",
    ]);
    // Any other role to the watch, a vault reader's among them, is `secret-access`'s to refuse.
    const reads = changed(READS('api', 'db-app-password'), (found) => {
      grantProperties(found).principalId = principal('id-agentx-stg-job-watch');
    });
    expect(brokenRules(reads)).toEqual(['secret-access']);
  });

  it('role-actions (AZ2): a custom role allowing a wildcard, a door, the environment, a grant, a policy rule or a secret listing', () => {
    const RELEASE_ROLE = (resource: PredictedResource): boolean =>
      resource.type === 'Microsoft.Authorization/roleDefinitions' &&
      at(resource.properties, 'description') ===
        'CI after a merge: update our image in the API and the migration job, and run the migration. Nothing else.';
    const EVIDENCE_ROLE = (resource: PredictedResource): boolean =>
      resource.type === 'Microsoft.Authorization/roleDefinitions' &&
      list(at(resource.properties, 'permissions', '0', 'dataActions')).length === 1;
    // Read back from staging (S188): CI's role has neither a door's write nor any wildcard.
    const actions = list(at(staging.predictedResources.find(RELEASE_ROLE)?.properties, 'permissions', '0', 'actions'));
    expect(actions.some((action) => String(action).includes('*') || /httpRouteConfigs/i.test(String(action)))).toBe(
      false,
    );
    const adding =
      (action: string, key = 'actions') =>
      (role: Mutable) =>
        (first(inside(role, 'properties').permissions)[key] = [
          ...list(first(inside(role, 'properties').permissions)[key]),
          action,
        ]);
    for (const action of [
      'Microsoft.App/jobs/*/action',
      '*',
      'Microsoft.App/managedEnvironments/httpRouteConfigs/write',
      'MICROSOFT.APP/MANAGEDENVIRONMENTS/HTTPROUTECONFIGS/WRITE',
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
      'Microsoft.Storage/storageAccounts/write',
      'Microsoft.Storage/storageAccounts/listKeys/action',
      'Microsoft.Storage/storageAccounts/regenerateKey/action',
    ]) {
      expect(brokenRules(changed(RELEASE_ROLE, adding(action)))).toEqual(['release-identity', 'role-actions']);
    }
    // Reading a secret from the RBAC vault is a data action, refused as one.
    expect(
      brokenRules(changed(RELEASE_ROLE, adding('Microsoft.KeyVault/vaults/secrets/getSecret/action', 'dataActions'))),
    ).toContain('role-actions');
    // A store's role, held to its data actions by its own rule, is held here too.
    expect(
      brokenRules(
        changed(
          EVIDENCE_ROLE,
          adding('Microsoft.Storage/storageAccounts/blobServices/containers/blobs/*', 'dataActions'),
        ),
      ),
    ).toContain('role-actions');
  });

  it("role-actions (AZ3): a role but CI's allowed to start a job, whose start is the job's secrets", () => {
    const WATCH_ROLE = (resource: PredictedResource): boolean =>
      ROLE_DEFINITIONS(resource) && String(at(resource.properties, 'roleName')).startsWith('Agent X job watch ');
    const starting = (action: string) => (role: Mutable) => {
      const permissions = first(inside(role, 'properties').permissions);
      permissions.actions = [...list(permissions.actions), action];
    };
    // CI's role starts the migration, as every release does.
    expect(
      list(at(staging.predictedResources.find(RELEASE_ROLE)?.properties, 'permissions', '0', 'actions')),
    ).toContain('Microsoft.App/jobs/start/action');
    for (const action of ['Microsoft.App/jobs/start/action', 'MICROSOFT.APP/JOBS/START/ACTION']) {
      expect(brokenRules(changed(WATCH_ROLE, starting(action)))).toEqual(['job-watch', 'role-actions']);
    }
    // A stop or a read of a run is no start.
    expect(brokenRules(changed(WATCH_ROLE, starting('Microsoft.App/jobs/stop/action')))).toEqual(['job-watch']);
  });

  it("SEC-DB-07 Stage G's mark and checks (AZ3): their own identity, reading the owner's, the app's and the backup role's logins alone", () => {
    const grants = staging.predictedResources
      .filter((resource) => ASSIGNMENTS(resource))
      .map((resource) => String(at(resource.properties, 'description')))
      .filter((description) => description.startsWith('stage-g reads '));
    expect(grants).toEqual([
      'stage-g reads db-owner-password (deploy/azure/secrets.bicep)',
      'stage-g reads db-app-password (deploy/azure/secrets.bicep)',
      'stage-g reads db-backup-password (deploy/azure/secrets.bicep)',
    ]);
    // The server admin's login, the operator's or Zitadel's, given to it: refused.
    for (const secret of ['db-admin-password', 'db-operator-password', 'db-zitadel-password']) {
      const extra = structuredClone(
        staging.predictedResources.find(READS('stage-g', 'db-owner-password')),
      ) as unknown as Mutable;
      const reader = structuredClone(staging.predictedResources.find(READS('db-setup', secret))) as unknown as Mutable;
      extra.id = String(reader.id).replace(/[^/]+$/, 'stage-g-extra');
      expect(brokenRules(withExtra(extra))).toEqual(['secret-access']);
    }
    // One of its three left out: refused, as each is needed.
    expect(brokenRules(without(READS('stage-g', 'db-backup-password')))).toEqual(['secret-access']);
  });

  it('release-writes-alert (AZ2): no alert on CI doing anything but a release, or one that lets a write through, fires late or quietly', () => {
    const RELEASE_WRITES = named(/^alert-agentx-.+-release-writes$/);
    const properties = (alert: Mutable): Mutable => inside(alert, 'properties');
    const query = String(
      at(staging.predictedResources.find(RELEASE_WRITES)?.properties, 'criteria', 'allOf', '0', 'query'),
    );
    const identity = idOf(named(/^id-agentx-stg-release$/));
    const api = idOf(APP('api'));
    const migrate = idOf(JOB('migrate'));
    expect(query).toBe(
      `AzureActivity | where tostring(parse_json(Claims).xms_mirid) =~ "${identity}" | where not((OperationNameValue =~ "Microsoft.App/containerApps/write" and _ResourceId =~ "${api}") or (OperationNameValue in~ ("Microsoft.App/jobs/write", "Microsoft.App/jobs/start/action") and _ResourceId =~ "${migrate}")) | summarize Writes = count()`,
    );
    expect(brokenRules(without(RELEASE_WRITES))).toEqual(['release-writes-alert']);
    // Without case, as KQL's =~ compares, it is the same query.
    expect(
      brokenRules(
        changed(RELEASE_WRITES, (alert) => (criterion(alert).query = query.replace(identity, identity.toUpperCase()))),
      ),
    ).toEqual([]);
    const asked = (text: string) => (alert: Mutable) => (criterion(alert).query = text);
    for (const change of [
      asked(query.replace(identity, idOf(named(/^id-agentx-stg-job-watch$/)))),
      asked(query.replace('xms_mirid', 'appid')),
      asked(query.replace(`"${api}"`, `"${idOf(APP('zitadel'))}"`)),
      asked(query.replace(`"${migrate}"`, `"${idOf(JOB('db-setup'))}"`)),
      asked(
        query.replace(
          ', "Microsoft.App/jobs/start/action"',
          ', "Microsoft.App/jobs/start/action", "Microsoft.App/jobs/stop/action"',
        ),
      ),
      asked(query.replace('Microsoft.App/containerApps/write', 'Microsoft.App/containerApps/*')),
      asked(query.replace('where not(', 'where (')),
      asked(query.replace(' | summarize', ' | where ActivityStatusValue == "Success" | summarize')),
      (alert: Mutable) => (criterion(alert).threshold = 1),
      (alert: Mutable) => (criterion(alert).operator = 'LessThan'),
      (alert: Mutable) => (criterion(alert).timeAggregation = 'Count'),
      (alert: Mutable) => (properties(alert).windowSize = 'PT30M'),
      (alert: Mutable) => (properties(alert).evaluationFrequency = 'PT30M'),
      (alert: Mutable) => (inside(criterion(alert), 'failingPeriods').minFailingPeriodsToAlert = 3),
      (alert: Mutable) => (inside(criterion(alert), 'failingPeriods').numberOfEvaluationPeriods = 3),
      (alert: Mutable) => (properties(alert).scopes = [idOf(LOGIN_WORKSPACE)]),
    ]) {
      expect(brokenRules(changed(RELEASE_WRITES, change))).toEqual(['release-writes-alert']);
    }
    expect(brokenRules(changed(RELEASE_WRITES, (alert) => (properties(alert).severity = 2)))).toEqual([
      'alert-runbook',
      'release-writes-alert',
    ]);
    expect(brokenRules(changed(RELEASE_WRITES, (alert) => (properties(alert).autoMitigate = true)))).toEqual([
      'alert-delivery',
      'release-writes-alert',
    ]);
    // With no identity of CI's, no query can be right: not even one naming no identity, which would match nothing.
    expect(brokenRules(without(named(/^id-agentx-stg-release$/)))).toContain('release-writes-alert');
    const noIdentity = changed(
      (resource) => RELEASE_WRITES(resource),
      (alert) => (criterion(alert).query = query.replace(`=~ "${identity}"`, '=~ ""')),
      without(named(/^id-agentx-stg-release$/)),
    );
    expect(brokenRules(noIdentity)).toContain('release-writes-alert');
  });

  describe("azure-policy (AZ2): Azure's own refusals on the resource group", () => {
    const DEFINITION = (guardrail: string) => (resource: PredictedResource) =>
      resource.type === 'Microsoft.Authorization/policyDefinitions' && resource.name === `agentx-staging-${guardrail}`;
    const ASSIGNMENT = (guardrail: string) => (resource: PredictedResource) =>
      resource.type === 'Microsoft.Authorization/policyAssignments' && resource.name === `agentx-staging-${guardrail}`;
    const GUARDRAIL_NAMES = ['apps-internal', 'apps-https', 'images', 'jobs-by-hand', 'app-replicas', 'allowed-types'];
    const policyProblemsOf = (snapshotted: Snapshot): string[] =>
      policyProblems(snapshotted, STAGING)
        .filter((problem) => problem.rule === 'azure-policy')
        .map(({ resource, message }) => `${resource}: ${message}`);
    const ruleOf = (definition: Mutable): Mutable => inside(definition, 'properties', 'policyRule');
    /** Each leaf of a rule's condition, a count's `where` walked into, for changing one in place. */
    const leaves = (condition: unknown): Mutable[] => {
      if (Array.isArray(condition)) return condition.flatMap(leaves);
      if (typeof condition !== 'object' || condition === null) return [];
      const object = condition as Mutable;
      return 'field' in object && !('where' in object) ? [object] : Object.values(object).flatMap(leaves);
    };

    it('gives each of the six rules once on the group, enforced, as Deny, Indexed, with the words a refusal gets back', () => {
      const group = idOf(type('Microsoft.Resources/resourceGroups'));
      for (const guardrail of GUARDRAIL_NAMES) {
        const definition = staging.predictedResources.find(DEFINITION(guardrail));
        const assignment = staging.predictedResources.find(ASSIGNMENT(guardrail));
        expect(at(definition?.properties, 'mode')).toBe('Indexed');
        expect(at(definition?.properties, 'policyRule', 'then', 'effect')).toBe('deny');
        expect(assignment?.id).toBe(
          `${group}/providers/Microsoft.Authorization/policyAssignments/agentx-staging-${guardrail}`,
        );
        expect(at(assignment?.properties, 'policyDefinitionId')).toBe(definition?.id);
        expect(String(at(assignment?.properties, 'nonComplianceMessages', '0', 'message'))).toMatch(
          /^Refused: .+ Nothing changed; .+\.$/,
        );
      }
      // The aliases Azure lists for Microsoft.App, the ingress two as its built-in rules use them (S188).
      expect(JSON.stringify(staging.predictedResources.find(DEFINITION('apps-internal'))?.properties)).toContain(
        '"field":"Microsoft.App/containerApps/configuration.ingress.external","equals":true',
      );
      expect(JSON.stringify(staging.predictedResources.find(DEFINITION('apps-https'))?.properties)).toContain(
        '"field":"Microsoft.App/containerApps/configuration.ingress.allowInsecure","equals":true',
      );
    });

    it('a rule or its assignment missing, doubled, another kind, not enforced, scoped wider or narrower, or one nobody reads', () => {
      for (const guardrail of GUARDRAIL_NAMES) {
        expect(brokenRules(without(DEFINITION(guardrail)))).toEqual(['azure-policy']);
        expect(brokenRules(without(ASSIGNMENT(guardrail)))).toEqual(['azure-policy']);
        const twice = structuredClone(staging.predictedResources.find(ASSIGNMENT(guardrail))) as unknown as Mutable;
        expect(brokenRules(withExtra(twice))).toEqual(['azure-policy']);
      }
      const definitionProperties = (definition: Mutable): Mutable => inside(definition, 'properties');
      const assignmentProperties = definitionProperties;
      for (const change of [
        (definition: Mutable) => (definitionProperties(definition).mode = 'All'),
        (definition: Mutable) => (inside(ruleOf(definition), 'then').effect = 'audit'),
        (definition: Mutable) => (inside(ruleOf(definition), 'then').effect = 'disabled'),
        (definition: Mutable) => (definitionProperties(definition).policyType = 'BuiltIn'),
        (definition: Mutable) => (definitionProperties(definition).parameters = { effect: { type: 'String' } }),
        (definition: Mutable) =>
          (definition.id = String(definition.id).replace(
            '/providers/',
            '/resourceGroups/rg-agentx-staging/providers/',
          )),
      ]) {
        expect(brokenRules(changed(DEFINITION('images'), change))).toEqual(['azure-policy']);
      }
      for (const change of [
        (assignment: Mutable) => (assignmentProperties(assignment).enforcementMode = 'DoNotEnforce'),
        (assignment: Mutable) => (assignmentProperties(assignment).notScopes = [idOf(APP('api'))]),
        (assignment: Mutable) => (assignmentProperties(assignment).nonComplianceMessages = []),
        (assignment: Mutable) => (assignmentProperties(assignment).nonComplianceMessages = [{ message: '' }]),
        (assignment: Mutable) =>
          (assignment.id = String(assignment.id).replace('/resourceGroups/rg-agentx-staging', '')),
        (assignment: Mutable) => (assignmentProperties(assignment).policyDefinitionId = idOf(DEFINITION('apps-https'))),
      ]) {
        expect(brokenRules(changed(ASSIGNMENT('images'), change))).toEqual(['azure-policy']);
      }
      const stranger = structuredClone(staging.predictedResources.find(DEFINITION('images'))) as unknown as Mutable;
      stranger.name = 'agentx-staging-something-else';
      expect(policyProblemsOf(withExtra(stranger))).toEqual([
        'agentx-staging-something-else: is no rule of modules/guardrails.bicep: one no check reads',
      ]);
    });

    it('each rule refuses its bad examples: a rule whose field or value is wrong refuses nothing, and is caught', () => {
      const lets = (guardrail: string): string =>
        `agentx-staging-${guardrail}: lets through what it is for (${guardrail}): its condition matches nothing it should`;
      const firstLeaf =
        (field: RegExp) =>
        (definition: Mutable): Mutable =>
          leaves(ruleOf(definition).if).find((leaf) => field.test(String(leaf.field))) ?? {};
      const cases: readonly (readonly [string, (definition: Mutable) => void])[] = [
        [
          'apps-internal',
          (definition) =>
            (firstLeaf(/ingress\.external$/)(definition).field =
              'Microsoft.App/containerApps/configuration.ingress.externall'),
        ],
        ['apps-internal', (definition) => (firstLeaf(/ingress\.external$/)(definition).equals = 'yes')],
        [
          'apps-https',
          (definition) =>
            (firstLeaf(/allowInsecure$/)(definition).field =
              'Microsoft.App/containerApps/configuration.ingress.transport'),
        ],
        // Each place's digest condition, one at a time: Zitadel's image by tag alone gets through.
        ...[0, 1, 2, 3].map(
          (place) =>
            [
              'images',
              (definition: Mutable) => {
                const leaf = leaves(ruleOf(definition).if).filter((each) => 'notContains' in each)[place];
                if (leaf !== undefined) leaf.notContains = ':';
              },
            ] as const,
        ),
        // Each place's list of images, one at a time: another image by digest gets through.
        ...[0, 1, 2, 3].map(
          (place) =>
            [
              'images',
              (definition: Mutable) => {
                const leaf = leaves(ruleOf(definition).if).filter(
                  (each) => each.notLike === 'ghcr.io/shahbaz242630/agent-x@sha256:*',
                )[place];
                if (leaf !== undefined) leaf.notLike = '*';
              },
            ] as const,
        ),
        [
          'images',
          (definition) => {
            for (const leaf of leaves(ruleOf(definition).if).filter(
              (each) => 'notLike' in each && String(each.notLike).startsWith('ghcr.io/shahbaz242630/agent-x@'),
            ))
              leaf.notLike = 'ghcr.io/shahbaz242630/agent-x*';
          },
        ],
        [
          'images',
          (definition) => {
            for (const leaf of leaves(ruleOf(definition).if).filter((each) =>
              String(each.field).includes('initContainers'),
            ))
              leaf.field = String(leaf.field).replace('.image', '.images');
          },
        ],
        [
          'jobs-by-hand',
          (definition) => {
            for (const leaf of leaves(ruleOf(definition).if).filter(
              (each) => String(each.field).endsWith('.parallelism') && 'notIn' in each,
            ))
              leaf.notIn = [0, 1, 2];
          },
        ],
        [
          'jobs-by-hand',
          (definition) => {
            for (const leaf of leaves(ruleOf(definition).if).filter(
              (each) => String(each.field).endsWith('.replicaCompletionCount') && 'notIn' in each,
            ))
              leaf.notIn = [0, 1, 2];
          },
        ],
        [
          'app-replicas',
          (definition) => {
            for (const leaf of leaves(ruleOf(definition).if).filter((each) => list(each.notIn).length === 5))
              leaf.notIn = [0, 1, 2, 3, 4, 5];
          },
        ],
        [
          'app-replicas',
          (definition) => {
            for (const leaf of leaves(ruleOf(definition).if).filter((each) => each.field === 'name'))
              leaf.like = '*-job';
          },
        ],
        [
          'app-replicas',
          (definition) => {
            for (const leaf of leaves(ruleOf(definition).if).filter(
              (each) => String(each.field).endsWith('maxReplicas') && list(each.notIn).length === 2,
            ))
              leaf.notIn = [0, 1, 2];
          },
        ],
      ];
      for (const [guardrail, change] of cases) {
        expect(policyProblemsOf(changed(DEFINITION(guardrail), change))).toEqual([lets(guardrail)]);
      }
    });

    it('no rule refuses what we ship, a release sends, the load image, or four API replicas', () => {
      const refuses = (guardrail: string, what: string): string =>
        `agentx-staging-${guardrail}: refuses ${what}, which this deployment ships or a release sends: Azure would refuse our own deploy`;
      // A misspelled trigger field reads as missing, which the rule now refuses (AZ2e): every job refused, so caught.
      expect(
        policyProblemsOf(
          changed(DEFINITION('jobs-by-hand'), (definition) => {
            for (const leaf of leaves(ruleOf(definition).if).filter((each) =>
              String(each.field).endsWith('triggerType'),
            ))
              leaf.field = 'Microsoft.App/jobs/configuration.triggerTypo';
          }),
        ),
      ).toContain(refuses('jobs-by-hand', 'job-agentx-stg-migrate'));
      // A trigger rule turned to refuse the one trigger we use: our own jobs, and a release of them, refused.
      expect(
        policyProblemsOf(
          changed(DEFINITION('jobs-by-hand'), (definition) => {
            for (const leaf of leaves(ruleOf(definition).if).filter((each) =>
              String(each.field).endsWith('triggerType'),
            )) {
              delete leaf.notEquals;
              leaf.equals = 'Manual';
            }
          }),
        ),
      ).toContain(refuses('jobs-by-hand', 'job-agentx-stg-migrate'));
      // Zitadel's login pages' image left out of those allowed.
      expect(
        policyProblemsOf(
          changed(DEFINITION('images'), (definition) => {
            for (const leaf of leaves(ruleOf(definition).if).filter(
              (each) => each.notLike === 'ghcr.io/zitadel/zitadel-login:*',
            ))
              leaf.notLike = 'ghcr.io/zitadel/zitadel-logins:*';
          }),
        ),
      ).toEqual([refuses('images', 'ca-agentx-stg-login')]);
      // The load test's image left out: refused only in a load run, which the checks also make.
      expect(
        policyProblemsOf(
          changed(DEFINITION('images'), (definition) => {
            for (const leaf of leaves(ruleOf(definition).if).filter(
              (each) => each.notLike === 'ghcr.io/shahbaz242630/agent-x-load@sha256:*',
            ))
              leaf.notLike = 'ghcr.io/shahbaz242630/agent-x-lode@sha256:*';
          }),
        ),
      ).toEqual([refuses('images', 'ca-agentx-stg-api'), refuses('images', 'job-agentx-stg-migrate')]);
      // The cap below four: production's Zitadel and staging's load run need room.
      expect(
        policyProblemsOf(
          changed(DEFINITION('app-replicas'), (definition) => {
            for (const leaf of leaves(ruleOf(definition).if).filter((each) => list(each.notIn).length === 5))
              leaf.notIn = [0, 1, 2, 3];
          }),
        ),
      ).toEqual([refuses('app-replicas', 'ca-agentx-stg-api')]);
      // Turned around, refusing an app that keeps to https: every app (the API as shipped, as a release leaves it,
      // and at four replicas), and the bad example let through.
      expect(
        policyProblemsOf(
          changed(DEFINITION('apps-https'), (definition) => {
            const leaf = leaves(ruleOf(definition).if).find((each) => String(each.field).endsWith('allowInsecure'));
            if (leaf !== undefined) leaf.equals = false;
          }),
        ),
      ).toEqual([
        ...[
          'ca-agentx-stg-api',
          'ca-agentx-stg-zitadel',
          'ca-agentx-stg-login',
          'ca-agentx-stg-api',
          'ca-agentx-stg-api',
        ].map((app) => refuses('apps-https', app)),
        'agentx-staging-apps-https: lets through what it is for (apps-https): its condition matches nothing it should',
      ]);
    });

    it('reads `like` as Azure does: one wildcard, text on both sides of it, without case on either side', () => {
      expect(policyLike('aba', 'ab*ba')).toBe(false);
      expect(policyLike('abba', 'ab*ba')).toBe(true);
      expect(policyLike('abXba', 'ab*ba')).toBe(true);
      expect(policyLike('ABXBA', 'ab*ba')).toBe(true);
      expect(policyLike('abxba', 'AB*BA')).toBe(true);
      expect(policyLike('ab', 'ab')).toBe(true);
      expect(policyLike(undefined, 'ab*')).toBe(false);
      // Our image named in capitals is still ours (Azure compares without case); another's in capitals is still refused.
      const named = (image: string) =>
        changed(APP('api'), (app) => {
          containerOf(app).image = image;
        });
      const ours = String(containerOf(staging.predictedResources.find(APP('api')) as unknown as Mutable).image);
      expect(
        policyProblemsOf(named(ours.replace('ghcr.io/shahbaz242630/agent-x', 'GHCR.IO/SHAHBAZ242630/AGENT-X'))),
      ).toEqual([]);
      // Refused as shipped and as CI's partial update of it.
      expect(policyProblemsOf(named(`DOCKER.IO/LIBRARY/BUSYBOX@sha256:${'0'.repeat(64)}`))).toEqual(
        Array.from(
          { length: 2 },
          () =>
            'agentx-staging-images: refuses ca-agentx-stg-api, which this deployment ships or a release sends: Azure would refuse our own deploy',
        ),
      );
    });

    it('the images rule given twice, once at the group and once wider: refused', () => {
      const wider = structuredClone(staging.predictedResources.find(ASSIGNMENT('images'))) as unknown as Mutable;
      wider.id = String(wider.id).replace('/resourceGroups/rg-agentx-staging', '');
      expect(brokenRules(withExtra(wider))).toEqual(['azure-policy']);
      const renamed = structuredClone(staging.predictedResources.find(ASSIGNMENT('images'))) as unknown as Mutable;
      renamed.id = String(renamed.id).replace(/agentx-staging-images$/, 'agentx-staging-images-again');
      expect(brokenRules(withExtra(renamed))).toEqual(['azure-policy']);
    });

    it('a condition the checks cannot read is refused, not judged', () => {
      const unread = (guardrail: string, what: string): string =>
        `agentx-staging-${guardrail}: holds a condition these checks can't read (${what}), so none can say it's right`;
      expect(
        policyProblemsOf(
          changed(DEFINITION('images'), (definition) => {
            const leaf = leaves(ruleOf(definition).if).find((each) => 'notLike' in each);
            if (leaf !== undefined) leaf.notLike = 'ghcr.io/*/agent-x@*';
          }),
        ),
      ).toEqual([unread('images', 'like with more than one wildcard: ghcr.io/*/agent-x@*')]);
      expect(
        policyProblemsOf(
          changed(DEFINITION('apps-internal'), (definition) => {
            const leaf = leaves(ruleOf(definition).if).find((each) => String(each.field).endsWith('external'));
            if (leaf !== undefined) {
              delete leaf.equals;
              leaf.match = 'true';
            }
          }),
        ),
      ).toEqual([unread('apps-internal', "an operator these checks don't read: match")]);
      expect(
        policyProblemsOf(
          changed(DEFINITION('apps-internal'), (definition) => {
            const leaf = leaves(ruleOf(definition).if).find((each) => String(each.field).endsWith('external'));
            if (leaf !== undefined) leaf.field = 'Microsoft.App/containerApps/template.containers[*].image';
          }),
        ),
      ).toEqual([
        unread(
          'apps-internal',
          'an array field outside a count: Microsoft.App/containerApps/template.containers[*].image',
        ),
      ]);
    });

    it('allows exactly the types the deployment creates and its records', () => {
      const typesOf = (definition: Mutable): Mutable => inside(ruleOf(definition), 'if', 'not');
      const allowed = list(
        at(staging.predictedResources.find(DEFINITION('allowed-types'))?.properties, 'policyRule', 'if', 'not', 'in'),
      );
      // The list is staging's own types (a load run's and Stage G's are among them) and the deployments' records.
      // #627's activity-log alerts are allowed before they land, as the foundation that brings them is judged by it.
      const made = [
        ...staging.predictedResources.map((resource) => resource.type),
        'Microsoft.Resources/deployments',
        'Microsoft.Insights/activityLogAlerts',
        // The interface Azure makes for the audit-export store's private endpoint (AZ11).
        'Microsoft.Network/networkInterfaces',
      ];
      expect(new Set(allowed)).toEqual(new Set(made));
      expect(new Set(ALLOWED_TYPES)).toEqual(new Set(made));
      expect(ALLOWED_TYPES).toHaveLength(new Set(made).size);
      // An alert processing rule in the group could mute every alarm, the access alarm's among them (AZ5e review):
      // only the allowed-types guardrail keeps CI from making one, so the type stays off the list.
      expect(ALLOWED_TYPES).not.toContain('Microsoft.AlertsManagement/actionRules');
      const exactly: unknown = expect.stringMatching(
        /^agentx-staging-allowed-types: must allow exactly Microsoft\.App\//,
      );
      const fewer = changed(DEFINITION('allowed-types'), (definition) => {
        typesOf(definition).in = allowed.filter((each) => each !== 'Microsoft.Network/virtualNetworks');
      });
      expect(policyProblemsOf(fewer)).toEqual([
        'agentx-staging-allowed-types: refuses vnet-agentx-staging, which this deployment ships or a release sends: Azure would refuse our own deploy',
        exactly,
      ]);
      // The activity-log alerts left out: #627's two (now shipped) and the must-pass example are refused.
      const noAlerts = changed(DEFINITION('allowed-types'), (definition) => {
        typesOf(definition).in = allowed.filter((each) => each !== 'Microsoft.Insights/activityLogAlerts');
      });
      expect(policyProblemsOf(noAlerts)).toEqual([
        'agentx-staging-allowed-types: refuses alert-agentx-stg-alert-rules-changed, which this deployment ships or a release sends: Azure would refuse our own deploy',
        'agentx-staging-allowed-types: refuses alert-agentx-stg-alert-rules-unhealthy, which this deployment ships or a release sends: Azure would refuse our own deploy',
        'agentx-staging-allowed-types: refuses an activity-log alert, which this deployment ships or a release sends: Azure would refuse our own deploy',
        exactly,
      ]);
      // AZ11's endpoint and its interface left out: the shipped endpoint and the must-pass examples are refused.
      const noEndpoint = changed(DEFINITION('allowed-types'), (definition) => {
        typesOf(definition).in = allowed.filter(
          (each) => each !== 'Microsoft.Network/privateEndpoints' && each !== 'Microsoft.Network/networkInterfaces',
        );
      });
      expect(policyProblemsOf(noEndpoint)).toEqual([
        expect.stringMatching(/^agentx-staging-allowed-types: refuses pe-stagentxstg[a-z0-9]{6}-blob, which/),
        'agentx-staging-allowed-types: refuses a private endpoint, which this deployment ships or a release sends: Azure would refuse our own deploy',
        "agentx-staging-allowed-types: refuses a private endpoint's interface, which this deployment ships or a release sends: Azure would refuse our own deploy",
        exactly,
      ]);
      const more = changed(DEFINITION('allowed-types'), (definition) => {
        typesOf(definition).in = [...allowed, 'Microsoft.Compute/virtualMachines'];
      });
      expect(policyProblemsOf(more)).toEqual([
        'agentx-staging-allowed-types: lets through what it is for (allowed-types): its condition matches nothing it should',
        exactly,
      ]);
      // Another name in place of one: the same count, still refused.
      const swapped = changed(DEFINITION('allowed-types'), (definition) => {
        typesOf(definition).in = allowed.map((each) =>
          each === 'Microsoft.Insights/workbooks' ? 'Microsoft.Compute/virtualMachines' : each,
        );
      });
      expect(policyProblemsOf(swapped)).toContainEqual(exactly);
      // Case is Azure's to ignore.
      const cased = changed(DEFINITION('allowed-types'), (definition) => {
        typesOf(definition).in = allowed.map((each) => String(each).toUpperCase());
      });
      expect(policyProblemsOf(cased)).toEqual([]);
      // A new type in the deployment needs the list to name it, or Azure refuses our own deploy.
      const added = withExtra({
        ...structuredClone(staging.predictedResources.find(VAULT)),
        type: 'Microsoft.Cache/redis',
        name: 'redis',
      });
      expect(policyProblemsOf(added)).toEqual([
        'agentx-staging-allowed-types: refuses redis, which this deployment ships or a release sends: Azure would refuse our own deploy',
      ]);
    });
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

  it('SEC-OPS-11 vault-secrets, B5-3: the email key copied on a condition, from another service, or written in the code; a copy standing in for another secret', () => {
    const COPIED_KEY = SECRET('acs-access-key');
    const listed = String(at(staging.predictedResources.find(COPIED_KEY)?.properties, 'value'));
    const service = String(staging.predictedResources.find(COMMUNICATION)?.id);
    // As staging has it: the primary key of the service this deployment creates.
    expect(listed).toBe(`[listKeys('${service}', '2026-03-18').primaryKey]`);
    const value = (to: string) => (secret: Mutable) => (inside(secret, 'properties').value = to);
    // Only when a condition holds: a rotation run could leave the old key while the API reads the new.
    expect(
      brokenRules(changed(COPIED_KEY, (secret) => (secret.condition = "[not(empty(parameters('directoryToken')))]"))),
    ).toEqual(['vault-secrets']);
    // From a service abroad or no service of ours, from our email service by another name, or the key written down.
    for (const change of [
      value(listed.replace('/resourceGroups/rg-agentx-staging/', '/resourceGroups/rg-elsewhere/')),
      value(listed.replace('/communicationServices/acs-agentx-stg-', '/communicationServices/acs-other-')),
      value(listed.replace(service, String(staging.predictedResources.find(EMAIL_SERVICE)?.id))),
      value('written in the code'),
    ]) {
      expect(brokenRules(changed(COPIED_KEY, change))).toEqual(['no-secret-literals', 'vault-secrets']);
    }
    // The secondary key, or any other property of the list: still copied from our service, but not the one named.
    expect(brokenRules(changed(COPIED_KEY, value(listed.replace('.primaryKey]', '.secondaryKey]'))))).toEqual([
      'no-secret-literals',
      'vault-secrets',
    ]);
    // A copy of the email key standing in for another secret: a value that isn't its own, whatever its condition.
    expect(brokenRules(changed(SECRET('db-app-password'), value(listed)))).toEqual(['no-secret-literals']);
    expect(
      brokenRules(
        changed(SECRET('db-app-password'), (secret) => {
          value(listed)(secret);
          delete secret.condition;
        }),
      ),
    ).toEqual(['no-secret-literals', 'vault-secrets']);
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
    // B5-3: a key copied from a service on every run, on no condition; `vault-secrets` holds which service.
    const copied = { ...secret, properties: { value: "[listKeys('communication', '2026-03-18').primaryKey]" } };
    expect(templateProblems('t.bicep', { resources: [copied] })).toEqual([]);
    expect(templateProblems('t.bicep', { resources: [{ ...copied, condition: '[true()]' }] })).toHaveLength(1);
    expect(
      templateProblems('t.bicep', { resources: [{ ...copied, '@options': { onlyIfNotExists: [] } }] }),
    ).toHaveLength(1);
    for (const value of ["[listKeys('communication', '2026-03-18')]", "x[listKeys('c', 'v').primaryKey]"]) {
      expect(templateProblems('t.bicep', { resources: [{ ...copied, properties: { value } }] })).toHaveLength(1);
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
    const principal = (workload: string): string => {
      const id = staging.predictedResources.find(named(new RegExp('^id-agentx-stg-' + workload + '$')))?.id;
      return `[reference('${String(id)}', '2024-11-30').principalId]`;
    };
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

  it('SEC-OPS-12 jobs: one that starts itself, runs twice at once, retries, or runs an image a tag could move', () => {
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
    // Azure itself refuses a job that starts itself or runs two replicas a run (AZ2, `azure-policy`).
    const refused = ['azure-policy', 'jobs'];
    for (const [start, rules] of [
      [{ triggerType: 'Schedule' }, refused],
      [{ scheduleTriggerConfig: { cronExpression: '0 3 * * *' } }, ['jobs']],
      [{ eventTriggerConfig: { scale: {} } }, ['jobs']],
      [{ replicaRetryLimit: 1 }, ['jobs']],
      [{ replicaTimeout: 0 }, ['jobs']],
      [{ replicaTimeout: 4000 }, ['jobs']],
      [{ replicaTimeout: 'soon' }, ['jobs']],
      [{ manualTriggerConfig: { parallelism: 2, replicaCompletionCount: 1 } }, refused],
      [{ manualTriggerConfig: { parallelism: 1, replicaCompletionCount: 2 } }, refused],
    ] as const) {
      expect({
        start,
        rules: brokenRules(
          changed(JOB('db-setup'), (job) => {
            Object.assign(configurationOf(job), start);
          }),
        ),
      }).toEqual({ start, rules });
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
    ).toEqual(refused);
    // A job the deployment needs, left out. CI's role would then be given on
    // a migration job this deployment doesn't make, and the owner-login alert
    // would pair logins with its starts.
    for (const workload of ['db-setup', 'migrate', 'zitadel-init', 'zitadel-setup', 'operator', 'chain-restore']) {
      expect({ workload, rules: brokenRules(without(JOB(workload))) }).toEqual({
        workload,
        // The operator or the chain repair gone, the anchors' epoch is set by fewer than all three (anchor-epoch).
        rules: {
          migrate: ['owner-login-alert', 'release-access', 'release-writes-alert', 'jobs'],
          operator: ['anchor-epoch', 'jobs'],
          'chain-restore': ['anchor-epoch', 'jobs'],
        }[workload] ?? ['jobs'],
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
    // Azure itself refuses both too (AZ2, `azure-policy`).
    expect(brokenRules(changed(APP('api'), (app) => (ingressOf(app).external = true)))).toEqual([
      'azure-policy',
      'apps',
    ]);
    expect(brokenRules(changed(APP('zitadel'), (app) => (ingressOf(app).allowInsecure = true)))).toEqual([
      'azure-policy',
      'apps',
    ]);
    // An ingress left out entirely is one Azure decides, not us.
    expect(
      brokenRules(
        changed(APP('login'), (app) => {
          delete inside(app, 'properties', 'configuration').ingress;
        }),
      ),
    ).toEqual(['apps']);
    // The API holding the jobs, given a second copy; staging's Zitadel given a second, whose ten more
    // connections its server has no room for either (SA3a).
    expect(brokenRules(changed(APP('api'), (app) => (scaleOf(app).maxReplicas = 2)))).toEqual(['apps']);
    expect(brokenRules(changed(APP('zitadel'), (app) => (scaleOf(app).maxReplicas = 2)))).toEqual([
      'apps',
      'connections',
    ]);
    // An app that may run no replica at all, and one holding more than it may run.
    // A count that is no number of replicas Azure itself refuses too (AZ2, `azure-policy`).
    for (const [scale, rules] of [
      [{ maxReplicas: 0 }, ['apps']],
      [{ maxReplicas: 'one' }, ['azure-policy', 'apps']],
      [{ minReplicas: -1 }, ['apps']],
      [{ minReplicas: 2 }, ['apps']],
    ] as const) {
      expect({
        scale,
        rules: brokenRules(changed(APP('login'), (app) => Object.assign(scaleOf(app), scale))),
      }).toEqual({ scale, rules });
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
      'azure-policy',
      'apps',
    ]);
    // An app the deployment needs, left out. Zitadel's own secrets are then
    // read by nothing, and the login pages have nothing to sign a call to. A
    // door would reach an app this deployment doesn't make, and so would CI's role.
    // Without the API, Zitadel has nowhere to ask for its machine IDs (SA3e).
    for (const workload of ['api', 'login', 'zitadel']) {
      expect({ workload, rules: brokenRules(without(APP(workload))) }).toEqual({
        workload,
        rules:
          workload === 'api'
            ? ['anchor-epoch', 'release-access', 'release-writes-alert', 'apps', 'public-doors', 'zitadel-machine-ids']
            : ['apps', 'public-doors'],
      });
    }
  });

  it('apps: the API scaled other than its role says (4D2e D12)', () => {
    const asRole = (settings: Record<string, string>, scale: Record<string, number>) => (app: Mutable) => {
      settingsOf(app).push(...Object.entries(settings).map(([name, value]) => ({ name, value })));
      Object.assign(scaleOf(app), scale);
    };
    // The app's own problems: a lone `web` app is also the deployment's (no app holds the jobs), tested below.
    const appProblems = (snapshotted: Snapshot): string[] =>
      policyProblems(snapshotted, STAGING)
        .filter(({ rule, resource }) => rule === 'apps' && resource !== 'the deployment')
        .map(({ message }) => message);
    const web = { AGENTX_ROLE: 'web', AGENTX_WEB_COPIES: '3' };
    expect(appProblems(changed(APP('api'), asRole(web, { minReplicas: 3, maxReplicas: 3 })))).toEqual([]);
    expect(appProblems(changed(APP('api'), asRole(web, { minReplicas: 2, maxReplicas: 3 })))).toEqual([
      'must run exactly 3 (minReplicas and maxReplicas 3): AGENTX_WEB_COPIES, which each copy shares its rate limits by; it says 2 to 3',
    ]);
    expect(appProblems(changed(APP('api'), asRole(web, { minReplicas: 4, maxReplicas: 4 })))).toHaveLength(1);
    // One copy where none is said.
    const oneWeb = asRole({ AGENTX_ROLE: 'web' }, { minReplicas: 1, maxReplicas: 1 });
    expect(appProblems(changed(APP('api'), oneWeb))).toEqual([]);
    // The jobs app (4D2e D13): the API's own copy at `jobs`, renamed, with no ingress.
    const asJobs = (scale: Record<string, number>) => (app: Mutable) => {
      app.name = 'ca-agentx-stg-jobs';
      delete inside(app, 'properties', 'configuration').ingress;
      asRole({ AGENTX_ROLE: 'jobs' }, scale)(app);
    };
    expect(appProblems(changed(APP('api'), asJobs({ minReplicas: 1, maxReplicas: 1 })))).toEqual([]);
    const exactlyOne = (scale: { minReplicas: number; maxReplicas: number }): string =>
      `must run exactly 1 (minReplicas and maxReplicas 1): the jobs keep to one copy, which the lease alone doesn't make safe for the copier; it says ${String(scale.minReplicas)} to ${String(scale.maxReplicas)}`;
    expect(appProblems(changed(APP('api'), asJobs({ minReplicas: 0, maxReplicas: 1 })))).toEqual([
      exactlyOne({ minReplicas: 0, maxReplicas: 1 }),
    ]);
    // Past one, the jobs app is ONE_REPLICA's too.
    expect(appProblems(changed(APP('api'), asJobs({ minReplicas: 1, maxReplicas: 2 })))).toEqual([
      "must run at most one replica (maxReplicas 1): the API's jobs keep to one copy, which the lease alone doesn't make safe for the copier; it says 2",
      exactlyOne({ minReplicas: 1, maxReplicas: 2 }),
    ]);
    // `all`, said or not, holds the jobs: at most one, and none while staging sleeps.
    expect(
      appProblems(changed(APP('api'), asRole({ AGENTX_ROLE: 'all' }, { minReplicas: 0, maxReplicas: 1 }))),
    ).toEqual([]);
    expect(appProblems(changed(APP('api'), asRole({}, { maxReplicas: 2 })))).toEqual([
      'must run at most one replica (maxReplicas 1): AGENTX_ROLE all holds the jobs; it says 2',
    ]);
    expect(appProblems(changed(APP('api'), asRole({ AGENTX_ROLE: 'worker' }, {})))).toEqual([
      "sets AGENTX_ROLE to worker, which the API doesn't take: all, web or jobs",
    ]);
    // Copies that can't be read hold the replicas to nothing.
    expect(
      appProblems(changed(APP('api'), asRole({ AGENTX_ROLE: 'web', AGENTX_WEB_COPIES: 'three' }, { maxReplicas: 1 }))),
    ).toEqual(['must give AGENTX_WEB_COPIES as a whole number, which its replicas are held to']);
  });

  it('apps: across the API apps, one unnamed, none or two holding the jobs, or all beside web (4D2e D12)', () => {
    const deploymentProblems = (snapshotted: Snapshot): string[] =>
      policyProblems(snapshotted, STAGING)
        .filter(({ rule }) => rule === 'apps')
        .map(({ resource, message }) => `${resource}: ${message}`);
    const role = (value: string) => (app: Mutable) => {
      settingsOf(app).push({ name: 'AGENTX_ROLE', value });
    };
    /** Staging with a second API app beside its own, named for `workload`, in `role`: at `jobs`, with no ingress. */
    const beside = (workload: string, value: string, from: Snapshot = staging): Snapshot => {
      const second = structuredClone(from.predictedResources.find(APP('api'))) as unknown as Mutable;
      second.name = `ca-agentx-stg-${workload}`;
      if (value === 'jobs') delete inside(second, 'properties', 'configuration').ingress;
      role(value)(second);
      Object.assign(scaleOf(second), { minReplicas: 1, maxReplicas: 1 });
      return { ...from, predictedResources: [...from.predictedResources, second as unknown as PredictedResource] };
    };
    expect(deploymentProblems(staging)).toEqual([]);
    // The split D13 makes: web beside jobs.
    const webbed = changed(APP('api'), (app) => {
      role('web')(app);
      Object.assign(scaleOf(app), { minReplicas: 1, maxReplicas: 1 });
    });
    expect(deploymentProblems(beside('jobs', 'jobs', webbed))).toEqual([]);
    expect(deploymentProblems(webbed)).toEqual([
      'the deployment: needs exactly one app holding the jobs (AGENTX_ROLE jobs or all); it has 0',
    ]);
    expect(deploymentProblems(beside('jobs', 'jobs'))).toEqual([
      'the deployment: needs exactly one app holding the jobs (AGENTX_ROLE jobs or all); it has 2',
    ]);
    expect(deploymentProblems(beside('jobs', 'web'))).toEqual([
      'the deployment: runs AGENTX_ROLE all beside web: all counts its rate limits as the only copy',
      'ca-agentx-stg-jobs: runs AGENTX_ROLE web: the jobs app runs AGENTX_ROLE jobs, and only it, as the one with no ingress',
    ]);
    expect(deploymentProblems(beside('worker', 'jobs', webbed))).toEqual([
      'ca-agentx-stg-worker: runs the API, which only api and jobs may: an app nothing names could hold the jobs',
      'ca-agentx-stg-worker: runs AGENTX_ROLE jobs: the jobs app runs AGENTX_ROLE jobs, and only it, as the one with no ingress',
    ]);
    // Each at its own role (4D2e D13): the API, which the doors reach, never at `jobs`; the jobs app never `all`.
    const apiAtJobs = changed(APP('api'), (app) => {
      role('jobs')(app);
      Object.assign(scaleOf(app), { minReplicas: 1, maxReplicas: 1 });
    });
    expect(deploymentProblems(apiAtJobs)).toEqual([
      'ca-agentx-stg-api: must have no ingress: AGENTX_ROLE jobs serves nothing, so neither a door nor a neighbour may reach it',
      'ca-agentx-stg-api: runs AGENTX_ROLE jobs: the jobs app runs AGENTX_ROLE jobs, and only it, as the one with no ingress',
    ]);
    const allJobs = beside('jobs', 'all', webbed);
    expect(deploymentProblems(allJobs)).toContain(
      'ca-agentx-stg-jobs: runs AGENTX_ROLE all: the jobs app runs AGENTX_ROLE jobs, and only it, as the one with no ingress',
    );
  });

  it("apps.bicep reads the jobs app's identity only where the API is split, so a plain apps before the foundation works (4D2e D13)", () => {
    const template = bicepFile('apps.bicep').template;
    // A condition on the existing node: ARM never reads it, and drops what depends on it, when there is no jobs app.
    expect(at(template, 'resources', 'jobsIdentity')).toMatchObject({
      condition: "[variables('split')]",
      existing: true,
    });
    // Stage G's copy's anchors role (4D2e) reads it only on the copy's run, a load run, so always split.
    expect(at(template, 'resources', 'throwawayAnchorsKept', 'condition')).toBe("[variables('throwaway')]");
    expect(at(template, 'variables', 'throwaway')).toMatch(/^\[and\(parameters\('loadRun'\), /);
    expect(at(template, 'variables', 'split')).toMatch(/^\[or\(parameters\('loadRun'\), /);
    // Every other read of it sits in the branch for the jobs app alone, which ARM's if() evaluates only when taken.
    const { throwawayAnchorsKept: _onTheCopy, ...others } = at(template, 'resources') as Record<string, unknown>;
    const compiled = JSON.stringify({ ...(template as Record<string, unknown>), resources: others });
    const reads = [...compiled.matchAll(/reference\('jobsIdentity'\)/g)].map((match) => match.index);
    expect(reads.length).toBeGreaterThan(0);
    const branch = "if(equals(variables('apps')[copyIndex()].workload, 'jobs'), createArray(";
    for (const index of reads) {
      const before = compiled.slice(0, index);
      expect(before.lastIndexOf(branch)).toBeGreaterThan(-1);
      expect(index - before.lastIndexOf(branch)).toBeLessThan(400);
    }
  });

  it('apps: the jobs app reachable, or production not split (4D2e D13)', () => {
    const production = { region: 'uaenorth', environment: 'production' } as const;
    const appsProblems = (snapshotted: Snapshot, expected: Expectations = production): string[] =>
      policyProblems(snapshotted, expected)
        .filter(({ rule }) => rule === 'apps')
        .map(({ resource, message }) => `${resource}: ${message}`);
    const split = productionLike({ subject: true });
    expect(appsProblems(split)).toEqual([]);
    expect(at(split.predictedResources.find(APP('jobs'))?.properties, 'configuration', 'ingress')).toBeUndefined();
    const noIngress =
      'ca-agentx-stg-jobs: must have no ingress: AGENTX_ROLE jobs serves nothing, so neither a door nor a neighbour may reach it';
    // An ingress of any kind, internal and refusing plain http among them, or one said as nothing at all is fine.
    const withIngress = (ingress: unknown) =>
      changed(
        APP('jobs'),
        (app) => {
          inside(app, 'properties', 'configuration').ingress = ingress;
        },
        split,
      );
    expect(
      appsProblems(
        withIngress(at(staging.predictedResources.find(APP('api'))?.properties, 'configuration', 'ingress')),
      ),
    ).toEqual([noIngress]);
    expect(appsProblems(withIngress({}))).toEqual([noIngress]);
    expect(appsProblems(withIngress(null))).toEqual([]);
    // Production's API at `all`, as staging's is out of a load run.
    // (Its API alone: production's two Zitadel copies are production's, SA3a.)
    // splitTheApi changes what it is given, so a copy of staging's, never staging's itself.
    expect(appsProblems(splitTheApi(structuredClone(staging)), STAGING)).toEqual([]);
    const unsplit = {
      ...staging,
      predictedResources: staging.predictedResources.map((resource) =>
        resource.tags === undefined ? resource : { ...resource, tags: { ...resource.tags, environment: 'production' } },
      ),
    };
    // Staging's shape as production's: its one copy of Zitadel and of its login pages, asleep, are each short of
    // production's two too (SA3a, SA3c).
    expect(appsProblems(unsplit)).toEqual([
      'ca-agentx-stg-zitadel: must keep at least 2 replicas running (minReplicas 2): sign-in must not hang on one copy; it says 0',
      'ca-agentx-stg-login: must keep at least 2 replicas running (minReplicas 2): sign-in must not hang on one copy; it says 0',
      'the deployment: must run the API split in production, web copies beside the jobs app (4D2e D13), whose identity alone keeps the anchors there',
    ]);
  });

  it("apps: the API's heap not set by its command, or outside half to three quarters of its memory (4D2e D12)", () => {
    const heapProblems = (snapshotted: Snapshot): string[] =>
      policyProblems(snapshotted, STAGING)
        .filter(({ rule, message }) => rule === 'apps' && message.includes('max-old-space-size'))
        .map(({ message }) => message);
    const api = staging.predictedResources.find(APP('api'));
    expect(at(containerOf(api as unknown as Mutable), 'command')).toEqual([
      'node',
      '--max-old-space-size=768',
      'apps/api/src/main.ts',
    ]);
    expect(heapProblems(staging)).toEqual([]);
    const commanded = (command: readonly string[], memory = '1Gi') =>
      changed(APP('api'), (app) => {
        containerOf(app).command = [...command];
        inside(containerOf(app), 'resources').memory = memory;
      });
    expect(heapProblems(commanded(['node', '--max-old-space-size=512', 'apps/api/src/main.ts']))).toEqual([]);
    expect(heapProblems(commanded(['node', '--max-old-space-size=1536', 'x'], '2Gi'))).toEqual([]);
    for (const [command, memory] of [
      [['node', 'apps/api/src/main.ts'], '1Gi'],
      [['node', '--max-old-space-size=511', 'apps/api/src/main.ts'], '1Gi'],
      [['node', '--max-old-space-size=769', 'apps/api/src/main.ts'], '1Gi'],
      [['node', '--max-old-space-size=lots', 'apps/api/src/main.ts'], '1Gi'],
      [['node', '--max-old-space-size=768', 'apps/api/src/main.ts'], '1G'],
    ] as const) {
      expect({ command, memory, problems: heapProblems(commanded(command, memory)) }).toEqual({
        command,
        memory,
        problems: [expect.stringMatching(/^must start node with --max-old-space-size=<MiB> between half and three/)],
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
    // The auth door (SA1): the debug pages and the login pages, then an
    // allow-list of what a browser needs from Zitadel, then the API, which answers 404 on that host.
    const authLines = [
      'prefix "/debug" in any case to api',
      'prefix "/ui/v2/login" to login',
      'prefix "/.well-known/" to zitadel',
      'prefix "/oauth/v2/" to zitadel',
      'prefix "/oidc/v1/" to zitadel',
      'prefix "/ui/console" to zitadel',
      'prefix "/ui/login" to zitadel',
      'prefix "/assets/v1/" to zitadel',
      'prefix "/zitadel.admin.v1.AdminService/" to zitadel',
      'prefix "/zitadel.management.v1.ManagementService/" to zitadel',
      'prefix "/zitadel.auth.v1.AuthService/" to zitadel',
      'prefix "/zitadel.user.v2.UserService/" to zitadel',
      'prefix "/zitadel.session.v2.SessionService/" to zitadel',
      'prefix "/zitadel.feature.v2.FeatureService/" to zitadel',
      'prefix "/zitadel.action.v2.ActionService/" to zitadel',
      'prefix "/zitadel.webkey.v2.WebKeyService/" to zitadel',
      'prefix "/zitadel.org.v2.OrganizationService/" to zitadel',
      'prefix "/zitadel.authorization.v2.AuthorizationService/" to zitadel',
      'prefix "/zitadel.application.v2.ApplicationService/" to zitadel',
      'prefix "/" to api',
    ];
    const listed = { app: 'prefix "/" to api', auth: authLines.join('; ') };
    // The auth door's lines with some changed: line index to its new text, or undefined to drop it.
    const authWith = (changes: Readonly<Record<number, string | undefined>>, extra: readonly string[] = []): string =>
      [
        ...authLines.flatMap((line, index) => {
          if (!(index in changes)) return [line];
          const changed = changes[index];
          return changed === undefined ? [] : [changed];
        }),
        ...extra,
      ].join('; ');
    const routed = (name: string, lines: string): string =>
      `${name}: must route exactly as PUBLIC_DOORS says, in order: ${name === app ? listed.app : listed.auth}. It routes: ${lines}`;
    const rulesOf = (door: Mutable): Mutable[] => at(door, 'properties', 'rules') as Mutable[];
    const routeOf = (door: Mutable, index = 0): Mutable => first(nth(rulesOf(door), index).routes);
    const targetOf = (door: Mutable, index = 0): Mutable => first(nth(rulesOf(door), index).targets);
    const authRouting = (change: (door: Mutable) => void): string[] => doorProblems(changed(AUTH_DOOR, change));
    const appRouting = (change: (door: Mutable) => void): string[] => doorProblems(changed(APP_DOOR, change));
    // The rules backwards: `/` first, where the API would take every sign-in.
    expect(authRouting((door) => rulesOf(door).reverse())).toEqual([routed(auth, [...authLines].reverse().join('; '))]);
    // An allowed path moved after `/`, where it never matches.
    expect(authRouting((door) => rulesOf(door).push(...rulesOf(door).splice(2, 1)))).toEqual([
      routed(auth, authWith({ 2: undefined }, [authLines[2] ?? ''])),
    ]);
    // The debug pages matched in one case only, or with case left to Azure; `/` in any case.
    expect(authRouting((door) => (inside(routeOf(door), 'match').caseSensitive = true))).toEqual([
      routed(auth, authWith({ 0: 'prefix "/debug" to api' })),
    ]);
    expect(authRouting((door) => delete inside(routeOf(door), 'match').caseSensitive)).toEqual([
      routed(auth, authWith({ 0: 'prefix "/debug" with case left to Azure to api' })),
    ]);
    // An allowed prefix in any case, or with case left to Azure: wider than the one path Zitadel serves.
    expect(authRouting((door) => (inside(routeOf(door, 8), 'match').caseSensitive = false))).toEqual([
      routed(auth, authWith({ 8: 'prefix "/zitadel.admin.v1.AdminService/" in any case to zitadel' })),
    ]);
    expect(authRouting((door) => delete inside(routeOf(door, 3), 'match').caseSensitive)).toEqual([
      routed(auth, authWith({ 3: 'prefix "/oauth/v2/" with case left to Azure to zitadel' })),
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
      routed(auth, authWith({ 0: 'prefix "/debug" in any case to zitadel' })),
    ]);
    // The deny-list again: every path no rule allows sent to Zitadel, not the API.
    expect(authRouting((door) => (targetOf(door, -1).containerApp = 'ca-agentx-stg-zitadel'))).toEqual([
      routed(auth, authWith({ 19: 'prefix "/" to zitadel' })),
    ]);
    // An allowed path sent to the API instead, and one dropped: the console breaks, so neither passes either.
    expect(authRouting((door) => (targetOf(door, 4).containerApp = 'ca-agentx-stg-api'))).toEqual([
      routed(auth, authWith({ 4: 'prefix "/oidc/v1/" to api' })),
    ]);
    expect(authRouting((door) => rulesOf(door).splice(12, 1))).toEqual([routed(auth, authWith({ 12: undefined }))]);
    // Zitadel's system API, an instance service or a REST gateway let through
    // before `/`, or an allowed service widened to every `zitadel.` service.
    const systemRule =
      (prefix: string): ((door: Mutable) => void) =>
      (door) => {
        const rule = structuredClone(nth(rulesOf(door), 2));
        inside(first(rule.routes), 'match').prefix = prefix;
        rulesOf(door).splice(-1, 0, rule);
      };
    for (const prefix of [
      '/zitadel.system.v1.SystemService/',
      '/zitadel.instance.v2.InstanceService/',
      '/system/v1/',
    ]) {
      expect(authRouting(systemRule(prefix))).toEqual([
        routed(auth, authWith({ 19: undefined }, [`prefix "${prefix}" to zitadel`, 'prefix "/" to api'])),
      ]);
    }
    expect(authRouting((door) => (inside(routeOf(door, 8), 'match').prefix = '/zitadel.'))).toEqual([
      routed(auth, authWith({ 8: 'prefix "/zitadel." to zitadel' })),
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
      routed(auth, authWith({ 2: 'prefix "/.well-known/" to zitadel pinned to label "blue"' })),
    ]);
    // A second target on a rule, a rule too many, and no rules at all.
    expect(
      appRouting((door) => (first(rulesOf(door)).targets as Mutable[]).push({ containerApp: 'ca-agentx-stg-login' })),
    ).toEqual([routed(app, 'prefix "/" to api; prefix "/" to login')]);
    expect(authRouting((door) => rulesOf(door).push(structuredClone(first(rulesOf(door)))))).toEqual([
      routed(auth, authWith({}, ['prefix "/debug" in any case to api'])),
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

  it("workload-secrets: the owner's login held by the chain repair (4D2e E10) but never the operator's job, and the repair never given the operator's key", () => {
    const vault = staging.predictedResources.find(VAULT);
    const messages = (snapshotted: Snapshot): string[] => policyProblems(snapshotted, STAGING).map(describeProblem);
    const mounted = (job: Mutable, secret: string, from: string): void => {
      declaredSecrets(job).push({
        ...structuredClone(secretNamed(job, from)),
        name: secret,
        keyVaultUrl: `[uri(reference('${String(vault?.id)}', '2025-05-01').vaultUri, 'secrets/${secret}')]`,
      });
      (at(first(at(job, 'properties', 'template', 'volumes')), 'secrets') as Mutable[]).push({
        secretRef: secret,
        path: secret,
      });
    };
    const restorer = staging.predictedResources.find(JOB('chain-restore')) as unknown as Mutable;
    expect(declaredSecrets(restorer).map((secret) => secret.name)).toEqual([
      'db-owner-password',
      ...APP_KEYS.filter((key) => key.startsWith('key-audit-mac-v')),
      'public-audit-rebase-v1',
      'public-operator-signing-v1',
      'chain-restore-request',
    ]);
    expect(
      messages(
        changed(JOB('operator'), (job) => {
          mounted(job, 'db-owner-password', 'db-operator-password');
        }),
      ),
    ).toEqual([
      "job-agentx-stg-operator [workload-secrets] is given db-owner-password, which GRANTS doesn't let operator read",
    ]);
    expect(
      messages(
        changed(JOB('chain-restore'), (job) => {
          mounted(job, 'key-operator-signing-v1', 'db-owner-password');
        }),
      ),
    ).toEqual([
      "job-agentx-stg-chain-restore [workload-secrets] is given key-operator-signing-v1, which GRANTS doesn't let chain-restore read",
    ]);
    expect(
      messages(
        changed(JOB('chain-restore'), (job) => {
          mounted(job, 'db-app-password', 'db-owner-password');
        }),
      ),
    ).toEqual([
      "job-agentx-stg-chain-restore [workload-secrets] is given db-app-password, which GRANTS doesn't let chain-restore read",
    ]);
  });

  it('workload-secrets: our login IDs reach the API only from the vault, never as a value in the deployment (SA2b)', () => {
    // As staging deploys it: both lists mounted from the vault, by the _FILE settings alone.
    const api = staging.predictedResources.find(APP('api'));
    expect(JSON.stringify(api)).toContain('AGENTX_IDP_OUR_ACTORS_FILE');
    expect(JSON.stringify(api)).toContain('AGENTX_IDP_OUR_SERVICE_USERS_FILE');
    for (const name of ['AGENTX_IDP_OUR_ACTORS', 'AGENTX_IDP_OUR_SERVICE_USERS']) {
      const literal = changed(APP('api'), (app) => {
        setSetting(app, name, '900000000000000001');
      });
      expect(brokenRules(literal)).toEqual(['workload-secrets']);
      expect(policyProblems(literal, STAGING).map(describeProblem)).toEqual([
        `ca-agentx-stg-api [workload-secrets] sets ${name} in the deployment, where anyone reading it sees it; mount it from the vault as ${name}_FILE`,
      ]);
    }
    const setsOurs = (resource: string): string =>
      `${resource} [workload-secrets] sets AGENTX_IDP_OUR_ACTORS in the deployment, where anyone reading it sees it; mount it from the vault as AGENTX_IDP_OUR_ACTORS_FILE`;
    // The API's jobs app, where the API is split (4D2e D13), and any job.
    const split = splitTheApi(structuredClone(staging));
    const onJobsApp = changed(
      APP('jobs'),
      (app) => {
        setSetting(app, 'AGENTX_IDP_OUR_ACTORS', '900000000000000001');
      },
      split,
    );
    // Only what workload-secrets says: the split alone leaves other rules to weigh (the anchors' role), not this one.
    const secretsSaid = (snapshotted: Snapshot): string[] =>
      policyProblems(snapshotted, STAGING)
        .filter(({ rule }) => rule === 'workload-secrets')
        .map(describeProblem);
    expect(secretsSaid(split)).toEqual([]);
    expect(secretsSaid(onJobsApp)).toEqual([setsOurs('ca-agentx-stg-jobs')]);
    const onJob = changed(JOB('migrate'), (job) => {
      setSetting(job, 'AGENTX_IDP_OUR_ACTORS', '900000000000000001');
    });
    expect(policyProblems(onJob, STAGING).map(describeProblem)).toEqual([setsOurs('job-agentx-stg-migrate')]);
    // From a secret in the environment rather than a value: refused all the same, the file form alone.
    const fromSecret = changed(APP('api'), (app) => {
      settingsOf(app).push({ name: 'AGENTX_IDP_OUR_ACTORS', secretRef: 'zitadel-our-actors' });
    });
    expect(brokenRules(fromSecret)).toEqual(['workload-secrets']);
    expect(policyProblems(fromSecret, STAGING).map(describeProblem)).toContain(setsOurs('ca-agentx-stg-api'));
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
      'job-agentx-stg-operator [no-secret-literals] configuration.secrets[5].value must come from a @secure() parameter, never a value in the code',
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
    // A request in the job's own command or arguments, in place of the file or after it, the file alone with
    // its flag lost, or a word moved from one to the other.
    const runAs =
      "job-agentx-stg-operator [workload-secrets] must run node apps/operator/src/main.ts --request /mnt/secrets/operator-request and nothing else: a request in its command or arguments would sit in the deployment and every run's record";
    const script = 'apps/operator/src/main.ts';
    for (const [command, args] of [
      [
        ['node', script],
        ['create-organization', '--name', 'Quartzite Other Co'],
      ],
      [
        ['node', script],
        ['--request', '/mnt/secrets/operator-request', 'create-organization'],
      ],
      [['node', script], ['/mnt/secrets/operator-request']],
      [['node', script], []],
      [['node', script, 'create-organization', '--name', 'Quartzite Other Co'], []],
      // The arguments as they should be, the command not.
      [
        ['node', script, 'create-organization', '--name', 'Quartzite Other Co', '--'],
        ['--request', '/mnt/secrets/operator-request'],
      ],
      [
        ['sh', '-c', `node ${script} create-organization --name "Quartzite Other Co" #`],
        ['--request', '/mnt/secrets/operator-request'],
      ],
      [[], ['--request', '/mnt/secrets/operator-request']],
      [['sh', '-c', `node ${script} create-organization --name "Quartzite Other Co"`], []],
      [['node'], [script, '--request', '/mnt/secrets/operator-request']],
      [['node', script, '--request'], ['/mnt/secrets/operator-request']],
    ]) {
      expect({
        command,
        args,
        problems: messages(
          changed(operator, (job) => {
            containerOf(job).command = command;
            containerOf(job).args = args;
          }),
        ),
      }).toEqual({ command, args, problems: [runAs] });
    }
  });

  it("zitadel-machine-ids: a Zitadel process's machine ID by its hostname, or asked anywhere but the API's internal host", () => {
    const MACHINE = 'ZITADEL_MACHINE_IDENTIFICATION_';
    const set = (entries: Mutable[], name: string, value: string): Mutable[] => [
      ...entries.filter((entry) => entry.name !== name),
      { name, value },
    ];
    for (const workload of ['zitadel-init', 'zitadel-setup', 'zitadel']) {
      const pick = workload === 'zitadel' ? APP(workload) : JOB(workload);
      const broken = (change: (entries: Mutable[]) => Mutable[]): RuleId[] =>
        brokenRules(
          changed(pick, (resource) => {
            containerOf(resource).env = change(settingsOf(resource));
          }),
        );
      // S19's hostname mode, which two copies can collide in; and with the webhook still on, since hostname is tried first.
      expect({ workload, rules: broken((env) => set(env, `${MACHINE}HOSTNAME_ENABLED`, 'true')) }).toEqual({
        workload,
        rules: ['zitadel-machine-ids'],
      });
      expect({ workload, rules: broken((env) => set(env, `${MACHINE}PRIVATEIP_ENABLED`, 'true')) }).toEqual({
        workload,
        rules: ['zitadel-machine-ids'],
      });
      expect({ workload, rules: broken((env) => set(env, `${MACHINE}WEBHOOK_ENABLED`, 'false')) }).toEqual({
        workload,
        rules: ['zitadel-machine-ids'],
      });
      // Left to the image's defaults: private address on, then Google Cloud's metadata server.
      expect({
        workload,
        rules: broken((env) => env.filter((entry) => !String(entry.name).startsWith(MACHINE))),
      }).toEqual({ workload, rules: ['zitadel-machine-ids'] });
      for (const url of [
        'http://metadata.google.internal/computeMetadata/v1/instance/id',
        'https://app.example.invalid/internal/zitadel-machine-id',
        "[format('https://{0}/internal/zitadel-machine-id', format('{0}.internal.{1}', 'ca-agentx-stg-login', reference('/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-agentx-staging/providers/Microsoft.App/managedEnvironments/cae-agentx-staging', '2026-01-01').defaultDomain))]",
      ]) {
        expect({ workload, url, rules: broken((env) => set(env, `${MACHINE}WEBHOOK_URL`, url)) }).toEqual({
          workload,
          url,
          rules: ['zitadel-machine-ids'],
        });
      }
      expect({ workload, rules: broken((env) => set(env, `${MACHINE}WEBHOOK_JPATH`, '$.machine')) }).toEqual({
        workload,
        rules: ['zitadel-machine-ids'],
      });
    }
    // The API not handing them out on its internal host: every Zitadel process would ask in vain, and panic.
    for (const value of [undefined, 'app.example.invalid']) {
      expect({
        value,
        rules: brokenRules(
          changed(APP('api'), (app) => {
            const kept = settingsOf(app).filter((entry) => entry.name !== 'AGENTX_MACHINE_IDS_HOST');
            containerOf(app).env = value === undefined ? kept : [...kept, { name: 'AGENTX_MACHINE_IDS_HOST', value }];
          }),
        ),
      }).toEqual({ value, rules: ['zitadel-machine-ids'] });
    }
    // The API and every Zitadel process agreeing on a host that isn't the API's own internal name in this
    // environment: another app's (the login pages', which would 404 every ask), or another environment's.
    const MACHINE_SETTINGS = new Set(['AGENTX_MACHINE_IDS_HOST', 'ZITADEL_MACHINE_IDENTIFICATION_WEBHOOK_URL']);
    const asksAndAnswers = (resource: PredictedResource): boolean =>
      ['api', 'zitadel'].some((workload) => APP(workload)(resource)) ||
      ['zitadel-init', 'zitadel-setup'].some((workload) => JOB(workload)(resource));
    for (const [from, to] of [
      ["'ca-agentx-stg-api'", "'ca-agentx-stg-login'"],
      ['/managedEnvironments/cae-agentx-staging', '/managedEnvironments/cae-agentx-elsewhere'],
    ] as const) {
      expect({
        to,
        rules: brokenRules(
          changed(asksAndAnswers, (resource) => {
            containerOf(resource).env = settingsOf(resource).map((entry) =>
              MACHINE_SETTINGS.has(String(entry.name))
                ? { ...entry, value: String(entry.value).replace(from, to) }
                : entry,
            );
          }),
        ),
      }).toEqual({ to, rules: ['zitadel-machine-ids'] });
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

  it("platform-settings: a container setting one of Azure's own variables, the run's name above all (B1c-2b)", () => {
    const sets = (pick: (resource: PredictedResource) => boolean, name: string) =>
      brokenRules(
        changed(pick, (resource) => {
          settingsOf(resource).push({ name, value: 'job-agentx-stg-operator-7x2kq9m' });
        }),
      );
    // And where a container gets its identity's token (E10c): one set here could send the operator's request elsewhere.
    for (const name of [
      'CONTAINER_APP_JOB_EXECUTION_NAME',
      'CONTAINER_APP_NAME',
      'IDENTITY_ENDPOINT',
      'IDENTITY_HEADER',
      'MSI_ENDPOINT',
      'MSI_SECRET',
    ]) {
      expect({ name, rules: sets(JOB('operator'), name) }).toEqual({ name, rules: ['platform-settings'] });
    }
    // Any container of ours, the apps' as well as the jobs'.
    expect(sets(APP('api'), 'CONTAINER_APP_REVISION')).toEqual(['platform-settings']);
    expect(sets(JOB('migrate'), 'CONTAINER_APP_JOB_NAME')).toEqual(['platform-settings']);
    // Names that only look like one are variables of their own: a longer word, other capitals (Linux tells them apart), a word before.
    for (const name of ['CONTAINER_APPLICATION_NAME', 'container_app_job_execution_name', 'MY_CONTAINER_APP_NAME']) {
      expect({ name, rules: sets(JOB('operator'), name) }).toEqual({ name, rules: [] });
    }
    expect(
      policyProblems(
        changed(JOB('operator'), (job) => {
          settingsOf(job).push({ name: 'CONTAINER_APP_JOB_EXECUTION_NAME', value: 'job-agentx-stg-operator-7x2kq9m' });
        }),
        STAGING,
      ),
    ).toEqual([
      {
        rule: 'platform-settings',
        resource: 'job-agentx-stg-operator',
        message:
          "sets CONTAINER_APP_JOB_EXECUTION_NAME: Azure sets its CONTAINER_APP_ and identity variables in every container itself, and one set here could stand in for the platform's",
      },
    ]);
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
      AGENTX_DB_OPERATOR_PASSWORD_FILE: '/mnt/secrets/db-operator-password',
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
    // Each Zitadel process takes its machine ID from the API, in turn (SA3e): the
    // private-address default finds none on Container Apps (S19), and two hostnames'
    // hashes can collide. The API answers on its internal host alone.
    const apiHost = settingsGiven('api').AGENTX_MACHINE_IDS_HOST;
    expect(apiHost).toBe(
      "[format('{0}.internal.{1}', 'ca-agentx-stg-api', reference('/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-agentx-staging/providers/Microsoft.App/managedEnvironments/cae-agentx-staging', '2026-01-01').defaultDomain)]",
    );
    for (const workload of ['zitadel-init', 'zitadel-setup', 'zitadel']) {
      expect({ workload, settings: settingsGiven(workload) }).toMatchObject({
        workload,
        settings: {
          ZITADEL_MACHINE_IDENTIFICATION_PRIVATEIP_ENABLED: 'false',
          ZITADEL_MACHINE_IDENTIFICATION_HOSTNAME_ENABLED: 'false',
          ZITADEL_MACHINE_IDENTIFICATION_WEBHOOK_ENABLED: 'true',
          ZITADEL_MACHINE_IDENTIFICATION_WEBHOOK_URL: `[format('https://{0}/internal/zitadel-machine-id', ${String(apiHost).slice(1, -1)})]`,
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

describe('the load run (D2c, PL-38)', () => {
  /** A digest of the load image, as `apps --load-run` gives one once verify.ts has checked it. */
  const LOAD_DIGEST = `sha256:${'a'.repeat(64)}`;
  let load: EnvironmentSnapshot;

  beforeAll(() => {
    load = inCopy((dir) =>
      environmentSnapshot(dir, 'staging', {
        AGENTX_AZURE_LOAD_RUN: 'true',
        AGENTX_AZURE_LOAD_IMAGE_DIGEST: LOAD_DIGEST,
      }),
    );
  });

  /** A copy of the load run's snapshot with one change made to the resources `pick` selects. */
  const loadChanged = (pick: (resource: PredictedResource) => boolean, change: (resource: Mutable) => void): Snapshot =>
    changed(pick, change, load.together);
  const LOAD_JOBS = ['load-first', 'load-second', 'load-cleanup'];
  const found = (snapshotted: Snapshot, pick: (resource: PredictedResource) => boolean): PredictedResource => {
    const resource = snapshotted.predictedResources.find(pick);
    if (resource === undefined) throw new Error('not in the snapshot');
    return resource;
  };
  const containerIn = (resource: PredictedResource): Mutable => containerOf(resource as unknown as Mutable);
  const settingNames = (resource: PredictedResource): string[] =>
    settingsOf(resource as unknown as Mutable).map((entry) => String(entry.name));

  it('compiles: every rule holds, the API is at its load size and limits without email, split from its jobs, and the three jobs are added', () => {
    expect(policyProblems(load.together, STAGING).map(describeProblem)).toEqual([]);
    const api = found(load.together, APP('api'));
    expect(at(containerIn(api), 'resources')).toEqual({ cpu: 2, memory: '4Gi' });
    expect(settingNames(api)).toEqual(
      expect.arrayContaining([
        'AGENTX_RATE_LIMIT_PER_MINUTE',
        'AGENTX_RATE_LIMIT_PER_USER_PER_MINUTE',
        'AGENTX_RATE_LIMIT_PER_AGENT_PER_MINUTE',
        'AGENTX_RATE_LIMIT_PER_ORGANISATION_PER_MINUTE',
        'AGENTX_LOG_EVENT_CAP_PER_MINUTE',
        'AGENTX_OUTBOUND_ALLOWED_ORIGINS',
      ]),
    );
    expect(settingNames(api).filter((name) => /EMAIL|DIRECTORY/.test(name))).toEqual([]);
    const pool = (resource: PredictedResource) =>
      settingsOf(resource as unknown as Mutable).find(({ name }) => name === 'AGENTX_DB_POOL_MAX')?.value;
    expect(pool(api)).toBe('12');
    expect(pool(found(staging, APP('api')))).toBe('10');
    expect(at(containerIn(found(staging, APP('api'))), 'resources')).toEqual({ cpu: 0.5, memory: '1Gi' });
    // Split (4D2e D13): three web copies, each its third of the gate, beside the jobs app, which keeps the anchors.
    const value = (resource: PredictedResource, name: string) =>
      settingsOf(resource as unknown as Mutable).find((entry) => entry.name === name)?.value;
    expect(['AGENTX_ROLE', 'AGENTX_WEB_COPIES', 'AGENTX_DECISION_GATE_ACTIVE'].map((name) => value(api, name))).toEqual(
      ['web', '3', '11'],
    );
    expect(at(api.properties, 'template', 'scale')).toEqual({ minReplicas: 3, maxReplicas: 3 });
    expect(settingNames(api).filter((name) => name.includes('ANCHOR'))).toEqual([]);
    expect(settingNames(found(staging, APP('api')))).not.toContain('AGENTX_ROLE');
    const jobsApp = found(load.together, APP('jobs'));
    expect(Object.keys(at(jobsApp.identity, 'userAssignedIdentities') as Mutable)).toEqual([
      expect.stringMatching(/\/id-agentx-stg-jobs$/) as unknown as string,
    ]);
    expect(at(jobsApp.properties, 'configuration', 'ingress')).toBeNull();
    expect(at(jobsApp.properties, 'template', 'scale')).toEqual({ minReplicas: 1, maxReplicas: 1 });
    expect(at(containerIn(jobsApp), 'resources')).toEqual({ cpu: 1, memory: '2Gi' });
    expect(
      ['AGENTX_ROLE', 'AGENTX_DB_JOBS_POOL_MAX', 'AGENTX_LOG_EVENT_CAP_PER_MINUTE'].map((name) => value(jobsApp, name)),
    ).toEqual(['jobs', '6', '200000']);
    expect(settingNames(jobsApp)).toEqual(
      expect.arrayContaining(['AGENTX_ANCHOR_EPOCH', 'AGENTX_AUDIT_ANCHORS_URL', 'AGENTX_ACTIVITY_DOWNLOADS_URL']),
    );
    expect(settingNames(jobsApp).filter((name) => /EMAIL|DIRECTORY|HTTP_|RATE_LIMIT|DB_POOL_MAX/.test(name))).toEqual(
      [],
    );
    for (const workload of LOAD_JOBS) {
      const job = found(load.together, JOB(workload));
      expect(Object.keys(at(job.identity, 'userAssignedIdentities') as Mutable)).toEqual([
        expect.stringMatching(/\/id-agentx-stg-api'?\)?\]?$/) as unknown as string,
      ]);
      expect(at(containerIn(job), 'image')).toBe(`ghcr.io/shahbaz242630/agent-x-load@${LOAD_DIGEST}`);
    }
    expect(settingNames(found(load.together, JOB('load-first')))).toContain('AGENTX_LOAD_API');
    expect(settingNames(found(load.together, JOB('load-cleanup')))).not.toContain('AGENTX_LOAD_API');
    // Nothing else changes: the same resources, but the three jobs and the jobs app.
    const names = (snapshotted: Snapshot) => snapshotted.predictedResources.map((resource) => resource.name).sort();
    expect(names(load.together).filter((name) => !name.includes('-load-') && name !== 'ca-agentx-stg-jobs')).toEqual(
      names(staging),
    );
    expect(staging.predictedResources.filter(APPS).map((app) => app.name)).not.toContain('ca-agentx-stg-jobs');
    expect(staging.predictedResources.filter(JOBS).map((job) => job.name)).not.toContain('job-agentx-stg-load-first');
  });

  it('load-run: on production, or with a job missing or on another image', () => {
    expect(brokenRules(load.together, { region: 'uaenorth', environment: 'production' })).toContain('load-run');
    const kept = load.together.predictedResources.filter((resource) => !JOB('load-second')(resource));
    expect(brokenRules({ predictedResources: kept, diagnostics: [] })).toEqual(['load-run']);
    expect(
      brokenRules(
        loadChanged(JOB('load-first'), (job) => {
          containerOf(job).image = `ghcr.io/shahbaz242630/agent-x@${LOAD_DIGEST}`;
        }),
      ),
    ).toEqual(['load-run']);
  });

  it('load-run: the API off twelve connections a copy in a load run, or over ten on staging out of one', () => {
    const api = APP('api');
    const poolAt = (value: string) => (app: Mutable) => {
      for (const entry of settingsOf(app).filter(({ name }) => name === 'AGENTX_DB_POOL_MAX')) entry.value = value;
    };
    expect(brokenRules(loadChanged(api, poolAt('7')))).toEqual(['load-run']);
    // The pinned numbers keep the decisions' room (S177): the target at 60% or less of the copies' gates, each gate
    // under its pool, so a change to either is a change to this.
    const gate = Number(LOAD_RUN.apiSettings.AGENTX_DECISION_GATE_ACTIVE);
    expect(gateBusy(Number(LOAD_RUN.webCopies), gate)).toBeLessThanOrEqual(DECISION_HEADROOM.mostBusy);
    expect(gate).toBeLessThan(Number(LOAD_RUN.apiPool));
    expect(gateBusy(3, 9)).toBeGreaterThan(DECISION_HEADROOM.mostBusy);
    expect(brokenRules(changed(api, poolAt('11')))).toEqual(['load-run']);
    expect(brokenRules(changed(api, poolAt('10')))).toEqual([]);
    // Production's own server sizes its pool: PL-63 wants twenty or more there.
    expect(
      policyProblems(changed(api, poolAt('20')), { region: 'uaenorth', environment: 'production' }).filter(
        ({ rule, message }) => rule === 'load-run' && message.includes('connections'),
      ),
    ).toEqual([]);
  });

  it("connections: the apps' pools past the server's connections, in a load run or out of one (4D2e D12)", () => {
    const connectionProblems = (snapshotted: Snapshot): string[] =>
      policyProblems(snapshotted, STAGING)
        .filter(({ rule }) => rule === 'connections')
        .map(({ message }) => message);
    const setting = (name: string, value: string) => (app: Mutable) => {
      const entries = settingsOf(app);
      const entry = entries.find((each) => each.name === name);
      if (entry === undefined) entries.push({ name, value });
      else entry.value = value;
    };
    const api = APP('api');
    // Staging: two of the API's ten, Zitadel's ten, a job and one more are 32 of 35; eleven are 34, twelve 36.
    expect(connectionProblems(staging)).toEqual([]);
    expect(connectionProblems(changed(api, setting('AGENTX_DB_POOL_MAX', '11')))).toEqual([]);
    expect(connectionProblems(changed(api, setting('AGENTX_DB_POOL_MAX', '12')))).toEqual([
      "has 35 connections for users (max_connections 50 less Azure's 15), but the apps may hold 36: two of each API copy's pool, each Zitadel copy's, one job and one to spare",
    ]);
    // Zitadel's pool where it sets one, in place of its image's ten.
    expect(
      connectionProblems(changed(APP('zitadel'), setting('ZITADEL_DATABASE_POSTGRES_MAXOPENCONNS', '13'))),
    ).toEqual([]);
    expect(
      connectionProblems(changed(APP('zitadel'), setting('ZITADEL_DATABASE_POSTGRES_MAXOPENCONNS', '14'))),
    ).toHaveLength(1);
    // A pool that can't be read is said, never summed as nothing: given as words, or from a secret.
    for (const entry of [
      { name: 'ZITADEL_DATABASE_POSTGRES_MAXOPENCONNS', value: 'ten' },
      { name: 'ZITADEL_DATABASE_POSTGRES_MAXOPENCONNS', secretRef: 'zitadel-pool' },
    ]) {
      expect(connectionProblems(changed(APP('zitadel'), (app) => settingsOf(app).push(entry)))).toEqual([
        "ca-agentx-stg-zitadel must state ZITADEL_DATABASE_POSTGRES_MAXOPENCONNS as a whole number, or leave it to its image's 10, so its connections can be counted",
      ]);
    }
    expect(
      connectionProblems(
        changed(api, (app) => {
          setting('AGENTX_ROLE', 'web')(app);
          setting('AGENTX_WEB_COPIES', 'three')(app);
        }),
      ),
    ).toEqual(['ca-agentx-stg-api must state AGENTX_WEB_COPIES as a whole number, so its connections can be counted']);
    // An API whose pool isn't stated can't be counted.
    expect(
      connectionProblems(
        changed(api, (app) => {
          containerOf(app).env = settingsOf(app).filter(({ name }) => name !== 'AGENTX_DB_POOL_MAX');
        }),
      ),
    ).toEqual(['ca-agentx-stg-api must state AGENTX_DB_POOL_MAX as a whole number, so its connections can be counted']);
    // The load run on the larger server's 105, split as apps.bicep makes it (4D2e D13; S183): three web copies of
    // twelve and the jobs app's six are 96; four web copies, 120; the jobs' pool at ten, 104; at eleven, 106.
    expect(connectionProblems(load.together)).toEqual([]);
    const copies = (count: string) => (app: Mutable) => {
      setting('AGENTX_WEB_COPIES', count)(app);
      Object.assign(scaleOf(app), { minReplicas: Number(count), maxReplicas: Number(count) });
    };
    const over = (holds: number) =>
      `has 105 connections for users (max_connections 120 less Azure's 15), but the apps may hold ${String(holds)}: two of each API copy's pool, each Zitadel copy's, one job and one to spare`;
    expect(connectionProblems(loadChanged(api, copies('4')))).toEqual([over(120)]);
    expect(connectionProblems(loadChanged(APP('jobs'), setting('AGENTX_DB_JOBS_POOL_MAX', '10')))).toEqual([]);
    expect(connectionProblems(loadChanged(APP('jobs'), setting('AGENTX_DB_JOBS_POOL_MAX', '11')))).toEqual([over(106)]);
  });

  it("apps and connections: Zitadel's copies, one on staging and up to four in production, each one's pool counted (SA3a)", () => {
    const production = { region: 'uaenorth', environment: 'production' } as const;
    const zitadelAt = (most: unknown, from: Snapshot = staging, fewest: unknown = 1): Snapshot =>
      changed(APP('zitadel'), (app) => Object.assign(scaleOf(app), { minReplicas: fewest, maxReplicas: most }), from);
    // The rule's messages alone: only Zitadel is changed, and the server's name carries the deployment's suffix.
    const problemsOf = (snapshotted: Snapshot, rule: RuleId, expected: Expectations = STAGING): string[] =>
      policyProblems(snapshotted, expected)
        .filter((problem) => problem.rule === rule)
        .map(({ message }) => message);
    expect(problemsOf(zitadelAt(2), 'apps')).toEqual([
      "must run at most one replica (maxReplicas 1): staging's server has no room for a second copy's database connections; it says 2",
    ]);
    // Production's Zitadel: up to four copies pass; a fifth, or a count that isn't one, doesn't.
    const productionApps = (most: unknown, fewest: unknown = 2): string[] =>
      problemsOf(zitadelAt(most, productionLike({ subject: true }), fewest), 'apps', production);
    for (const most of [2, 4]) expect({ most, problems: productionApps(most) }).toEqual({ most, problems: [] });
    expect(productionApps(4, 3)).toEqual([]);
    // Production keeps two running, so sign-in never hangs on one copy; staging's may still sleep at none.
    const atLeastTwo = (says: string): string =>
      `must keep at least 2 replicas running (minReplicas 2): sign-in must not hang on one copy; it says ${says}`;
    expect(productionApps(4, 1)).toEqual([atLeastTwo('1')]);
    expect(productionApps(4, 0)).toEqual([atLeastTwo('0')]);
    expect(productionApps(4, 'two')).toEqual([
      atLeastTwo('two'),
      'must keep no more replicas than it may run (minReplicas two, maxReplicas 4)',
    ]);
    expect(problemsOf(zitadelAt(1, staging, 0), 'apps')).toEqual([]);
    expect(problemsOf(zitadelAt(1, staging, 1), 'apps')).toEqual([]);
    const atMostFour = (says: string): string =>
      `must run at most 4 replicas (maxReplicas 4): Zitadel's copies stop at four (SA3a), each holding its own database connections; it says ${says}`;
    expect(productionApps(5)).toEqual([atMostFour('5')]);
    expect(productionApps('four')).toEqual([
      atMostFour('four'),
      'must be able to run a replica (maxReplicas at least 1); it says four',
    ]);
    // Its pool counts once for each copy it may run: 32 of staging's 35 with one copy, 42 with two.
    expect(problemsOf(zitadelAt(1), 'connections')).toEqual([]);
    expect(problemsOf(zitadelAt(2), 'connections')).toEqual([
      "has 35 connections for users (max_connections 50 less Azure's 15), but the apps may hold 42: two of each API copy's pool, each Zitadel copy's, one job and one to spare",
    ]);
    // A count of copies that can't be read is said, never summed as nothing.
    for (const most of ['two', 1.5]) {
      expect(problemsOf(zitadelAt(most), 'connections')).toEqual([
        'ca-agentx-stg-zitadel must state maxReplicas as a whole number, so its connections can be counted',
      ]);
    }
    // Production counts a revision swap too: the new revision's two copies beside the old one's four, 10 × 6 = 60.
    // With the split API's 10 and 12 and two more, 84: a server of 99 fits it exactly, one of 98 is one short.
    const atServer = (limit: string, from: Snapshot): Snapshot =>
      changed(
        (resource) =>
          resource.type === 'Microsoft.DBforPostgreSQL/flexibleServers/configurations' &&
          resource.name.endsWith('/max_connections'),
        (setting) => (inside(setting, 'properties').value = limit),
        from,
      );
    const productionZitadel = (fewest: unknown): Snapshot =>
      changed(
        APP('zitadel'),
        (app) => {
          setSetting(app, 'ZITADEL_DATABASE_POSTGRES_MAXOPENCONNS', '10');
        },
        zitadelAt(4, productionLike({ subject: true }), fewest),
      );
    expect(problemsOf(atServer('99', productionZitadel(2)), 'connections', production)).toEqual([]);
    expect(problemsOf(atServer('98', productionZitadel(2)), 'connections', production)).toEqual([
      "has 83 connections for users (max_connections 98 less Azure's 15), but the apps may hold 84: two of each API copy's pool, each Zitadel copy's, one job and one to spare",
    ]);
    expect(problemsOf(atServer('99', productionZitadel('two')), 'connections', production)).toEqual([
      'ca-agentx-stg-zitadel must state minReplicas as a whole number, so its connections can be counted',
    ]);
    // Staging's one copy counts alone, its overlap not (32 of 35): counted as production's, it would be 42.
    expect(problemsOf(zitadelAt(1, staging, 1), 'connections')).toEqual([]);
  });

  it('apps.bicep compiled for production: Zitadel at two to four copies of 1 vCPU and 2Gi, passing the apps and jobs rules (SA3a)', () => {
    // No production parameters are committed yet: staging's two, the foundation's and the apps', named production,
    // with the snapshot's stand-ins for what the shell gives. Production's own values (its backups, evidence store,
    // alerts, secrets and certificates) are other rules', so only the apps and jobs rules are read here.
    const production = inCopy((dir) => {
      for (const part of ['', '.apps']) {
        const text = readFileSync(path.join(dir, `staging${part}.bicepparam`), 'utf8');
        expect(text).toContain("param environment = 'staging'");
        writeFileSync(
          path.join(dir, `production${part}.bicepparam`),
          text.replace("param environment = 'staging'", "param environment = 'production'"),
        );
      }
      return environmentSnapshot(dir, 'production').together;
    });
    const zitadel = production.predictedResources.find(APP('zitadel'));
    expect(zitadel?.name).toBe('ca-agentx-prd-zitadel');
    expect(at(zitadel?.properties, 'template', 'scale')).toEqual({ minReplicas: 2, maxReplicas: 4 });
    expect(at(containerOf(zitadel as unknown as Mutable), 'resources')).toEqual({ cpu: 1, memory: '2Gi' });
    // Its login pages too, at staging's size (SA3c).
    const login = production.predictedResources.find(APP('login'));
    expect(at(login?.properties, 'template', 'scale')).toEqual({ minReplicas: 2, maxReplicas: 4 });
    expect(at(containerOf(login as unknown as Mutable), 'resources')).toEqual({ cpu: 0.5, memory: '1Gi' });
    // The API's copies at 1 vCPU and 2 GiB, its heap three quarters of it; staging's at 0.5 vCPU and 1 GiB. Both with
    // all three probes pinned (AZ8b): startup and readiness at Azure's documented defaults, liveness its own.
    const apiOf = (from: Snapshot): Mutable =>
      containerOf(from.predictedResources.find(APP('api')) as unknown as Mutable);
    const tcp = (type: string, [delay, period, timeout, failures]: readonly number[]): Mutable => ({
      type,
      tcpSocket: { port: 8080 },
      initialDelaySeconds: delay,
      periodSeconds: period,
      timeoutSeconds: timeout,
      successThreshold: 1,
      failureThreshold: failures,
    });
    const probes = [tcp('Startup', [1, 1, 3, 240]), tcp('Readiness', [3, 5, 5, 48]), tcp('Liveness', [1, 10, 5, 6])];
    expect(at(apiOf(production), 'resources')).toEqual({ cpu: 1, memory: '2Gi' });
    expect(at(apiOf(production), 'command')).toContain('--max-old-space-size=1536');
    expect(at(apiOf(production), 'probes')).toEqual(probes);
    expect(at(apiOf(staging), 'resources')).toEqual({ cpu: 0.5, memory: '1Gi' });
    expect(at(apiOf(staging), 'command')).toContain('--max-old-space-size=768');
    expect(at(apiOf(staging), 'probes')).toEqual(probes);
    // Every other app keeps Azure's defaults.
    for (const workload of ['zitadel', 'login', 'jobs']) {
      const app = production.predictedResources.find(APP(workload)) as unknown as Mutable;
      expect(at(containerOf(app), 'probes') ?? null, workload).toBeNull();
    }
    const problems = policyProblems(production, { region: 'uaenorth', environment: 'production' });
    expect(problems.filter(({ rule }) => rule === 'apps' || rule === 'jobs')).toEqual([]);
    // Its count at production's defaults (Azure.md): web 60, jobs 20, Zitadel 10 x (4 + 2), and two more.
    expect(problems.filter(({ rule }) => rule === 'connections').map(({ message }) => message)).toEqual([
      "has 35 connections for users (max_connections 50 less Azure's 15), but the apps may hold 142: two of each API copy's pool, each Zitadel copy's, one job and one to spare",
    ]);
    // The parameter's bounds are the policy's: no more copies than it allows, no fewer than it keeps running.
    const copies = at(bicepFile('apps.bicep').template, 'parameters', 'zitadelMostCopies');
    expect(at(copies, 'maxValue')).toBe(ZITADEL_COPIES.production.most);
    expect(at(copies, 'minValue')).toBe(ZITADEL_COPIES.production.fewest);
    expect(at(copies, 'defaultValue')).toBe(ZITADEL_COPIES.production.most);
    const loginCopies = at(bicepFile('apps.bicep').template, 'parameters', 'loginMostCopies');
    expect(at(loginCopies, 'maxValue')).toBe(LOGIN_COPIES.production.most);
    expect(at(loginCopies, 'minValue')).toBe(LOGIN_COPIES.production.fewest);
    expect(at(loginCopies, 'defaultValue')).toBe(LOGIN_COPIES.production.most);
  });

  it("apps: the login pages' copies, one on staging and two to four in production (SA3c)", () => {
    const production = { region: 'uaenorth', environment: 'production' } as const;
    const loginAt = (from: Snapshot, fewest: unknown, most: unknown): Snapshot =>
      changed(APP('login'), (app) => Object.assign(scaleOf(app), { minReplicas: fewest, maxReplicas: most }), from);
    const appsMessages = (snapshotted: Snapshot, expected: Expectations): string[] =>
      policyProblems(snapshotted, expected)
        .filter(({ rule }) => rule === 'apps')
        .map(({ message }) => message);
    // Staging: one, asleep or awake; a second is refused.
    for (const fewest of [0, 1]) expect(appsMessages(loginAt(staging, fewest, 1), STAGING)).toEqual([]);
    expect(appsMessages(loginAt(staging, 1, 2), STAGING)).toEqual([
      'must run at most one replica (maxReplicas 1): staging keeps one copy of the login pages, as it does of Zitadel; it says 2',
    ]);
    // Production: two to four running; a fifth, or fewer than two kept, is refused.
    const productionLogin = (fewest: unknown, most: unknown): string[] =>
      appsMessages(loginAt(productionLike({ subject: true }), fewest, most), production);
    for (const [fewest, most] of [
      [2, 2],
      [2, 4],
      [3, 4],
    ] as const) {
      expect({ fewest, most, problems: productionLogin(fewest, most) }).toEqual({ fewest, most, problems: [] });
    }
    expect(productionLogin(2, 5)).toEqual([
      "must run at most 4 replicas (maxReplicas 4): the login pages' copies stop at four (SA3c), as Zitadel's; it says 5",
    ]);
    expect(productionLogin(1, 4)).toEqual([
      'must keep at least 2 replicas running (minReplicas 2): sign-in must not hang on one copy; it says 1',
    ]);
  });

  it("apps and jobs: a container at a size Azure's Consumption profile doesn't offer", () => {
    const sized = (pick: (resource: PredictedResource) => boolean, cpu: unknown, memory: unknown): Snapshot =>
      changed(pick, (resource) => {
        containerOf(resource).resources = { cpu, memory };
      });
    const sizeProblems = (snapshotted: Snapshot): string[] =>
      policyProblems(snapshotted, STAGING)
        .filter(({ message }) => message.includes('Consumption profile offers'))
        .map(({ rule, resource, message }) => `${rule} ${resource}: ${message}`);
    // Staging's own apps and jobs, in a load run or out of one, are every one at an offered size.
    expect(sizeProblems(staging)).toEqual([]);
    expect(sizeProblems(load.together)).toEqual([]);
    // The smallest, the largest, and each a quarter vCPU apart with 2Gi a vCPU, in GiB or MiB.
    for (const [cpu, memory] of [
      [0.25, '0.5Gi'],
      [1, '2Gi'],
      [1, '2048Mi'],
      [1.75, '3.5Gi'],
      [4, '8Gi'],
    ] as const) {
      expect({ cpu, memory, problems: sizeProblems(sized(APP('zitadel'), cpu, memory)) }).toEqual({
        cpu,
        memory,
        problems: [],
      });
    }
    const offSize = (rule: string, resource: string, cpu: string, memory: string): string =>
      `${rule} ${resource}: must run at a size the Consumption profile offers (0.25 to 4 vCPU in quarters, with 2Gi for each vCPU); it says ${cpu} vCPU and ${memory}`;
    for (const [cpu, memory] of [
      [0.5, '2Gi'],
      [1, '1Gi'],
      [0.3, '0.6Gi'],
      [0, '0Gi'],
      [4.25, '8.5Gi'],
      ['1', '2Gi'],
      [1, undefined],
    ] as const) {
      expect(sizeProblems(sized(APP('zitadel'), cpu, memory))).toEqual([
        offSize('apps', 'ca-agentx-stg-zitadel', String(cpu), String(memory)),
      ]);
    }
    // A job's size too.
    expect(sizeProblems(sized(JOB('migrate'), 0.5, '2Gi'))).toEqual([
      offSize('jobs', 'job-agentx-stg-migrate', '0.5', '2Gi'),
    ]);
  });

  it('load-run: the API out of its load size, limits or email in a load run, or in either out of one', () => {
    const api = APP('api');
    for (const change of [
      // Each at a size Azure offers, its memory twice its vCPUs (the `apps` rule's otherwise): larger than measured,
      (app: Mutable) => {
        containerOf(app).resources = { cpu: 2.5, memory: '5Gi' };
      },
      // and smaller, with its heap brought down too: a heap of 3072 MiB in 1 GiB is the `apps` rule's (4D2e D12).
      (app: Mutable) => {
        containerOf(app).resources = { cpu: 0.5, memory: '1Gi' };
        containerOf(app).command = ['node', '--max-old-space-size=768', 'apps/api/src/main.ts'];
      },
      (app: Mutable) => {
        for (const entry of settingsOf(app).filter((each) => each.name === 'AGENTX_RATE_LIMIT_PER_AGENT_PER_MINUTE')) {
          entry.value = '120';
        }
      },
      (app: Mutable) => settingsOf(app).push({ name: 'AGENTX_EMAIL_SENDER', value: 'DoNotReply@example.invalid' }),
    ]) {
      expect(brokenRules(loadChanged(api, change))).toEqual(['load-run']);
    }
    // Out of a load run, the API never carries the load run's size or limits.
    expect(
      brokenRules(
        changed(api, (app) => settingsOf(app).push({ name: 'AGENTX_RATE_LIMIT_PER_MINUTE', value: '50000' })),
      ),
    ).toEqual(['load-run']);
    expect(
      brokenRules(
        changed(api, (app) => {
          containerOf(app).resources = { cpu: 2, memory: '4Gi' };
          containerOf(app).command = ['node', '--max-old-space-size=3072', 'apps/api/src/main.ts'];
        }),
      ),
    ).toEqual(['load-run']);
  });

  it('load-run: the API not split as three web copies, or its jobs app off its size, connections, cap or email, in a load run or out of one (4D2e D13)', () => {
    const loadRunProblems = (snapshotted: Snapshot, expected: Expectations = STAGING): string[] =>
      policyProblems(snapshotted, expected)
        .filter(({ rule }) => rule === 'load-run')
        .map(({ resource, message }) => `${resource}: ${message}`);
    const notSplit =
      'ca-agentx-stg-api: must run as 3 web copies in the load run (4D2e D13: AGENTX_ROLE web, AGENTX_WEB_COPIES 3), beside the jobs app, the split it is measured as';
    const unset = (name: string) => (app: Mutable) => {
      containerOf(app).env = settingsOf(app).filter((entry) => entry.name !== name);
    };
    expect(loadRunProblems(loadChanged(APP('api'), unset('AGENTX_ROLE')))).toEqual([notSplit]);
    expect(
      loadRunProblems(
        loadChanged(APP('api'), (app) => {
          setSetting(app, 'AGENTX_WEB_COPIES', '2');
          Object.assign(scaleOf(app), { minReplicas: 2, maxReplicas: 2 });
        }),
      ),
    ).toEqual([notSplit]);
    const jobs = APP('jobs');
    expect(loadRunProblems(loadChanged(jobs, (app) => (inside(containerOf(app), 'resources').cpu = 0.5)))).toEqual([
      'ca-agentx-stg-jobs: must run at 1 CPU and 2Gi in the load run (4D2e D13), the size it is measured at',
    ]);
    expect(
      loadRunProblems(
        loadChanged(jobs, (app) => {
          setSetting(app, 'AGENTX_DB_JOBS_POOL_MAX', '10');
        }),
      ),
    ).toEqual(['ca-agentx-stg-jobs: must keep 6 connections in the load run (4D2e D13), the size it is measured at']);
    expect(loadRunProblems(loadChanged(jobs, unset('AGENTX_LOG_EVENT_CAP_PER_MINUTE')))).toEqual([
      "ca-agentx-stg-jobs: must set AGENTX_LOG_EVENT_CAP_PER_MINUTE to 200000 in the load run (4D2e D13), as the API's, since they log for the same run",
    ]);
    expect(
      loadRunProblems(
        loadChanged(jobs, (app) => {
          setSetting(app, 'AGENTX_EMAIL_SENDER', 'DoNotReply@example.invalid');
        }),
      ),
    ).toEqual([
      'ca-agentx-stg-jobs: sets AGENTX_EMAIL_SENDER in the load run (D2c): its seeded admins have no address, so it sends no email',
    ]);
    expect(
      loadRunProblems({
        ...load.together,
        predictedResources: load.together.predictedResources.filter((r) => !jobs(r)),
      }),
    ).toEqual(['the deployment: needs the jobs app once in a load run (4D2e D13); the snapshot has 0']);
    // Staging out of a load run runs no jobs app: its one API holds the jobs and sleeps.
    const jobsApp = structuredClone(found(load.together, jobs));
    expect(loadRunProblems({ ...staging, predictedResources: [...staging.predictedResources, jobsApp] })).toContain(
      'the deployment: runs the jobs app on staging out of a load run: its one API holds the jobs and sleeps (4D2e D13), and a jobs app always running passes the $60 alarm',
    );
    // Production's jobs app keeps none of the load run's size or cap.
    const production = { region: 'uaenorth', environment: 'production' } as const;
    const split = productionLike({ subject: true });
    expect(loadRunProblems(split, production)).toEqual([]);
    expect(
      loadRunProblems(
        changed(
          jobs,
          (app) => {
            setSetting(app, 'AGENTX_LOG_EVENT_CAP_PER_MINUTE', '200000');
          },
          split,
        ),
        production,
      ),
    ).toEqual([
      "ca-agentx-stg-jobs: sets AGENTX_LOG_EVENT_CAP_PER_MINUTE, which only the load run's jobs do (4D2e D13): out of it they keep their own",
    ]);
    expect(
      loadRunProblems(
        changed(jobs, (app) => Object.assign(inside(containerOf(app), 'resources'), { cpu: 1, memory: '2Gi' }), split),
        production,
      ),
    ).toEqual([
      "ca-agentx-stg-jobs: runs at the load run's size out of a load run (4D2e D13): apps --load-run alone sets it",
    ]);
  });

  it("workload-secrets and stores in the load run: the jobs app given the email key, or told of a store as the API's identity (4D2e D13)", () => {
    const jobs = APP('jobs');
    const rulesFor = (snapshotted: Snapshot) =>
      policyProblems(snapshotted, STAGING).map(({ rule, resource }) => `${rule} ${resource}`);
    const withKey = loadChanged(jobs, (app) => {
      declaredSecrets(app).push({ ...secretNamed(app, 'db-app-password'), name: 'acs-access-key' });
    });
    expect(rulesFor(withKey)).toContain('workload-secrets ca-agentx-stg-jobs');
    const asApi = (prefix: string) =>
      loadChanged(jobs, (app) => {
        for (const entry of settingsOf(app).filter((each) => String(each.name).startsWith(prefix))) {
          entry.value = String(entry.value).replace('id-agentx-stg-jobs', 'id-agentx-stg-api');
        }
      });
    expect(rulesFor(asApi('AGENTX_AUDIT_ANCHORS_'))).toEqual(['evidence-store ca-agentx-stg-jobs']);
    expect(rulesFor(asApi('AGENTX_ACTIVITY_DOWNLOADS_'))).toEqual(['activity-downloads ca-agentx-stg-jobs']);
    // The web copies, which hold no jobs, are told nothing of the anchors, nor their epoch.
    const anchorsOf = settingsOf(found(load.together, jobs) as unknown as Mutable).filter((entry) =>
      /^AGENTX_(?:ANCHOR_EPOCH|AUDIT_ANCHORS_)/.test(String(entry.name)),
    );
    const webTold = loadChanged(APP('api'), (app) => settingsOf(app).push(...structuredClone(anchorsOf)));
    expect(rulesFor(webTold)).toEqual(
      expect.arrayContaining(['evidence-store ca-agentx-stg-api', 'anchor-epoch ca-agentx-stg-api']),
    );
  });

  it("workload-secrets: a load job given anything of the API's but its login and keys, as another identity, or with its request changed", () => {
    const first = JOB('load-first');
    const message = (snapshotted: Snapshot): string[] =>
      policyProblems(snapshotted, STAGING)
        .filter((problem) => problem.rule === 'workload-secrets')
        .map((problem) => problem.message);
    expect(
      message(
        loadChanged(first, (job) => {
          declaredSecrets(job).push({ ...secretNamed(job, 'db-app-password'), name: 'zitadel-reset-token' });
        }),
      ),
    ).toContain("is given zitadel-reset-token, which GRANTS doesn't let load-first read");
    expect(
      message(
        loadChanged(first, (job) => {
          job.identity = { type: 'UserAssigned', userAssignedIdentities: { other: {} } };
        }),
      ),
    ).toContain('must run as its own identity alone, the one named for api');
    expect(
      message(
        loadChanged(first, (job) => {
          secretNamed(job, 'load-request').value = '{"AGENTX_LOAD_RUN_ID":"r1"}';
        }),
      ),
    ).toContain('must hold load-request once, as {} and nothing else: a person writes it before a run');
    expect(
      message(
        loadChanged(first, (job) => {
          containerOf(job).args = ['cleanup'];
        }),
      ),
    ).toContain(
      "must run node tooling/load/job.ts first and nothing else: a request in its command or arguments would sit in the deployment and every run's record",
    );
    // In a load run the API goes without the email key and the directory token; out of one it must have both.
    expect(
      message(
        changed(APP('api'), (app) => {
          configurationOf(app).secrets = declaredSecrets(app).filter((secret) => secret.name !== 'acs-access-key');
        }),
      ),
    ).toContain('must be given acs-access-key, which api reads (GRANTS)');
  });
});

describe("Stage G's run on its throwaway copy (4D2e)", () => {
  const LOAD_DIGEST = `sha256:${'a'.repeat(64)}`;
  const COPY = 'psql-agentx-stg-g-a1b2c3d4';
  const COPY_HOST = `${COPY}.postgres.database.azure.com`;
  const ANCHORS = 'audit-anchors-g-a1b2c3d4';
  let copy: EnvironmentSnapshot;
  let ignored: EnvironmentSnapshot;
  let plainLoad: EnvironmentSnapshot;

  beforeAll(() => {
    const snap = (values: Readonly<Record<string, string>>) =>
      inCopy((dir) => environmentSnapshot(dir, 'staging', values));
    const loadRun = { AGENTX_AZURE_LOAD_RUN: 'true', AGENTX_AZURE_LOAD_IMAGE_DIGEST: LOAD_DIGEST };
    copy = snap({ ...loadRun, AGENTX_AZURE_LOAD_DATABASE_HOST: COPY_HOST });
    plainLoad = snap(loadRun);
    // A plain apps can never carry the copy: apps.bicep reads it in a load run alone.
    ignored = snap({ AGENTX_AZURE_LOAD_DATABASE_HOST: COPY_HOST });
  });

  const onCopy = (pick: (resource: PredictedResource) => boolean, change: (resource: Mutable) => void): Snapshot =>
    changed(pick, change, copy.together);
  const found = (snapshotted: Snapshot, pick: (resource: PredictedResource) => boolean): Mutable => {
    const resource = snapshotted.predictedResources.find(pick);
    if (resource === undefined) throw new Error('not in the snapshot');
    return resource as unknown as Mutable;
  };
  const value = (resource: Mutable, name: string) => settingsOf(resource).find((entry) => entry.name === name)?.value;
  const said = (snapshotted: Snapshot) =>
    policyProblems(snapshotted, STAGING).map(({ rule, resource, message }) => `${rule} ${resource}: ${message}`);
  const setTo = (name: string, to: string) => (resource: Mutable) => {
    for (const entry of settingsOf(resource).filter((each) => each.name === name)) entry.value = to;
  };
  const STAGE_G = ['load-mark', 'load-step', 'load-check'];
  const REACHING = [APP('api'), APP('jobs'), JOB('load-first'), JOB('load-step'), JOB('load-check')];
  const STAGING_HOST = (snapshotted: Snapshot) =>
    `${String(found(snapshotted, SERVER).name)}.postgres.database.azure.com`;
  const ANCHORS_ON_COPY = (resource: PredictedResource) =>
    resource.type === 'Microsoft.Storage/storageAccounts/blobServices/containers' &&
    resource.id.endsWith(`/${ANCHORS}`);
  const COPY_ROLE = (resource: PredictedResource) =>
    resource.type === 'Microsoft.Authorization/roleAssignments' && resource.id.includes(`/containers/${ANCHORS}/`);

  it('compiles: every rule holds, the API, its jobs app and the load jobs on the copy, every other job on staging', () => {
    expect(policyProblems(copy.together, STAGING).map(describeProblem)).toEqual([]);
    const staging = STAGING_HOST(copy.together);
    for (const pick of REACHING) {
      const resource = found(copy.together, pick);
      expect([value(resource, 'AGENTX_DB_HOST'), value(resource, 'AGENTX_LOAD_DB_HOST') ?? COPY_HOST]).toEqual([
        COPY_HOST,
        COPY_HOST,
      ]);
    }
    for (const job of ['db-setup', 'migrate', 'operator', 'chain-restore']) {
      expect(value(found(copy.together, JOB(job)), 'AGENTX_DB_HOST')).toBe(staging);
    }
    // The copy's own anchors, its container and its role for the jobs app; no downloads, no resets on it.
    expect(value(found(copy.together, APP('jobs')), 'AGENTX_AUDIT_ANCHORS_URL')).toMatch(
      new RegExp(`'${ANCHORS}'\\)\\]$`),
    );
    expect(found(copy.together, ANCHORS_ON_COPY)).toBeDefined();
    expect(at(found(copy.together, COPY_ROLE), 'properties', 'principalId')).toMatch(/id-agentx-stg-jobs/);
    for (const app of [APP('api'), APP('jobs')]) {
      const names = settingsOf(found(copy.together, app)).map(({ name }) => String(name));
      expect(names.filter((name) => /DOWNLOADS|FACTOR_RESET|EMAIL/.test(name))).toEqual([]);
      expect(declaredSecrets(found(copy.together, app)).map(({ name }) => name)).not.toContain('zitadel-reset-token');
    }
    // Stage G's jobs: who each runs as, what each reads, how long the step may run.
    const identity = (job: string) =>
      Object.keys(at(found(copy.together, JOB(job)), 'identity', 'userAssignedIdentities') as Mutable)[0];
    expect(STAGE_G.map(identity)).toEqual([
      expect.stringMatching(/id-agentx-stg-stage-g$/),
      expect.stringMatching(/id-agentx-stg-api/),
      expect.stringMatching(/id-agentx-stg-stage-g$/),
    ]);
    const reads = (job: string) => declaredSecrets(found(copy.together, JOB(job))).map(({ name }) => name);
    expect(reads('load-mark')).toEqual(['db-owner-password']);
    expect(reads('load-check')).toEqual(['db-app-password', 'db-backup-password', 'load-request']);
    // The key's vault name built here: a password-named name beside a name with a digit reads to GitGuardian as a secret (S175, #573).
    const macKey = `key-audit-mac-v${String(1)}`;
    expect(reads('load-step')).toEqual(expect.arrayContaining(['db-app-password', macKey, 'load-request']));
    expect(at(found(copy.together, JOB('load-step')), 'properties', 'configuration', 'replicaTimeout')).toBe(
      STAGE_G_JOB_SECONDS,
    );
  });

  it("can't be carried by a plain apps, and a load run without it stays on staging with no Stage G job", () => {
    const names = (snapshotted: Snapshot) => snapshotted.predictedResources.map((resource) => resource.name).sort();
    expect(names(ignored.together)).toEqual(names(staging));
    expect(JSON.stringify(ignored.together)).not.toContain(COPY);
    expect(policyProblems(plainLoad.together, STAGING)).toEqual([]);
    expect(JSON.stringify(plainLoad.together)).not.toContain('stageg-job');
    expect(JSON.stringify(plainLoad.together)).not.toContain('audit-anchors-g-');
  });

  it('load-database: the API, its jobs or a load job somewhere else, or another job on the copy', () => {
    const staging = STAGING_HOST(copy.together);
    // The API back on staging while the load jobs stay on the copy: two databases.
    expect(said(onCopy(APP('api'), setTo('AGENTX_DB_HOST', staging)))).toEqual(
      expect.arrayContaining([
        `load-database the deployment: must reach one database from the API, its jobs app and the load jobs; they reach ${COPY_HOST}, ${staging}`,
      ]),
    );
    expect(brokenRules(onCopy(JOB('load-step'), setTo('AGENTX_LOAD_DB_HOST', staging)))).toEqual(['load-database']);
    // Every one of them on a server named as neither.
    const elsewhere = 'psql-agentx-stg-other.postgres.database.azure.com';
    const allElsewhere = onCopy(
      (resource) =>
        REACHING.some((pick) => pick(resource)) ||
        JOB('load-second')(resource) ||
        JOB('load-cleanup')(resource) ||
        JOB('load-mark')(resource),
      (resource) => {
        setTo('AGENTX_DB_HOST', elsewhere)(resource);
        setTo('AGENTX_LOAD_DB_HOST', elsewhere)(resource);
      },
    );
    expect(said(allElsewhere)).toContain(
      `load-database the deployment: reaches ${elsewhere}, which is neither staging's own server nor a Stage G copy (psql-agentx-stg-g-<8 lower-case letters or digits>.postgres.database.azure.com)`,
    );
    // The migration on the copy: everything else stays on staging's own server.
    expect(said(onCopy(JOB('migrate'), setTo('AGENTX_DB_HOST', COPY_HOST)))).toEqual([
      `load-database job-agentx-stg-migrate: must reach staging's own server, ${staging}: only the API, its jobs app and the load jobs reach Stage G's copy`,
    ]);
  });

  it("load-database: Stage G's jobs missing, twice, running something else, or with no copy", () => {
    const without = (pick: (resource: PredictedResource) => boolean): Snapshot => ({
      predictedResources: copy.together.predictedResources.filter((resource) => !pick(resource)),
      diagnostics: [],
    });
    for (const job of STAGE_G) {
      expect(said(without(JOB(job)))).toEqual([
        `load-database the deployment: needs the ${job} job once on Stage G's copy; the snapshot has 0`,
      ]);
    }
    expect(said(onCopy(JOB('load-mark'), (job) => (containerOf(job).args = ['step'])))).toEqual([
      'load-database job-agentx-stg-load-mark: must run node tooling/load/stageg-job.ts mark and nothing else',
    ]);
    expect(
      brokenRules(onCopy(JOB('load-mark'), (job) => (containerOf(job).command = ['node', 'tooling/load/job.ts']))),
    ).toEqual(['load-database']);
    // Stage G's jobs beside a load run on staging's own server.
    const mark = copy.together.predictedResources.filter(JOB('load-mark'));
    const onStaging: Snapshot = {
      predictedResources: [...plainLoad.together.predictedResources, ...mark],
      diagnostics: [],
    };
    expect(said(onStaging)).toContain(
      "load-database the deployment: runs Stage G's jobs with no throwaway copy: they exist only on its run (apps --load-run --load-database)",
    );
    // The copy reached with no load run at all (PL-38's jobs gone).
    const noLoadRun = without((resource) =>
      ['load-first', 'load-second', 'load-cleanup'].some((job) => JOB(job)(resource)),
    );
    expect(said(noLoadRun)).toContain(
      "load-database the deployment: reaches Stage G's copy out of a load run: apps --load-run --load-database alone points the API there",
    );
  });

  it("load-database and evidence-store: the copy's anchors in staging's container, another copy's, or kept by another", () => {
    const stagingAnchors = onCopy(APP('jobs'), (app) => {
      for (const entry of settingsOf(app).filter(({ name }) => name === 'AGENTX_AUDIT_ANCHORS_URL')) {
        entry.value = String(entry.value).replace(ANCHORS, 'audit-anchors');
      }
    });
    expect(said(stagingAnchors)).toEqual([
      "evidence-store ca-agentx-stg-jobs: must set AGENTX_AUDIT_ANCHORS_URL to this deployment's store's audit-anchors-g-a1b2c3d4 container, and AGENTX_AUDIT_ANCHORS_CLIENT_ID to the client ID of the identity its role is given to, each once as a value, and no other AGENTX_AUDIT_ANCHORS_ setting",
    ]);
    const without = (pick: (resource: PredictedResource) => boolean): Snapshot => ({
      predictedResources: copy.together.predictedResources.filter((resource) => !pick(resource)),
      diagnostics: [],
    });
    expect(said(without(COPY_ROLE))).toEqual([
      `load-database the deployment: must give the anchors' role on ${ANCHORS} once, to the jobs app; it gives 0`,
    ]);
    expect(said(without((resource) => ANCHORS_ON_COPY(resource) || COPY_ROLE(resource)))).toEqual(
      expect.arrayContaining([
        `load-database the deployment: needs Stage G's copy's own anchors container, ${ANCHORS}: never staging's audit-anchors`,
      ]),
    );
    const another = onCopy(
      (resource) => ANCHORS_ON_COPY(resource) || COPY_ROLE(resource),
      (resource) => {
        resource.id = String(resource.id).replace(ANCHORS, 'audit-anchors-g-zzzzzzzz');
        resource.name = String(resource.name).replace(ANCHORS, 'audit-anchors-g-zzzzzzzz');
      },
    );
    expect(brokenRules(another)).toEqual(['load-database']);
    const toApi = onCopy(COPY_ROLE, (role) => {
      inside(role, 'properties').principalId = String(at(role, 'properties', 'principalId')).replace(
        'id-agentx-stg-jobs',
        'id-agentx-stg-api',
      );
    });
    expect(said(toApi)).toEqual([
      expect.stringMatching(
        /^load-database [0-9a-f-]+: must give the anchors' role on the copy's anchors to the jobs app's identity alone$/,
      ),
    ]);
    // Out of the copy's run, a copy's container is no one's.
    const stray = found(copy.together, ANCHORS_ON_COPY);
    expect(
      brokenRules({
        predictedResources: [...staging.predictedResources, stray as unknown as PredictedResource],
        diagnostics: [],
      }),
    ).toEqual(['load-database']);
  });

  it('activity-downloads and workload-secrets: the copy given the downloads or the reset token', () => {
    const plainApi = found(staging, APP('api'));
    const downloads = settingsOf(plainApi).filter(({ name }) => String(name).startsWith('AGENTX_ACTIVITY_DOWNLOADS_'));
    expect(downloads).toHaveLength(2);
    expect(said(onCopy(APP('api'), (app) => settingsOf(app).push(...structuredClone(downloads))))).toEqual([
      "activity-downloads ca-agentx-stg-api: sets AGENTX_ACTIVITY_DOWNLOADS_URL, AGENTX_ACTIVITY_DOWNLOADS_CLIENT_ID: only the apps that run the API keep the activity downloads, and never on Stage G's copy",
    ]);
    const token = secretNamed(plainApi, 'zitadel-reset-token');
    expect(
      brokenRules(
        onCopy(APP('jobs'), (app) =>
          declaredSecrets(app).push({
            ...structuredClone(token),
            identity: secretNamed(app, 'db-app-password').identity,
          }),
        ),
      ),
    ).toEqual(['workload-secrets']);
    // The mark given the backup login too, or the check the owner's.
    expect(
      said(
        onCopy(JOB('load-mark'), (job) =>
          declaredSecrets(job).push({ ...secretNamed(job, 'db-owner-password'), name: 'db-backup-password' }),
        ),
      ),
    ).toContain(
      "workload-secrets job-agentx-stg-load-mark: is given db-backup-password, which GRANTS doesn't let load-mark read",
    );
    expect(
      said(
        onCopy(
          JOB('load-check'),
          (job) => (job.identity = { type: 'UserAssigned', userAssignedIdentities: { 'id-agentx-stg-api': {} } }),
        ),
      ),
    ).toContain(
      'workload-secrets job-agentx-stg-load-check: must run as its own identity alone, the one named for stage-g',
    );
  });

  it('jobs: the step past its stated limit, or any other load job past the hour', () => {
    const longer = (job: string, seconds: number) =>
      said(onCopy(JOB(job), (found) => (configurationOf(found).replicaTimeout = seconds)));
    expect(longer('load-step', STAGE_G_JOB_SECONDS + 1)).toEqual([
      `jobs job-agentx-stg-load-step: must give up after 1 to ${String(STAGE_G_JOB_SECONDS)} seconds (replicaTimeout); it says ${String(STAGE_G_JOB_SECONDS + 1)}`,
    ]);
    expect(longer('load-check', 3601)).toEqual([
      'jobs job-agentx-stg-load-check: must give up after 1 to 3600 seconds (replicaTimeout); it says 3601',
    ]);
  });
});
