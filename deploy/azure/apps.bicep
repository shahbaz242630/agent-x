// Agent X's apps and jobs on Azure (ADR-002 Amendment G2d): the four jobs that
// prepare a deployment and the operator's command (B1c), each started by hand,
// the three apps that serve traffic (the API, Zitadel and its login pages), and
// the public doors that put an app on a host name (G2e). A deployment of its
// own, into the resource group main.bicep creates and after secrets.bicep has
// written the secrets:
//
//   bicep snapshot deploy/azure/staging.apps.bicepparam --resource-group rg-agentx-staging
//   az deployment group create --resource-group rg-agentx-staging \
//     --parameters deploy/azure/staging.apps.bicepparam   # G3
//
// - each app and job runs as its own identity (main.bicep created one per app
//   and job) and reads its own secrets alone, by versionless URL, so a rotation
//   reaches it without a redeployment. `GRANTS` in policy.ts holds the one list of who
//   reads what, and checks this file against it
// - a secret reaches a container as a mounted file wherever the program can read
//   one: an environment is copied into crash output and read by every child
//   process. Ours takes every login as a file, and Zitadel's master key has a
//   file form too (`--masterkeyFile`, checked against the image). Only the
//   settings with no file form arrive in the environment, and `policy.ts` lists
//   exactly which (`SECRETS_IN_ENVIRONMENT`)
// - every app's ingress is internal, and the environment routes one app to
//   another by name inside it. The environment has a public IP, but an app is
//   only ever public because a door below says so (G2e), never by accident
// - the apps scale as the environment allows, within two limits: the API scales
//   as its role (AGENTX_ROLE all, as here, holds the jobs: one copy; policy.ts),
//   Zitadel runs two to four copies in production and one on staging, each
//   copy's ten database connections counted (SA3a), and staging keeps
//   no replica at all while nothing runs (ADR-002), unless the operator deploys
//   with `apps --keep-running` for a while
// - manual trigger only: no *job* here runs on a clock or an event. The set-up
//   job holds the server admin's login, and Microsoft treats permission to
//   start a job as permission to use its secrets, so CI may start the
//   migration job alone (G4-2b, after the apps below)
// - one replica per run and no automatic retry: the work is one replica's, two of
//   them would race, and a retry would hide why the first attempt failed.
//   Container Apps has no lock between runs, so runs are started one at a time
//   and each log read before the next (Azure.md "The jobs"); the set-up job is
//   safe to run again in any case, and the migration runner takes the database's
//   own lock
// - every image is named by digest (SEC-SC-02): ours by the digest the deploying
//   shell gives, which `deploy/image/verify.ts` has checked a signature for
//   (G4), and Zitadel's two by the same pinned references the compose stack runs
//   (`tooling/checks/images.test.ts` keeps them equal)
import {
  appKeys
  appName
  appsPrefix
  doorName
  identityName
  jobName
  networkAddressSpace
  operatorHolds
  operatorOnly
  publicHalves
  releaseRoleName
  resourceNames
  resourceTags
  restoreHolds
  shortName
  uniqueSuffix
  workloads
} from 'names.bicep'
import { anchorContainerName, evidenceAccountName, evidenceContainerName } from 'modules/evidence.bicep'
import { activityDownloadsAccountName, activityDownloadsContainerName } from 'modules/activity-downloads.bicep'

targetScope = 'resourceGroup'

@description('Which environment this is.')
@allowed([
  'staging'
  'production'
])
param environment string

@description('The region every resource is in: UAE deployments use uaenorth (ADR-009).')
param location string

@description('The suffix main.bicep was deployed with, so the vault, the server and the identities match.')
@minLength(4)
@maxLength(6)
param nameSuffix string = uniqueSuffix(subscription().id)

@description('Where our own image is published (Product-Documentation/Container-Image.md), without a tag or digest.')
param appImageRepository string

@description('The digest of our image, as `sha256:` and 64 hex characters: a digest and never a tag, so the deployment can only run the exact image CI signed.')
@minLength(71)
@maxLength(71)
param appImageDigest string

@description('The build these jobs are, named on every log line (AGENTX_RELEASE): the commit our image was built from.')
@minLength(1)
@maxLength(64)
param release string

@description('Zitadel\'s image, pinned by digest, the same reference the compose stack runs.')
param zitadelImage string

@description('Zitadel\'s login pages, a second image of the same version, pinned by digest, the same reference the compose stack runs.')
param zitadelLoginImage string

@description('The host name Zitadel is served on, which its first instance is created with. The domain never sits in this repository (Rule Book §7).')
@minLength(4)
param authHost string

@description('The host name the API is served on, which it takes as its one public origin (SEC-WEB-01). The domain never sits in this repository (Rule Book §7).')
@minLength(4)
param appHost string

@description('The API\'s client ID in Zitadel (B2-6), which Zitadel gave when the API was registered with it as a confidential web client; its secret is in the vault (api-oidc-client-secret). Visible ASCII, as the API\'s config takes it.')
@minLength(1)
@maxLength(255)
param apiOidcClientId string

@description('The payment partner the API talks to (ADR-014 §4, AGENTX_PARTNER_MODE): `fake` in staging, over its own records in the database, until the adapter for the partner is built. The API refuses `fake` in production, and anything not yet built anywhere.')
@allowed(['fake', 'sandbox', 'live'])
param partnerMode string

@description('How many replicas of each app keep running with no traffic. Staging scales to zero (ADR-002): nothing is billed while nothing runs, at the cost of a cold start on the first request. The deploy tool sets 1 for `apps --keep-running`.')
@minValue(0)
@maxValue(1)
param appMinReplicas int

@description('The first Zitadel admin\'s email address, the only way in before anyone else exists. No mail is sent: nothing in the UAE deployment has an SMTP server, so the address is marked verified and the password comes from the vault.')
@minLength(6)
param zitadelAdminEmail string

@description('Whether this is the load test\'s run (D2c, PL-38): the API at the size it is measured at, its limits out of the way and email off, and the load test\'s three jobs. The deploy tool sets it for `apps --load-run` alone, so a plain `apps` puts the API back.')
param loadRun bool

@description('Where the load test\'s image is published (D2c), without a tag or digest.')
param loadImageRepository string

@description('The digest of the load test\'s image for the same commit as ours, which `deploy/image/verify.ts` has checked a signature for; empty unless `loadRun`.')
@maxLength(71)
param loadImageDigest string

@description('Stage G\'s throwaway copy of staging\'s database (4D2e, tooling/load/throwaway.ts), by its host: `psql-agentx-stg-g-<8 lower-case letters or digits>.postgres.database.azure.com`, which `apps --load-run --load-database <name>` alone sets and checks; empty otherwise. Read only in a load run: the API, its jobs app and the load jobs then reach that copy and keep its anchors in its own container, never staging\'s.')
@maxLength(80)
param loadDatabaseHost string = ''

@description('The anchor key\'s public halves, `<version>:<key>` comma-separated, as the API\'s `api.starting` line shows them (4D2e E9): the operator checks the anchors\' store with them alone. Empty until set: a chain recovery plan is then refused.')
@maxLength(1000)
param anchorPublicKeys string = ''

@description('The anchors\' epoch (AGENTX_ANCHOR_EPOCH): raised by one only for a sanctioned restore of the whole database. One value for the app that holds the jobs, which signs for it, and the operator, which reads it (4D2e E9).')
@minValue(1)
@maxValue(1000000)
param anchorEpoch int = 1

@description('How many `web` copies production\'s API runs beside its jobs (4D2e D13), counted against its server by policy.ts `connections`. Staging\'s load run always runs three (`loadWebCopies`), the size it is measured at.')
@minValue(1)
@maxValue(10)
param webCopies int = 3

@description('The most Zitadel copies production runs (SA3a): two always, more as its traffic asks, each holding its own database connections, which policy.ts `connections` counts. Read in production alone: staging keeps one.')
@minValue(2)
@maxValue(4)
param zitadelMostCopies int = 4

@description('The most copies of Zitadel\'s login pages production runs (SA3c): two always, more as its traffic asks. Read in production alone: staging keeps one.')
@minValue(2)
@maxValue(4)
param loginMostCopies int = 4

var names = resourceNames(environment, nameSuffix)

// The login pages' copies (SA3c). None of their state is one copy's, read from
// the pinned image itself: a sign-in's sessions are in the browser's cookies
// and its request in the address, Next's server-action key is built into the
// image, and the system user's key is the one mounted file. Production runs two
// always, so sign-in outlives a copy, and up to `loginMostCopies`, at the size
// staging runs; staging keeps one, scaling to zero (`appMinReplicas`).
var loginScale = environment == 'production'
  ? {
      minReplicas: 2
      maxReplicas: loginMostCopies
    }
  : {
      minReplicas: appMinReplicas
      maxReplicas: 1
    }

// Zitadel's copies and size (SA3a). None of its state is one copy's, read from
// the pinned image itself: its memory cache is off and the caches it uses are
// in Postgres, each projection takes a Postgres lock before it writes, and every
// copy mounts the one master key. Production runs two always, so sign-in
// outlives a copy, and up to `zitadelMostCopies`, at 1 vCPU and 2 GiB each.
// Staging keeps one at the smallest pair the Consumption profile offers above
// its minimum, as the jobs take, scaling to zero (`appMinReplicas`): its
// server's 35 user connections hold no second pool.
var zitadelScale = environment == 'production'
  ? {
      minReplicas: 2
      maxReplicas: zitadelMostCopies
      cpu: '1'
      memory: '2Gi'
    }
  : {
      minReplicas: appMinReplicas
      maxReplicas: 1
      cpu: '0.5'
      memory: '1Gi'
    }

// Where the API runs as `web` copies beside one `jobs` app (4D2e D13): production,
// and staging's load run. Out of one, staging keeps a single API at AGENTX_ROLE
// all (unset), holding the jobs and scaling to zero, so a quiet staging costs
// nothing more (StageD-Design: a `jobs` app on staging would pass the $60 alarm).
var split = loadRun || environment == 'production'

// Stage G's run on its throwaway copy (4D2e; tooling/load/throwaway.ts): only in
// a load run, so a plain apps can never carry it. The copy is a restore of
// staging's server in the same subnet and private zone; the API, its jobs app
// and the load jobs reach it, every other job staging's own server. Its anchors
// go to a container of its own (`throwawayAnchors`): the copy holds staging's
// organisations, so its anchors in staging's container would read to staging as
// chains wound back, a false tamper alarm there.
var throwaway = loadRun && !empty(loadDatabaseHost)
var appDatabaseHost = throwaway ? loadDatabaseHost : names.databaseHost
var throwawayAnchorsName = 'audit-anchors-g-${last(sys.split(first(sys.split(loadDatabaseHost, '.')), '-'))}'

// The restore drill's copy (S78): a point-in-time restore made under this name,
// in the same subnet and private zone, which the operator's restore check reads
// beside the live server; it exists only while a drill runs. Named here, as
// names.bicep's serverName would with the suffix 'drill', not there: every hand
// deploy reads names.bicep, so a change there asks for all four.
var drillDatabaseHost = 'psql-agentx-${shortName(environment)}-drill.postgres.database.azure.com'
var tags = resourceTags(environment)

// Our own image, which can only be a digest: `appImageDigest` is separate from
// the repository so that no run can pass a tag in its place.
var appImage = '${appImageRepository}@${appImageDigest}'

// Where each job's mounted secrets appear. Outside /app, which holds the code.
var secretsPath = '/mnt/secrets'
var secretsVolume = 'secrets'

// Each identity's resource id, by the workload it belongs to.
var identityIds = toObject(
  workloads,
  workload => workload,
  workload => resourceId('Microsoft.ManagedIdentity/userAssignedIdentities', identityName(environment, workload))
)

// The environment the foundation created (G2b). Read as an existing resource
// rather than by id alone, because an app with internal ingress answers at
// `<name>.internal.<the environment's default domain>`, and that domain is
// Azure's to give: it can't be written down here.
resource appsEnvironment 'Microsoft.App/managedEnvironments@2026-01-01' existing = {
  name: names.appsEnvironment
}

var appsEnvironmentId = appsEnvironment.id

// Where the login pages reach Zitadel: inside the environment, never out and
// back in through a public door. The ingress is https, which the platform's own
// certificate serves, and peer-to-peer encryption covers it besides (G2b).
var zitadelInternalUrl = 'https://${appName(environment, 'zitadel')}.internal.${appsEnvironment.properties.defaultDomain}'

// Where the load test's traffic goes (D2c): the API inside the environment, as
// Zitadel is reached, never out and back in through the public door.
var loadApiSetting = {
  name: 'AGENTX_LOAD_API'
  value: 'https://${appName(environment, 'api')}.internal.${appsEnvironment.properties.defaultDomain}'
}

// Email (B5-3): the foundation's Communication Services and the domain it
// sends from (communication.bicep). Azure names both: the service's host, in
// its data location's geography, and the domain's, a GUID under azurecomm.net.
resource communication 'Microsoft.Communication/communicationServices@2026-03-18' existing = {
  name: names.communication
}

resource emailService 'Microsoft.Communication/emailServices@2026-03-18' existing = {
  name: names.emailService
}

resource emailDomain 'Microsoft.Communication/emailServices/domains@2026-03-18' existing = {
  parent: emailService
  name: 'AzureManagedDomain'
}

var emailEndpoint = 'https://${communication.properties.hostName}'

// The API's one origin to call out to when it sends no email (the load run):
// Zitadel inside the environment, for sign-in.
var zitadelOrigins = [
  {
    name: 'AGENTX_OUTBOUND_ALLOWED_ORIGINS'
    value: zitadelInternalUrl
  }
]

// What an app that sends the admins' notices is told (B5-3), known only once
// the deployment reads the email resources, so added to its container
// alone, as Zitadel's address is: the two origins it may call out to, where
// each notice is sent, and the address it is sent from, Azure's own
// domain's DoNotReply. The API is the one app that both reaches Zitadel
// inside the environment and sends email, so its allowlist lives here: an app
// that reached Zitadel without sending email would need its own.
var emailSettings = [
  {
    name: 'AGENTX_OUTBOUND_ALLOWED_ORIGINS'
    value: '${zitadelInternalUrl},${emailEndpoint}'
  }
  {
    name: 'AGENTX_EMAIL_ENDPOINT'
    value: emailEndpoint
  }
  {
    name: 'AGENTX_EMAIL_SENDER'
    value: 'DoNotReply@${emailDomain.properties.mailFromSenderDomain}'
  }
]

// What every container of ours is told, wherever it runs: which environment
// this is, which build it is, and where the database is. Each job adds the
// role it logs in as and the file its login is in.
func ourSettingsOn(environment string, release string, host string) array => [
  {
    name: 'AGENTX_ENV'
    value: environment
  }
  {
    name: 'AGENTX_RELEASE'
    value: release
  }
  {
    name: 'AGENTX_DB_HOST'
    value: host
  }
  {
    name: 'AGENTX_DB_NAME'
    value: 'agentx'
  }
]

var ourSettings = ourSettingsOn(environment, release, names.databaseHost)

// The same for the API, its jobs app and the load jobs: on Stage G's copy in its
// run, staging's own server otherwise.
var appOurSettings = ourSettingsOn(environment, release, appDatabaseHost)

// Zitadel's own connection, as its own role and as its own "admin": the role and
// the database exist before it runs (db-setup makes them), so Zitadel never
// holds the server admin's login. TLS is checked to the host name (names.bicep)
// against the image's own trusted roots: Zitadel refuses verify-full without a
// root certificate setting (the first real run, S19), and its driver (pgx
// v5.9.2) reads `system` as the operating system's pool, which in the pinned
// image holds the roots Azure's server certificates chain to. The compose stack
// has no TLS and so says `disable` there.
var zitadelDatabase = [
  {
    name: 'ZITADEL_DATABASE_POSTGRES_HOST'
    value: names.databaseHost
  }
  {
    name: 'ZITADEL_DATABASE_POSTGRES_PORT'
    value: '5432'
  }
  {
    name: 'ZITADEL_DATABASE_POSTGRES_DATABASE'
    value: 'zitadel'
  }
  {
    name: 'ZITADEL_DATABASE_POSTGRES_USER_USERNAME'
    value: 'zitadel'
  }
  {
    name: 'ZITADEL_DATABASE_POSTGRES_USER_PASSWORD'
    secretRef: 'db-zitadel-password'
  }
  {
    name: 'ZITADEL_DATABASE_POSTGRES_USER_SSL_MODE'
    value: 'verify-full'
  }
  {
    name: 'ZITADEL_DATABASE_POSTGRES_USER_SSL_ROOTCERT'
    value: 'system'
  }
  {
    name: 'ZITADEL_DATABASE_POSTGRES_ADMIN_USERNAME'
    value: 'zitadel'
  }
  {
    name: 'ZITADEL_DATABASE_POSTGRES_ADMIN_PASSWORD'
    secretRef: 'db-zitadel-password'
  }
  {
    name: 'ZITADEL_DATABASE_POSTGRES_ADMIN_SSL_MODE'
    value: 'verify-full'
  }
  {
    name: 'ZITADEL_DATABASE_POSTGRES_ADMIN_SSL_ROOTCERT'
    value: 'system'
  }
  {
    name: 'ZITADEL_DATABASE_POSTGRES_ADMIN_EXISTINGDATABASE'
    value: 'zitadel'
  }
]

// How Zitadel tells its processes apart in the IDs it makes (the first real
// setup run, S19). Its defaults are the container's private address, which a
// Container Apps replica doesn't have in the ranges Zitadel counts as private,
// and then Google Cloud's metadata server, a call out that can only fail here;
// with both failing, setup panicked. Every replica and job run has a hostname
// of its own, which Zitadel hashes to the 16 bits it needs.
var zitadelMachine = [
  {
    name: 'ZITADEL_MACHINE_IDENTIFICATION_PRIVATEIP_ENABLED'
    value: 'false'
  }
  {
    name: 'ZITADEL_MACHINE_IDENTIFICATION_HOSTNAME_ENABLED'
    value: 'true'
  }
  {
    name: 'ZITADEL_MACHINE_IDENTIFICATION_WEBHOOK_ENABLED'
    value: 'false'
  }
]

// What Zitadel writes, and what it must not send anywhere (ADR-013,
// SEC-DATA-08): JSON lines at info level, which the workspace collects; no
// daily report to zitadel.com (it carries every instance's domains and counts)
// and no metrics endpoint.
var zitadelLogging = [
  {
    name: 'ZITADEL_LOG_LEVEL'
    value: 'info'
  }
  {
    name: 'ZITADEL_LOG_FORMATTER_FORMAT'
    value: 'json'
  }
  {
    name: 'ZITADEL_SERVICEPING_ENABLED'
    value: 'false'
  }
  {
    name: 'ZITADEL_METRICS_TYPE'
    value: 'none'
  }
  // Tracing. G2d-1 left it out because `init` never reads it; it goes on every
  // Zitadel container now that the server runs, so that one list says what all
  // of them do about telemetry and the rule can check every one the same way.
  // Its accepted values are "otel", "google", "log" and "none", read off the
  // defaults the pinned image carries; "none" is already the default, and is
  // said here so that a later version's default can't quietly export a trace.
  {
    name: 'ZITADEL_TRACING_TYPE'
    value: 'none'
  }
  // The same image marks the three settings above ZITADEL_TRACING_TYPE
  // deprecated in favour of an `Instrumentation` family, whose exporters each
  // offer an "auto" mode that follows the standard OTEL_* variables. Every one
  // of them is "none" by default today, and said outright here so that the
  // version that stops reading the deprecated settings changes nothing
  // (ADR-013, SEC-DATA-08).
  {
    name: 'ZITADEL_INSTRUMENTATION_TRACE_EXPORTER_TYPE'
    value: 'none'
  }
  {
    name: 'ZITADEL_INSTRUMENTATION_METRIC_EXPORTER_TYPE'
    value: 'none'
  }
  {
    name: 'ZITADEL_INSTRUMENTATION_LOG_EXPORTER_TYPE'
    value: 'none'
  }
]

// How Zitadel is reached, which its first instance is created with: the ingress
// terminates TLS, so the outside address is https on 443 and Zitadel itself
// serves plain http behind it.
var zitadelAddress = [
  {
    name: 'ZITADEL_EXTERNALDOMAIN'
    value: authHost
  }
  {
    name: 'ZITADEL_EXTERNALPORT'
    value: '443'
  }
  {
    name: 'ZITADEL_EXTERNALSECURE'
    value: 'true'
  }
  {
    name: 'ZITADEL_TLS_ENABLED'
    value: 'false'
  }
]

// The instance Zitadel's setup creates, once: one organisation, one human admin
// and nothing else. No machine user with a token, which the compose stack makes
// for its tests. The starting password comes from the vault and must be changed
// at the first sign-in, so nobody keeps it; Zitadel's own default (a password
// in its source) never applies, because ours is always given.
var zitadelFirstInstance = [
  {
    name: 'ZITADEL_FIRSTINSTANCE_INSTANCENAME'
    value: 'Agent X ${environment}'
  }
  {
    name: 'ZITADEL_FIRSTINSTANCE_ORG_NAME'
    value: 'Agent X'
  }
  {
    name: 'ZITADEL_FIRSTINSTANCE_ORG_HUMAN_USERNAME'
    value: 'admin'
  }
  {
    name: 'ZITADEL_FIRSTINSTANCE_ORG_HUMAN_PASSWORD'
    secretRef: 'zitadel-admin-password'
  }
  {
    name: 'ZITADEL_FIRSTINSTANCE_ORG_HUMAN_PASSWORDCHANGEREQUIRED'
    value: 'true'
  }
  {
    name: 'ZITADEL_FIRSTINSTANCE_ORG_HUMAN_EMAIL_ADDRESS'
    value: zitadelAdminEmail
  }
  {
    name: 'ZITADEL_FIRSTINSTANCE_ORG_HUMAN_EMAIL_VERIFIED'
    value: 'true'
  }
]

// The rules every organisation in the instance starts with, which setup writes
// once (ADR-003 §2, ADR-005): a second factor for everyone, passkeys offered,
// no skipping, no self-registration and no outside identity provider.
var zitadelPolicy = [
  {
    name: 'ZITADEL_DEFAULTINSTANCE_LOGINPOLICY_FORCEMFA'
    value: 'true'
  }
  {
    name: 'ZITADEL_DEFAULTINSTANCE_LOGINPOLICY_ALLOWREGISTER'
    value: 'false'
  }
  {
    name: 'ZITADEL_DEFAULTINSTANCE_LOGINPOLICY_ALLOWEXTERNALIDP'
    value: 'false'
  }
  {
    name: 'ZITADEL_DEFAULTINSTANCE_LOGINPOLICY_PASSWORDLESSTYPE'
    value: '1'
  }
  {
    name: 'ZITADEL_DEFAULTINSTANCE_LOGINPOLICY_MFAINITSKIPLIFETIME'
    value: '0h'
  }
  {
    name: 'ZITADEL_DEFAULTINSTANCE_RESTRICTIONS_DISALLOWPUBLICORGREGISTRATION'
    value: 'true'
  }
]

// The request the operator's job holds (B1c): what its next run is to do, as the
// command's own arguments in JSON. A run started with arguments of its own
// loses every mounted file (the start API takes no mounts), its login and key
// among them, and keeps those arguments in the run's record. So the person
// starting a run writes this secret first (deploy/azure/operator.ts), the run reads it as a
// file, and a read of the job never shows its value. Deployed as no request,
// which the command refuses, so a deployment of the apps clears any request
// left behind; one run again meanwhile changes nothing, since it names the
// organisation it makes and the directory refuses a second (apps/operator).
var operatorRequest = {
  name: 'operator-request'
  value: '[]'
}

// Where the operator writes an audit export (ADR-005 §6, E10c): the store's exports
// container, named as modules/evidence.bicep names it for the foundation, and
// the operator identity's client ID, which it asks Azure for a token as. Added
// in the job's own body, as `emailSettings` is in an app's: the client ID is
// read from Azure at deployment, which a loop's list can't hold.
resource operatorIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: identityName(environment, 'operator')
}

var evidenceSettings = [
  {
    name: 'AGENTX_EVIDENCE_CONTAINER_URL'
    value: 'https://${evidenceAccountName(shortName(environment), nameSuffix)}.blob.${az.environment().suffixes.storage}/${evidenceContainerName()}'
  }
  {
    name: 'AGENTX_EVIDENCE_CLIENT_ID'
    value: operatorIdentity.properties.clientId
  }
]

// Where the API keeps the activity log's background downloads (Phase 3 L5c,
// decision 31): the store's one container, named as modules/activity-downloads.bicep
// names it for the foundation, and the API identity's client ID, which it asks
// Azure for a token as (Azure sets IDENTITY_ENDPOINT in a container with an
// identity). Added in the app's own body, as `evidenceSettings` is in a job's.
resource apiIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: identityName(environment, 'api')
}

// The API's jobs' own identity, where they run apart from it (4D2e D13): read only
// then, so an apps run with no jobs app never asks Azure for it (it may not exist yet).
resource jobsIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = if (split) {
  name: identityName(environment, 'jobs')
}

var activityDownloadsUrl = 'https://${activityDownloadsAccountName(shortName(environment), nameSuffix)}.blob.${az.environment().suffixes.storage}/${activityDownloadsContainerName()}'

// A `web` copy hands a download out and the jobs build it, so both are told
// (4D2e D13), each as its own identity. Kept apart, and chosen by a condition
// (ARM evaluates only the branch taken), so a deployment with no `jobs` app never
// reads the jobs' identity: an apps run before the foundation has made it works.
var apiDownloadsSettings = [
  {
    name: 'AGENTX_ACTIVITY_DOWNLOADS_URL'
    value: activityDownloadsUrl
  }
  {
    name: 'AGENTX_ACTIVITY_DOWNLOADS_CLIENT_ID'
    value: apiIdentity.properties.clientId
  }
]

var jobsDownloadsSettings = [
  {
    name: 'AGENTX_ACTIVITY_DOWNLOADS_URL'
    value: activityDownloadsUrl
  }
  {
    name: 'AGENTX_ACTIVITY_DOWNLOADS_CLIENT_ID'
    value: jobsIdentity!.properties.clientId
  }
]

// The anchors' epoch, the same setting for the app that holds the jobs and the
// operator, so a plan reads the files those jobs write (4D2e E9; the policy's
// `anchor-epoch` holds them equal).
var anchorEpochSetting = {
  name: 'AGENTX_ANCHOR_EPOCH'
  value: string(anchorEpoch)
}

var anchorsUrl = 'https://${evidenceAccountName(shortName(environment), nameSuffix)}.blob.${az.environment().suffixes.storage}/${anchorContainerName()}'

// Stage G's copy keeps its anchors here (`throwaway`), made with the run below.
var throwawayAnchorsUrl = 'https://${evidenceAccountName(shortName(environment), nameSuffix)}.blob.${az.environment().suffixes.storage}/${throwawayAnchorsName}'

// Where the app that holds the jobs keeps the audit chains' anchors (4D2e E,
// PL-58; D13): the write-once store's second container, as its own identity.
// Kept apart by identity as the downloads' settings are.
var apiAnchorSettings = [
  anchorEpochSetting
  {
    name: 'AGENTX_AUDIT_ANCHORS_URL'
    value: anchorsUrl
  }
  {
    name: 'AGENTX_AUDIT_ANCHORS_CLIENT_ID'
    value: apiIdentity.properties.clientId
  }
]

var jobsAnchorSettings = [
  anchorEpochSetting
  {
    name: 'AGENTX_AUDIT_ANCHORS_URL'
    value: throwaway ? throwawayAnchorsUrl : anchorsUrl
  }
  {
    name: 'AGENTX_AUDIT_ANCHORS_CLIENT_ID'
    value: jobsIdentity!.properties.clientId
  }
]

// Where the operator reads the chains' anchors for a chain recovery plan (4D2e
// E9) and adds a chain's rebase (E11), and the chain repair reads them (E10):
// the same container, each as its own identity, the operator's able to add a new
// file and the chain repair's only to read (modules/evidence.bicep), and the
// public keys the lines are checked with.
var operatorAnchorSettings = concat(
  [
    anchorEpochSetting
    {
      name: 'AGENTX_AUDIT_ANCHORS_URL'
      value: anchorsUrl
    }
    {
      name: 'AGENTX_AUDIT_ANCHORS_CLIENT_ID'
      value: operatorIdentity.properties.clientId
    }
  ],
  empty(anchorPublicKeys)
    ? []
    : [
        {
          name: 'AGENTX_AUDIT_ANCHOR_PUBLIC_KEYS'
          value: anchorPublicKeys
        }
      ]
)

// The chain repair's request (4D2e E10), held as the operator's is and for the
// same reasons: written before a run, a JSON list of the command's words,
// deployed as no request, which the command refuses.
var restoreRequest = {
  name: 'chain-restore-request'
  value: '[]'
}

// Where the chain repair writes its records and reads the anchors (4D2e E10):
// the operator's two stores, as its own identity, which holds the two roles the
// operator does there (modules/evidence.bicep). Its client ID comes from Azure.
resource restorerIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: identityName(environment, 'chain-restore')
}

var restoreStoreSettings = concat(
  [
    {
      name: 'AGENTX_EVIDENCE_CONTAINER_URL'
      value: 'https://${evidenceAccountName(shortName(environment), nameSuffix)}.blob.${az.environment().suffixes.storage}/${evidenceContainerName()}'
    }
    {
      name: 'AGENTX_EVIDENCE_CLIENT_ID'
      value: restorerIdentity.properties.clientId
    }
    anchorEpochSetting
    {
      name: 'AGENTX_AUDIT_ANCHORS_URL'
      value: 'https://${evidenceAccountName(shortName(environment), nameSuffix)}.blob.${az.environment().suffixes.storage}/${anchorContainerName()}'
    }
    {
      name: 'AGENTX_AUDIT_ANCHORS_CLIENT_ID'
      value: restorerIdentity.properties.clientId
    }
  ],
  empty(anchorPublicKeys)
    ? []
    : [
        {
          name: 'AGENTX_AUDIT_ANCHOR_PUBLIC_KEYS'
          value: anchorPublicKeys
        }
      ]
)

// Every job: the work it does (its identity and its name come from that), the
// image and command, how long one run may take, what it reads as a mounted file
// with the setting that names each file, what it holds itself rather than reads
// from the vault (only the operator's request), its settings, and whether it
// writes to the evidence store (`evidenceSettings`). `secretRef`
// entries in `settings` name a secret too; `policy.ts` checks that the secrets a
// job is given are exactly the ones `GRANTS` says it reads, however they reach
// it, and what it may hold (`HELD`). A job runs as its own identity unless it
// says `runsAs` (the load test's), and at the smallest size unless it says `cpu`.
var jobs = concat([
  {
    // The roles and databases of a server, as the server admin (G2a). Safe to
    // run again, and run again on every deployment.
    workload: 'db-setup'
    image: appImage
    command: ['node', 'apps/db-setup/src/main.ts']
    args: []
    timeoutSeconds: 900
    evidence: false
    files: [
      {
        reads: 'db-admin-password'
        setting: 'AGENTX_DB_ADMIN_PASSWORD_FILE'
      }
      {
        reads: 'db-owner-password'
        setting: 'AGENTX_DB_OWNER_PASSWORD_FILE'
      }
      {
        reads: 'db-app-password'
        setting: 'AGENTX_DB_APP_PASSWORD_FILE'
      }
      {
        reads: 'db-backup-password'
        setting: 'AGENTX_DB_BACKUP_PASSWORD_FILE'
      }
      {
        reads: 'db-operator-password'
        setting: 'AGENTX_DB_OPERATOR_PASSWORD_FILE'
      }
      {
        reads: 'db-zitadel-password'
        setting: 'AGENTX_DB_ZITADEL_PASSWORD_FILE'
      }
    ]
    held: []
    settings: concat(ourSettings, [
      {
        name: 'AGENTX_DB_ADMIN_USER'
        value: 'agentx_admin'
      }
      {
        name: 'AGENTX_DB_ADMIN_DATABASE'
        value: 'postgres'
      }
    ])
  }
  {
    // db/migrations, as the owner role and never from inside the app (ADR-001).
    workload: 'migrate'
    image: appImage
    command: ['node', 'apps/migrate/src/main.ts']
    args: []
    timeoutSeconds: 900
    evidence: false
    files: [
      {
        reads: 'db-owner-password'
        setting: 'AGENTX_DB_MIGRATION_PASSWORD_FILE'
      }
    ]
    held: []
    settings: ourSettings
  }
  {
    // Zitadel's own schemas in its own database (ADR-003), as its own role.
    workload: 'zitadel-init'
    image: zitadelImage
    command: ['/app/zitadel']
    args: ['init', 'zitadel']
    timeoutSeconds: 900
    evidence: false
    files: []
    held: []
    settings: concat(zitadelDatabase, zitadelLogging, zitadelMachine)
  }
  {
    // Zitadel's setup steps: the first instance, its admin and the rules every
    // organisation starts with, encrypted with the master key. It runs once on a
    // new deployment and again after a Zitadel version upgrade.
    workload: 'zitadel-setup'
    image: zitadelImage
    command: ['/app/zitadel']
    // The master key from a file rather than the environment: `zitadel setup
    // --help` on the pinned image offers `--masterkeyFile`, and this key
    // encrypts every signing key and authenticator secret it writes.
    args: ['setup', '--masterkeyFile', '${secretsPath}/zitadel-masterkey']
    // Setup writes every step of a new instance, which takes longer than a
    // migration on the smallest server.
    timeoutSeconds: 1800
    evidence: false
    files: [
      {
        reads: 'zitadel-masterkey'
        // Named on the command line above, not by a setting.
        setting: ''
      }
    ]
    held: []
    settings: concat(zitadelDatabase, zitadelLogging, zitadelMachine, zitadelAddress, zitadelFirstInstance, zitadelPolicy)
  }
  {
    // The operator's command (B1c; ADR-011 §3), as its own role (PL-57) and no
    // other, holding the keys it needs and its own signing key: what it does, it
    // does through the same tenant walls as the API. It reads what it is asked from the request
    // it holds (above), never from a run's own arguments.
    workload: 'operator'
    image: appImage
    command: ['node', 'apps/operator/src/main.ts']
    args: ['--request', '${secretsPath}/${operatorRequest.name}']
    // One organisation and its two audit events take seconds, with every wait
    // for a chain's head bounded at 10 s (apps/operator); an audit export reads
    // up to 90 days of one organisation's log and names each actor first, so
    // it is given 15 minutes.
    timeoutSeconds: 900
    // Writes an audit export to the write-once store as its own identity (E10c).
    evidence: true
    // Reads the chains' anchors for a chain recovery plan (4D2e E9).
    readsAnchors: true
    files: concat(
      [
        {
          reads: 'db-operator-password'
          setting: 'AGENTX_DB_PASSWORD_FILE'
        }
      ],
      // Found by name in the folder AGENTX_KEYS_DIR names, as the API finds its keys.
      map(filter(appKeys, key => operatorHolds(key)), key => {
        reads: key
        setting: ''
      })
    )
    held: [operatorRequest]
    settings: concat(ourSettings, [
      {
        name: 'AGENTX_KEYS_DIR'
        value: secretsPath
      }
      {
        name: 'AGENTX_DB_USER'
        value: 'agentx_operator'
      }
      {
        // The restore drill's copy, which only the restore check reads, read-only (S78).
        name: 'AGENTX_DB_DRILL_HOST'
        value: drillDatabaseHost
      }
    ])
  }
  {
    // The chain repair (4D2e E10, PL-29; apps/operator/src/chain-restore-main.ts):
    // a recovery plan applied as the owner, the only job besides the migration
    // holding its login, so its every run sets off the owner-login SEV-1 alert,
    // by design. It holds the audit chains' MAC to check with and the operator's
    // public halves, never the operator's own key; it writes only original rows.
    workload: 'chain-restore'
    image: appImage
    command: ['node', 'apps/operator/src/chain-restore-main.ts']
    args: ['--request', '${secretsPath}/${restoreRequest.name}']
    // The plan read twice from both servers, then the whole chain checked in
    // its transaction: as long as a migration may take.
    timeoutSeconds: 1800
    // Writes its records and reads the anchors as its own identity (restoreStoreSettings).
    evidence: false
    restorerStores: true
    files: concat(
      [
        {
          reads: 'db-owner-password'
          setting: 'AGENTX_DB_PASSWORD_FILE'
        }
      ],
      // Found by name in the folder AGENTX_KEYS_DIR names, as the operator finds its keys.
      map(filter(appKeys, key => restoreHolds(key)), key => {
        reads: key
        setting: ''
      }),
      map(publicHalves, half => {
        reads: half
        setting: ''
      })
    )
    held: [restoreRequest]
    settings: concat(
      ourSettings,
      [
        {
          name: 'AGENTX_KEYS_DIR'
          value: secretsPath
        }
        {
          name: 'AGENTX_DB_USER'
          value: 'agentx_owner'
        }
        {
          // The drill's copy, read-only, which the repair takes original rows from.
          name: 'AGENTX_DB_DRILL_HOST'
          value: drillDatabaseHost
        }
      ]
    )
  }
], loadRun ? loadJobs : [], throwaway ? stageGJobs : [])

// The load test's run request (D2c): what changes from one run to the next (the
// run's ID, then its agents and phase 1's count), written onto each job by
// deploy/azure/load.ts before it starts one, as the operator's request is
// (above), and for the same reason: a run started with settings of its own
// loses every mounted file. Deployed as no request, which the jobs refuse.
var loadRequest = {
  name: 'load-request'
  value: '{}'
}

// What every load job shares: the load image by its digest, the database it
// reaches (Stage G's copy in its run, staging's own server otherwise) and where
// its request is.
var loadImage = '${loadImageRepository}@${loadImageDigest}'

var loadDatabaseSetting = {
  name: 'AGENTX_LOAD_DB_HOST'
  value: appDatabaseHost
}

var loadRequestSetting = {
  name: 'AGENTX_LOAD_REQUEST_FILE'
  value: '${secretsPath}/${loadRequest.name}'
}

// What a load job that sends traffic reads: the app's login, every key but the
// operator's own, and its public half instead (PL-57).
var loadFiles = concat(
  [
    {
      reads: 'db-app-password'
      setting: 'AGENTX_DB_PASSWORD_FILE'
    }
  ],
  map(filter(appKeys, key => !operatorOnly(key)), key => {
    reads: key
    setting: ''
  }),
  map(publicHalves, half => {
    reads: half
    setting: ''
  })
)

// The load test's three jobs (D2c, PL-38; tooling/load/job.ts), only with
// `loadRun`: seed and k6's phase 1, then new keys, k6's phase 2, the checks and
// the clean-up, and the clean-up alone for a run that stopped half-way. Each
// runs inside the network, where the database is, as the API's identity (no
// identity of its own, so no foundation or secrets deploy) and the app's role,
// with the app's keys and nothing else of the API's mounted; the identity could
// still be asked for every secret the API reads, which the partner accepted for
// the test day, the jobs deleted after it (S154, PL-61). The first two send the
// traffic, so they get k6's room: the API's size, so k6 is never what is
// measured. `callsApi` adds the API's internal address in the job's body, since
// Azure names the environment's domain.
var loadJobs = map(
  [
    {
      part: 'first'
      timeoutSeconds: 1800
      callsApi: true
    }
    {
      part: 'second'
      timeoutSeconds: 1800
      callsApi: true
    }
    {
      part: 'cleanup'
      timeoutSeconds: 900
      callsApi: false
    }
  ],
  load => {
    workload: 'load-${load.part}'
    runsAs: 'api'
    image: loadImage
    command: ['node', 'tooling/load/job.ts']
    args: [load.part]
    timeoutSeconds: load.timeoutSeconds
    cpu: load.callsApi ? '2' : '0.5'
    memory: load.callsApi ? '4Gi' : '1Gi'
    callsApi: load.callsApi
    evidence: false
    files: loadFiles
    held: [loadRequest]
    settings: concat(appOurSettings, [
      {
        name: 'AGENTX_KEYS_DIR'
        value: secretsPath
      }
      loadDatabaseSetting
      loadRequestSetting
    ])
  }
)

// Stage G's three jobs (4D2e; tooling/load/stageg-job.ts), only on its throwaway
// copy (`throwaway`), every one reaching that copy alone. Each refuses to start
// unless its host is a copy's by name, and the step and check unless the copy
// carries the sentinel naming it, which load-mark alone writes:
// - load-mark: the sentinel, as the copy's owner (a restore keeps staging's
//   passwords), as Stage G's own identity (names.bicep `loadWorkloads`, AZ3)
// - load-step: the seed's growth, or one step (its cohort, new keys, k6), as the
//   app with its keys, as the API's identity, as PL-38's jobs; one step a run,
//   up to the soak's full hour and its margin (stageg.ts STAGE_G_JOB_SECONDS)
// - load-check: the step's checks, past the tenant walls as the backup role
//   (stageg-checks.ts) and through them as the app, as Stage G's own identity,
//   which reads the owner's, the app's and the backup role's logins and no other
//   (secrets.bicep): never the server admin's, as the set-up job's does
// The step and check read their command from the run's request, held as
// PL-38's (`loadRequest`); the mark asks nothing.
var stageGJobs = [
  {
    workload: 'load-mark'
    runsAs: 'stage-g'
    image: loadImage
    command: ['node', 'tooling/load/stageg-job.ts']
    args: ['mark']
    timeoutSeconds: 900
    evidence: false
    files: [
      {
        reads: 'db-owner-password'
        setting: 'AGENTX_DB_PASSWORD_FILE'
      }
    ]
    held: []
    settings: concat(appOurSettings, [loadDatabaseSetting])
  }
  {
    workload: 'load-step'
    runsAs: 'api'
    image: loadImage
    command: ['node', 'tooling/load/stageg-job.ts']
    args: ['step']
    timeoutSeconds: 4500
    // k6's room, as PL-38's traffic jobs: the API's size, so k6 is never what is measured.
    cpu: '2'
    memory: '4Gi'
    callsApi: true
    evidence: false
    files: loadFiles
    held: [loadRequest]
    settings: concat(appOurSettings, [
      {
        name: 'AGENTX_KEYS_DIR'
        value: secretsPath
      }
      loadDatabaseSetting
      loadRequestSetting
    ])
  }
  {
    workload: 'load-check'
    runsAs: 'stage-g'
    image: loadImage
    command: ['node', 'tooling/load/stageg-job.ts']
    args: ['check']
    timeoutSeconds: 1800
    evidence: false
    files: [
      {
        reads: 'db-app-password'
        setting: 'AGENTX_DB_APP_PASSWORD_FILE'
      }
      {
        reads: 'db-backup-password'
        setting: 'AGENTX_DB_BACKUP_PASSWORD_FILE'
      }
    ]
    held: [loadRequest]
    settings: concat(appOurSettings, [loadDatabaseSetting, loadRequestSetting])
  }
]

// The API's limits in the load run (D2c), as the laptop's run sets them
// (tooling/load/compose.load.yaml): every client's, person's and agent's allowance
// far above what k6 sends, so what is measured is the API rather than a 429,
// and the log's cap at four times one, where the API's config needs twice.
var loadApiSettings = [
  {
    name: 'AGENTX_RATE_LIMIT_PER_MINUTE'
    value: '50000'
  }
  {
    name: 'AGENTX_RATE_LIMIT_PER_USER_PER_MINUTE'
    value: '50000'
  }
  {
    name: 'AGENTX_RATE_LIMIT_PER_AGENT_PER_MINUTE'
    value: '50000'
  }
  {
    name: 'AGENTX_RATE_LIMIT_PER_ORGANISATION_PER_MINUTE'
    value: '50000'
  }
  {
    name: 'AGENTX_LOG_EVENT_CAP_PER_MINUTE'
    value: '200000'
  }
  // The fair gate (4D2e C, PL-63), each copy its own (decision-gate.ts): eleven at once, as Stage G passed on Azure
  // (S179), so the target's 170 a second at ~0.1 s a decision fills about half of three copies' 33 (policy.ts holds it
  // at 60% or less, S177). One gate can't pass its pool's twelve; the waiting stay as measured.
  {
    name: 'AGENTX_DECISION_GATE_ACTIVE'
    value: '11'
  }
  {
    name: 'AGENTX_DECISION_GATE_PER_ORGANISATION'
    value: '2'
  }
  {
    name: 'AGENTX_DECISION_GATE_WAITING_PER_ORGANISATION'
    value: '34'
  }
  {
    name: 'AGENTX_DECISION_GATE_WAIT_MS'
    value: '10000'
  }
]

// The load run's split (4D2e D13; StageD-Design "Memory at N copies"): three `web`
// copies of twelve connections and one `jobs` of six (Stage G, S179).
var loadWebCopies = 3
var copies = loadRun ? loadWebCopies : webCopies

// What both apps that run the API read (4D2e D13): its login, and each of the
// app's keys (ADR-011 §2), which it finds by name in the folder AGENTX_KEYS_DIR
// names rather than one setting each; and the login service's tokens, which the
// `web` side signs out with and the jobs carry out resets with.
var apiFiles = concat(
  [
    {
      reads: 'db-app-password'
      setting: 'AGENTX_DB_PASSWORD_FILE'
    }
    {
      reads: 'api-oidc-client-secret'
      setting: 'AGENTX_OIDC_CLIENT_SECRET_FILE'
    }
  ],
  // B6-3c: Zitadel's token for removing a person's second factors once a reset
  // has cooled off, its own service user's (Org User Manager). Never on Stage G's
  // copy: it holds staging's resets, which the copy's jobs would carry out
  // against the real login service a second time.
  throwaway
    ? []
    : [
        {
          reads: 'zitadel-reset-token'
          setting: 'AGENTX_FACTOR_RESET_TOKEN_FILE'
        }
      ],
  // SA2b: who makes our own routine changes in the login service, and for whom
  // (AGENTX_IDP_OUR_*), from the vault alone, never a value here: the list tells
  // an attacker which accounts to aim at. The vault holds `none` for each until the
  // partner writes ours (deploy.ts), which leaves the feature off.
  [
    {
      reads: 'zitadel-our-actors'
      setting: 'AGENTX_IDP_OUR_ACTORS_FILE'
    }
    {
      reads: 'zitadel-our-service-users'
      setting: 'AGENTX_IDP_OUR_SERVICE_USERS_FILE'
    }
  ],
  // B5-3: the email service's key, copied in by the secrets deployment,
  // and Zitadel's read-only token for the admins' addresses. The four
  // email settings are all or none, so neither in the load run.
  loadRun
    ? []
    : [
        {
          reads: 'acs-access-key'
          setting: 'AGENTX_EMAIL_ACCESS_KEY_FILE'
        }
        {
          reads: 'zitadel-directory-token'
          setting: 'AGENTX_DIRECTORY_TOKEN_FILE'
        }
      ],
  // Every key but the operator's own, and their public halves instead (PL-57, E11).
  map(filter(appKeys, key => !operatorOnly(key)), key => {
    reads: key
    setting: ''
  }),
  map(publicHalves, half => {
    reads: half
    setting: ''
  })
)

var keysDirectorySetting = {
  name: 'AGENTX_KEYS_DIR'
  value: secretsPath
}

var appRoleSetting = {
  name: 'AGENTX_DB_USER'
  value: 'agentx_app'
}

// The one address a browser may send a change from (SEC-WEB-01). The
// app door (below) is what serves that host; the jobs put it in a notice's link.
var publicOriginSetting = {
  name: 'AGENTX_PUBLIC_ORIGIN'
  value: 'https://${appHost}'
}

// The proxy in front, so each client keeps its own rate limit and its own
// address in a security event rather than every client sharing the
// ingress's (ADR-011 §4). Microsoft: Envoy appends the client to
// X-Forwarded-For and "only the rightmost IP is provided by Azure
// Container Apps", so what is trusted is the subnet the ingress sits in.
// And the loopback address: the replica's own Envoy connects from
// 127.0.0.1 (S129, every activity log row on staging read 127.0.0.1, a
// GitHub runner's requests among them), and only something inside the
// replica can connect from there. The API's config asks for it wherever it is
// deployed, so the jobs, which nothing reaches, are told it too.
var trustedProxiesSetting = {
  name: 'AGENTX_TRUSTED_PROXIES'
  value: '127.0.0.1,${appsPrefix(networkAddressSpace)}'
}

// The login service (ADR-003 §5): its public address, which its tokens
// name, and the API's client ID there; then the payment partner (ADR-014 §4,
// Phase 1 D2-3a).
var signInAndPartnerSettings = [
  {
    name: 'AGENTX_OIDC_ISSUER'
    value: 'https://${authHost}'
  }
  {
    name: 'AGENTX_OIDC_CLIENT_ID'
    value: apiOidcClientId
  }
  {
    name: 'AGENTX_PARTNER_MODE'
    value: partnerMode
  }
]

// The API as `web` copies beside the `jobs` app (4D2e D13): each counts its share
// of every rate limit for the copies there are (rate-limit.ts, D12).
var webRoleSettings = [
  {
    name: 'AGENTX_ROLE'
    value: 'web'
  }
  {
    name: 'AGENTX_WEB_COPIES'
    value: string(copies)
  }
]

// The API's jobs apart from it (4D2e D13): their own pool, six in the load run
// (at least six: the hand-off's two transactions take at most a third of it),
// and the log's cap the load run's API has, since the jobs log for the same run.
var jobsRoleSettings = concat(
  [
    {
      name: 'AGENTX_ROLE'
      value: 'jobs'
    }
    {
      name: 'AGENTX_DB_JOBS_POOL_MAX'
      value: loadRun ? '6' : '10'
    }
  ],
  loadRun
    ? [
        {
          name: 'AGENTX_LOG_EVENT_CAP_PER_MINUTE'
          value: '200000'
        }
      ]
    : []
)

// The API's jobs, apart from it where it is split (4D2e D13): the same image and
// command at AGENTX_ROLE jobs, as its own identity. No ingress: it serves nothing,
// so nothing, a door or a neighbour, can reach it. One copy, always running:
// the lease alone doesn't make a second safe for the copier, and nothing would
// wake one scaled to zero. It reaches what the jobs reach: Zitadel inside the
// environment and the email endpoint, the downloads it builds and the anchors.
var jobsApp = {
  workload: 'jobs'
  image: appImage
  // As the API's heap (policy.ts): three quarters of its memory.
  command: ['node', '--max-old-space-size=${loadRun ? '1536' : '768'}', 'apps/api/src/main.ts']
  args: []
  zitadelSettings: ['AGENTX_OIDC_INTERNAL_ORIGIN']
  sendsEmail: !loadRun
  signsIn: true
  // Not on Stage G's copy: it holds staging's downloads under way, which its jobs
  // would write over in staging's container.
  keepsDownloads: !throwaway
  keepsAnchors: true
  minReplicas: 1
  maxReplicas: 1
  // As the API's: its runs end, then the lease is let go, within the stop deadline.
  stopSeconds: 30
  // Its jobs share no traffic's pace: half the API's load-run size is room enough.
  cpu: loadRun ? '1' : '0.5'
  memory: loadRun ? '2Gi' : '1Gi'
  files: apiFiles
  settings: concat(
    appOurSettings,
    [
      keysDirectorySetting
      appRoleSetting
      publicOriginSetting
      trustedProxiesSetting
    ],
    signInAndPartnerSettings,
    jobsRoleSettings
  )
}

// The API's size (AZ8b), its heap three quarters of its memory (policy.ts holds it
// between a half and three quarters): its rate limits' counters take up to about
// 92 MB, and Node's own default under 1 GiB is 560 MiB (4D2e D12, measured). The
// load run measures each copy at two CPUs (D2c). Production's copies run at 1 vCPU
// and 2 GiB, Cost-Model's smallest safe set-up: staging's one 0.5 vCPU copy misses
// probes under the weekly scan. Staging keeps the smallest pair the Consumption
// profile offers above its minimum, as the jobs take.
var apiSize = loadRun
  ? {
      cpu: '2'
      memory: '4Gi'
      heap: '3072'
    }
  : environment == 'production'
      ? {
          cpu: '1'
          memory: '2Gi'
          heap: '1536'
        }
      : {
          cpu: '0.5'
          memory: '1Gi'
          heap: '768'
        }

// The API's health checks (AZ8b), all three pinned, every timing given, so Azure
// adds no default of its own and gives back what this sends, as the release holds
// the live app to it (drift.ts). Startup and readiness are Azure's own defaults for
// an app with ingress, as Microsoft Learn's "Health probes in Azure Container Apps"
// lists them (read S189), so they behave as before. Liveness is a TCP connection to
// its port every 10 s, given 5 s, the copy restarted only after six misses in a row
// (a minute): a busy spell never restarts a copy that is only slow (staging's one
// 0.5 vCPU copy missed up to 18 a weekly scan, S188). Staging runs the same set, so
// its releases prove Azure echoes them back before production depends on it.
var apiProbes = [
  {
    type: 'Startup'
    tcpSocket: {
      port: 8080
    }
    initialDelaySeconds: 1
    periodSeconds: 1
    timeoutSeconds: 3
    successThreshold: 1
    failureThreshold: 240
  }
  {
    type: 'Readiness'
    tcpSocket: {
      port: 8080
    }
    initialDelaySeconds: 3
    periodSeconds: 5
    timeoutSeconds: 5
    successThreshold: 1
    failureThreshold: 48
  }
  {
    type: 'Liveness'
    tcpSocket: {
      port: 8080
    }
    initialDelaySeconds: 1
    periodSeconds: 10
    timeoutSeconds: 5
    successThreshold: 1
    failureThreshold: 6
  }
]

// The three apps that serve traffic (ADR-002 Amendment G2d), and the API's jobs
// apart from it where it is split (`jobsApp`). Each is shaped
// like a job above — the work it does, its image and command, what it reads as
// a mounted file, its settings — with what only something long-running has:
// the port it answers on and how many replicas may run.
//
// Every one that serves traffic has internal ingress. The environment has a public IP, but
// nothing here is a door: the doors are the route configs at the end of this
// file (G2e), so an app is only ever public because a door names it.
var apps = concat([
  {
    // The API (Product-Documentation/API.md), as the app role and no other.
    workload: 'api'
    image: appImage
    // Its heap as its size says (`apiSize`).
    command: ['node', '--max-old-space-size=${apiSize.heap}', 'apps/api/src/main.ts']
    args: []
    targetPort: 8080
    transport: 'auto'
    // Sign-in (B2-6): the API calls Zitadel inside the environment, as the
    // login pages do, naming the issuer's host in Zitadel's headers. That
    // internal address and the email endpoint (B5-3) are the two origins it
    // may call out to (AGENTX_OUTBOUND_ALLOWED_ORIGINS, `emailSettings`), and
    // the internal address alone in the load run (`zitadelOrigins`).
    zitadelSettings: ['AGENTX_OIDC_INTERNAL_ORIGIN']
    // The load run sends no email (D2c): its seeded admins have no address,
    // and each notice would end as a warning. Zitadel stays its one origin.
    sendsEmail: !loadRun
    signsIn: true
    // Keeps the activity log's background downloads (`apiDownloadsSettings`), but
    // on Stage G's copy, as its jobs app doesn't (`jobsApp`).
    keepsDownloads: !throwaway
    // Keeps the audit chains' anchors (`apiAnchorSettings`) where it holds the
    // jobs: out of a split. In one, the `jobs` app keeps them (4D2e D13).
    keepsAnchors: !split
    // AGENTX_ROLE all (unset) holds the jobs and counts its rate limits as the
    // only copy (4D2e D12): at most one, none while staging sleeps. A split's
    // `web` copies run exactly as many as they count their limits for (D13).
    minReplicas: split ? copies : appMinReplicas
    maxReplicas: split ? copies : 1
    // Longer than the API's own 25-second stop deadline (API.md), so the log's
    // held-back counts are still written.
    stopSeconds: 30
    cpu: apiSize.cpu
    memory: apiSize.memory
    probes: apiProbes
    files: apiFiles
    settings: concat(
      appOurSettings,
      [
        keysDirectorySetting
        {
          name: 'AGENTX_HTTP_HOST'
          value: '0.0.0.0'
        }
        {
          name: 'AGENTX_HTTP_PORT'
          value: '8080'
        }
        appRoleSetting
        publicOriginSetting
        trustedProxiesSetting
        // Ten of the server's 35 user connections, leaving Zitadel's ten, one for
        // each job, and room for the worker (ADR-002 Amendment G1). Twelve a copy on
        // the load run's larger server, three copies beside the jobs' six (4D2e
        // D13; Stage G S179): each organisation's agents may hold 30% of a copy's pool
        // (organisation-shares.ts). Production needs its own server's numbers
        // (Pre-Launch Checklist, PL-63), which the policy's `connections` counts.
        {
          name: 'AGENTX_DB_POOL_MAX'
          value: loadRun ? '12' : '10'
        }
      ],
      signInAndPartnerSettings,
      loadRun ? loadApiSettings : [],
      split ? webRoleSettings : []
    )
  }
  {
    // Zitadel itself, already set up by the two jobs above: this only starts it.
    workload: 'zitadel'
    image: zitadelImage
    command: ['/app/zitadel']
    // The master key from a file, as `setup` takes it: `zitadel start --help`
    // on the pinned image offers `--masterkeyFile` too.
    args: ['start', '--masterkeyFile', '${secretsPath}/zitadel-masterkey']
    targetPort: 8080
    // Zitadel serves gRPC beside HTTP on the one port, as it does on the
    // compose stack.
    transport: 'http2'
    zitadelSettings: []
    sendsEmail: false
    signsIn: false
    keepsDownloads: false
    keepsAnchors: false
    // Its copies and size by environment (`zitadelScale`, SA3a).
    minReplicas: zitadelScale.minReplicas
    maxReplicas: zitadelScale.maxReplicas
    stopSeconds: 30
    cpu: zitadelScale.cpu
    memory: zitadelScale.memory
    files: [
      {
        reads: 'zitadel-masterkey'
        // Named on the command line above, not by a setting.
        setting: ''
      }
      {
        reads: 'login-client-public-key'
        // Named by Path inside ZITADEL_SYSTEMAPIUSERS below.
        setting: ''
      }
    ]
    settings: concat(zitadelDatabase, zitadelLogging, zitadelMachine, zitadelAddress, [
      // The login pages' system user: the file its public half is in, and the
      // one role they need. `Path` rather than `KeyData`, so the key is read
      // from the mount and never sits in an environment — and because this is
      // one JSON setting holding the roles as well, which a secret reference
      // would have to replace whole. Proven on the compose stack (G2d-2a).
      {
        name: 'ZITADEL_SYSTEMAPIUSERS'
        value: '{"login-client":{"Path":"${secretsPath}/login-client-public-key","Memberships":[{"MemberType":"System","Roles":["IAM_LOGIN_CLIENT"]}]}}'
      }
    ])
  }
  {
    // Zitadel v4's login pages, a second container of the same version.
    workload: 'login'
    image: zitadelLoginImage
    command: []
    args: []
    targetPort: 3000
    transport: 'auto'
    // Nothing here is one copy's (SA3c): production runs two to four, as
    // Zitadel, and staging one (`loginScale`).
    minReplicas: loginScale.minReplicas
    maxReplicas: loginScale.maxReplicas
    stopSeconds: 30
    cpu: '0.5'
    memory: '1Gi'
    files: [
      {
        reads: 'login-client-private-key'
        setting: 'SYSTEM_USER_PRIVATE_KEY_FILE'
      }
    ]
    // ZITADEL_API_URL is added where the app is deployed, not here: the
    // environment's default domain is Azure's to give, and Bicep needs this
    // list settled before the deployment starts.
    zitadelSettings: ['ZITADEL_API_URL']
    sendsEmail: false
    signsIn: false
    keepsDownloads: false
    keepsAnchors: false
    settings: [
      // The host the browser uses, which Zitadel reads before the Host header
      // (ADR-003 Amendment S10), so the pages need no Host override here.
      {
        name: 'CUSTOM_REQUEST_HEADERS'
        value: 'x-zitadel-instance-host:${authHost},x-zitadel-public-host:${authHost}'
      }
      {
        name: 'AUDIENCE'
        value: 'https://${authHost}'
      }
      {
        name: 'SYSTEM_USER_ID'
        value: 'login-client'
      }
      {
        name: 'NEXT_PUBLIC_BASE_PATH'
        value: '/ui/v2/login'
      }
      // The pages carry an OpenTelemetry SDK that starts by default and exports
      // to an OTLP endpoint. Off, so nothing is gathered to be sent anywhere
      // (ADR-013).
      {
        name: 'OTEL_SDK_DISABLED'
        value: 'true'
      }
    ]
  }
], split ? [jobsApp] : [])

// Every secret a job is given, once each: the ones it reads as files and the
// ones its settings name.
func secretsOf(job object) array =>
  union(map(job.files, file => file.reads), map(filter(job.settings, setting => contains(setting, 'secretRef')), setting => setting.secretRef))

// The vault the foundation created, for the address Azure gave it rather than a
// domain written down here. No version in the URL: Container Apps picks up a new
// version within 30 minutes and restarts what reads it (Microsoft).
resource vault 'Microsoft.KeyVault/vaults@2025-05-01' existing = {
  name: names.vault
}

// Stage G's copy's own anchors (`throwaway`): a container of its own in the
// write-once store, beside staging's, and the anchors' role on it for the jobs
// app alone, which keeps them in a load run (4D2e D13), as modules/evidence.bicep
// gives staging's. Made with the run, never on a plain apps, and named from the
// copy's ID, so each copy starts with no anchors: one copy's would read to the
// next as chains wound back. The store keeps each file for its days (Unlocked on
// staging), so the container can be removed only once its last file's time is up.
resource evidenceStore 'Microsoft.Storage/storageAccounts@2025-01-01' existing = {
  name: evidenceAccountName(shortName(environment), nameSuffix)
}

resource evidenceBlobs 'Microsoft.Storage/storageAccounts/blobServices@2025-01-01' existing = {
  parent: evidenceStore
  name: 'default'
}

resource throwawayAnchors 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-01-01' = if (throwaway) {
  parent: evidenceBlobs
  name: throwawayAnchorsName
  properties: {
    publicAccess: 'None'
  }
}

// The anchors' custom role, as modules/evidence.bicep names it: add a new file, read and list; never overwrite or delete.
var anchorRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  guid(resourceGroup().id, 'audit-anchors')
)

resource throwawayAnchorsKept 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (throwaway) {
  scope: throwawayAnchors
  name: guid(throwawayAnchors.id, jobsIdentity.id, anchorRoleId)
  properties: {
    roleDefinitionId: anchorRoleId
    principalId: jobsIdentity!.properties.principalId
    principalType: 'ServicePrincipal'
    description: 'jobs keeps Stage G copy audit anchors (deploy/azure/apps.bicep)'
  }
}

resource deployedJobs 'Microsoft.App/jobs@2026-01-01' = [
  for job in jobs: {
    name: jobName(environment, job.workload)
    location: location
    tags: tags
    // Its own identity and no other, so it can read its own secrets alone.
    identity: {
      type: 'UserAssigned'
      userAssignedIdentities: {
        '${identityIds[job.?runsAs ?? job.workload]}': {}
      }
    }
    properties: {
      environmentId: appsEnvironmentId
      workloadProfileName: 'Consumption'
      configuration: {
        triggerType: 'Manual'
        replicaTimeout: job.timeoutSeconds
        replicaRetryLimit: 0
        // One replica does the work, and one finishing is success. Neither stops
        // two runs overlapping: nothing in Container Apps does.
        manualTriggerConfig: {
          parallelism: 1
          replicaCompletionCount: 1
        }
        // Read from the vault by the job's own identity, never a value held
        // here; then what the job holds itself, which is no secret (above).
        secrets: concat(
          map(secretsOf(job), secret => {
            name: secret
            keyVaultUrl: uri(vault.properties.vaultUri, 'secrets/${secret}')
            identity: identityIds[job.?runsAs ?? job.workload]
          }),
          job.held
        )
      }
      template: {
        containers: [
          {
            name: job.workload
            image: job.image
            command: job.command
            args: job.args
            // The smallest pair the Consumption profile offers above its
            // minimum, enough for a short Node or Go process, unless the job says its
            // own (the load test's, which send k6's traffic).
            resources: {
              cpu: json(job.?cpu ?? '0.5')
              memory: job.?memory ?? '1Gi'
            }
            env: concat(
              job.settings,
              map(filter(job.files, file => !empty(file.setting)), file => {
                name: file.setting
                value: '${secretsPath}/${file.reads}'
              }),
              job.evidence ? evidenceSettings : [],
              (job.?readsAnchors ?? false) ? operatorAnchorSettings : [],
              (job.?restorerStores ?? false) ? restoreStoreSettings : [],
              (job.?callsApi ?? false) ? [loadApiSetting] : []
            )
            volumeMounts: empty(concat(job.files, job.held))
              ? []
              : [
                  {
                    volumeName: secretsVolume
                    mountPath: secretsPath
                  }
                ]
          }
        ]
        volumes: empty(concat(job.files, job.held))
          ? []
          : [
              {
                name: secretsVolume
                storageType: 'Secret'
                // Named one by one: a secret volume with no list mounts every
                // secret the job has.
                secrets: concat(
                  map(job.files, file => {
                    secretRef: file.reads
                    path: file.reads
                  }),
                  map(job.held, held => {
                    secretRef: held.name
                    path: held.name
                  })
                )
              }
            ]
      }
    }
  }
]

resource deployedApps 'Microsoft.App/containerApps@2026-01-01' = [
  for app in apps: {
    name: appName(environment, app.workload)
    location: location
    tags: tags
    // Its own identity and no other, so it can read its own secrets alone.
    identity: {
      type: 'UserAssigned'
      userAssignedIdentities: {
        '${identityIds[app.workload]}': {}
      }
    }
    properties: {
      environmentId: appsEnvironmentId
      workloadProfileName: 'Consumption'
      configuration: {
        // Internal: reachable inside the environment only. The public doors are
        // the route configs (below), so no app is a door by accident. An app
        // that serves nothing (the API's jobs, 4D2e D13) has no ingress at all.
        ingress: app.?targetPort == null
          ? null
          : {
              external: false
              targetPort: app.targetPort
              transport: app.transport
              // Plain http is refused even inside the environment, which peer-to-peer
              // encryption already covers (G2b).
              allowInsecure: false
              traffic: [
                {
                  latestRevision: true
                  weight: 100
                }
              ]
            }
        // Read from the vault by the app's own identity, never a value held here.
        secrets: map(secretsOf(app), secret => {
          name: secret
          keyVaultUrl: uri(vault.properties.vaultUri, 'secrets/${secret}')
          identity: identityIds[app.workload]
        })
      }
      template: {
        scale: {
          minReplicas: app.minReplicas
          maxReplicas: app.maxReplicas
        }
        terminationGracePeriodSeconds: app.stopSeconds
        containers: [
          {
            name: app.workload
            image: app.image
            command: app.command
            args: app.args
            resources: {
              cpu: json(app.cpu)
              memory: app.memory
            }
            // Only the API sets any (`apiProbes`); the others keep Azure's defaults.
            probes: app.?probes
            env: concat(
              app.settings,
              map(filter(app.files, file => !empty(file.setting)), file => {
                name: file.setting
                value: '${secretsPath}/${file.reads}'
              }),
              // Zitadel inside the environment, by the name the platform
              // routes, in each setting that names where it is.
              map(app.zitadelSettings, setting => {
                name: setting
                value: zitadelInternalUrl
              }),
              app.sendsEmail ? emailSettings : app.signsIn ? zitadelOrigins : [],
              !app.keepsDownloads ? [] : app.workload == 'jobs' ? jobsDownloadsSettings : apiDownloadsSettings,
              !app.keepsAnchors ? [] : app.workload == 'jobs' ? jobsAnchorSettings : apiAnchorSettings
            )
            volumeMounts: empty(app.files)
              ? []
              : [
                  {
                    volumeName: secretsVolume
                    mountPath: secretsPath
                  }
                ]
          }
        ]
        volumes: empty(app.files)
          ? []
          : [
              {
                name: secretsVolume
                storageType: 'Secret'
                // Named one by one: a secret volume with no list mounts every
                // secret the app has.
                secrets: map(app.files, file => {
                  secretRef: file.reads
                  path: file.reads
                })
              }
            ]
      }
    }
  }
]

// CI's way in (G4-2b): the one role the foundation defines for it (release.bicep),
// given to its identity on the two things a merge changes, the API and the
// migration job, and nowhere else (policy rule `release-access`):
// - by the role's subscription-level id, the form Azure keeps a custom role
//   under wherever it may be given
// - on the resources themselves, never the resource group: CI can't touch
//   Zitadel, its login pages, the set-up job (which holds the server admin's
//   login) or a door, and holds no Key Vault role
// - what the role allows is wider than what CI's release tool does (G4-3):
//   writing the API or the job, or starting a run with a template of its own
//   (Microsoft: permission to start a job is permission to use its secrets),
//   can change the command and settings too, not only the image. The ceiling
//   is what the two run as: the API's and the migration's database logins
//   (ADR-002 "Deploying"; the handoff's residual risk, decided before
//   production)
resource releaseIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: names.release
}

var releaseRole = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', releaseRoleName(resourceGroup().id))

resource releaseUpdatesApi 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: deployedApps[indexOf(map(apps, app => app.workload), 'api')]
  name: guid(deployedApps[indexOf(map(apps, app => app.workload), 'api')].id, releaseIdentity.id, releaseRole)
  properties: {
    description: 'CI updates the API to a new image (deploy/azure/apps.bicep)'
    roleDefinitionId: releaseRole
    principalId: releaseIdentity.properties.principalId
    // Said outright, so Azure needn't look the identity up first.
    principalType: 'ServicePrincipal'
  }
}

resource releaseRunsMigrate 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: deployedJobs[indexOf(map(jobs, job => job.workload), 'migrate')]
  name: guid(deployedJobs[indexOf(map(jobs, job => job.workload), 'migrate')].id, releaseIdentity.id, releaseRole)
  properties: {
    description: 'CI updates the migration job to a new image and runs it (deploy/azure/apps.bicep)'
    roleDefinitionId: releaseRole
    principalId: releaseIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// The public doors (G2e): the only way in from the internet. A route config can
// send traffic to an app whose ingress is internal, so each door names the apps
// it reaches here and nowhere else, and the policy rule `public-doors` holds
// every door to its own list. Each door is one host, which the environment
// serves once the host's DNS records point at it (G3b):
// - `Auto` binds the managed certificate Azure makes for the host (G2e-3) once
//   it exists, and again on every later deployment (Microsoft: "If a managed
//   certificate is already created for this domain, it is added to the route
//   automatically"). Until then the host answers over plain http only, so
//   G2e-3 adds each door's certificate to this same deployment
// - each rule matches one path prefix, says outright whether case matters, and
//   sends its matches to one app, unchanged: no rewrite, no revision or label
//   pinned, so a door always reaches the app's live revision
// - the first rule that matches wins (Microsoft: "The order of the routing
//   rules matters. More specific prefixes need to be before less specific
//   prefixes"), so a door lists its narrow paths before `/`
var doors = [
  {
    // The app host: every path to the API, which answers anything it doesn't
    // serve with its own 404 (Product-Documentation/API.md).
    door: 'app'
    host: appHost
    routes: [
      {
        description: 'Every path on the app host goes to the API'
        prefix: '/'
        anyCase: false
        reaches: 'api'
      }
    ]
  }
  {
    // The auth host: Zitadel, with its login pages under the base path the
    // login container is built for, as the compose stack's edge serves them
    // (deploy/compose/edge/nginx.conf).
    door: 'auth'
    host: authHost
    routes: [
      {
        // Zitadel's health and debug pages are the platform's, not the
        // browser's, and its readiness page queries the database on every
        // request. The API answers them with its own 404, in any case, so
        // `/DEBUG` finds nothing either. No trailing slash, unlike the compose
        // edge's `/debug/`: `/debug` itself is caught too.
        description: 'Zitadel\'s debug pages on the auth host get the API\'s 404'
        prefix: '/debug'
        anyCase: true
        reaches: 'api'
      }
      {
        description: 'The login pages on the auth host go to the login app'
        prefix: '/ui/v2/login'
        anyCase: false
        reaches: 'login'
      }
      {
        description: 'Every other path on the auth host goes to Zitadel'
        prefix: '/'
        anyCase: false
        reaches: 'zitadel'
      }
    ]
  }
]

resource publicDoors 'Microsoft.App/managedEnvironments/httpRouteConfigs@2026-01-01' = [
  for door in doors: {
    parent: appsEnvironment
    name: doorName(environment, door.door)
    properties: {
      customDomains: [
        {
          name: door.host
          bindingType: 'Auto'
        }
      ]
      rules: map(door.routes, route => {
        description: route.description
        routes: [
          {
            match: {
              prefix: route.prefix
              caseSensitive: !route.anyCase
            }
          }
        ]
        targets: [
          {
            containerApp: appName(environment, route.reaches)
          }
        ]
      })
    }
    // A door names its apps, so they are made first.
    dependsOn: [
      deployedApps
    ]
  }
]
