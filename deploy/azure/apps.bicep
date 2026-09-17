// Agent X's apps and jobs on Azure (ADR-002 Amendment G2d): the four jobs that
// prepare a deployment, each started by hand, and the three apps that serve
// traffic (the API, Zitadel and its login pages), and the public doors that put
// an app on a host name (G2e). A deployment of its own, into the resource group
// main.bicep creates and after secrets.bicep has written the secrets:
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
// - the apps scale as the environment allows, within two limits: the API and
//   Zitadel each hold something one replica's (a rate limit's counts in memory;
//   Zitadel's projections and its ten database connections), and staging keeps
//   no replica at all while nothing runs (ADR-002), unless the operator deploys
//   with `apps --keep-running` for a while
// - manual trigger only: no *job* here runs on a clock or an event. The set-up
//   job holds the server admin's login, and Microsoft treats permission to
//   start a job as permission to use its secrets, so who may start which job is
//   settled with the deploy job (G4)
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
  appName
  appsPrefix
  appWorkloads
  doorName
  identityName
  jobName
  jobWorkloads
  networkAddressSpace
  resourceNames
  resourceTags
  uniqueSuffix
} from 'names.bicep'

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

@description('How many replicas of each app keep running with no traffic. Staging scales to zero (ADR-002): nothing is billed while nothing runs, at the cost of a cold start on the first request. The deploy tool sets 1 for `apps --keep-running`.')
@minValue(0)
@maxValue(1)
param appMinReplicas int

@description('The first Zitadel admin\'s email address, the only way in before anyone else exists. No mail is sent: nothing in the UAE deployment has an SMTP server, so the address is marked verified and the password comes from the vault.')
@minLength(6)
param zitadelAdminEmail string

var names = resourceNames(environment, nameSuffix)
var tags = resourceTags(environment)

// Our own image, which can only be a digest: `appImageDigest` is separate from
// the repository so that no run can pass a tag in its place.
var appImage = '${appImageRepository}@${appImageDigest}'

// Where each job's mounted secrets appear. Outside /app, which holds the code.
var secretsPath = '/mnt/secrets'
var secretsVolume = 'secrets'

// Each identity's resource id, by the workload it belongs to.
var identityIds = toObject(
  concat(appWorkloads, jobWorkloads),
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

// What every container of ours is told, wherever it runs: which environment
// this is, which build it is, and where the database is. Each job adds the
// role it logs in as and the file its login is in.
var ourSettings = [
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
    value: names.databaseHost
  }
  {
    name: 'AGENTX_DB_NAME'
    value: 'agentx'
  }
]

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

// Every job: the work it does (its identity and its name come from that), the
// image and command, how long one run may take, what it reads as a mounted file
// with the setting that names each file, and its settings. `secretRef` entries
// in `settings` name a secret too; `policy.ts` checks that the secrets a job is
// given are exactly the ones `GRANTS` says it reads, however they reach it.
var jobs = [
  {
    // The roles and databases of a server, as the server admin (G2a). Safe to
    // run again, and run again on every deployment.
    workload: 'db-setup'
    image: appImage
    command: ['node', 'apps/db-setup/src/main.ts']
    args: []
    timeoutSeconds: 900
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
        reads: 'db-zitadel-password'
        setting: 'AGENTX_DB_ZITADEL_PASSWORD_FILE'
      }
    ]
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
    files: [
      {
        reads: 'db-owner-password'
        setting: 'AGENTX_DB_MIGRATION_PASSWORD_FILE'
      }
    ]
    settings: ourSettings
  }
  {
    // Zitadel's own schemas in its own database (ADR-003), as its own role.
    workload: 'zitadel-init'
    image: zitadelImage
    command: ['/app/zitadel']
    args: ['init', 'zitadel']
    timeoutSeconds: 900
    files: []
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
    files: [
      {
        reads: 'zitadel-masterkey'
        // Named on the command line above, not by a setting.
        setting: ''
      }
    ]
    settings: concat(zitadelDatabase, zitadelLogging, zitadelMachine, zitadelAddress, zitadelFirstInstance, zitadelPolicy)
  }
]

// The three apps that serve traffic (ADR-002 Amendment G2d). Each is shaped
// like a job above — the work it does, its image and command, what it reads as
// a mounted file, its settings — with what only something long-running has:
// the port it answers on and how many replicas may run.
//
// Every one of them has internal ingress. The environment has a public IP, but
// nothing here is a door: the doors are the route configs at the end of this
// file (G2e), so an app is only ever public because a door names it.
var apps = [
  {
    // The API (Product-Documentation/API.md), as the app role and no other.
    workload: 'api'
    image: appImage
    command: ['node', 'apps/api/src/main.ts']
    args: []
    targetPort: 8080
    transport: 'auto'
    reachesZitadel: false
    // The rate limit's counts are one replica's, in memory (ADR-011 §4): a
    // second replica would give every client two allowances. The worker, which
    // holds no such count, is the part that scales in Phase 4.
    maxReplicas: 1
    // Longer than the API's own 25-second stop deadline (API.md), so the log's
    // held-back counts are still written.
    stopSeconds: 30
    files: [
      {
        reads: 'db-app-password'
        setting: 'AGENTX_DB_PASSWORD_FILE'
      }
    ]
    settings: concat(ourSettings, [
      {
        name: 'AGENTX_HTTP_HOST'
        value: '0.0.0.0'
      }
      {
        name: 'AGENTX_HTTP_PORT'
        value: '8080'
      }
      {
        name: 'AGENTX_DB_USER'
        value: 'agentx_app'
      }
      // The one address a browser may send a change from (SEC-WEB-01). The
      // app door (below) is what serves that host.
      {
        name: 'AGENTX_PUBLIC_ORIGIN'
        value: 'https://${appHost}'
      }
      // The proxy in front, so each client keeps its own rate limit and its own
      // address in a security event rather than every client sharing the
      // ingress's (ADR-011 §4). Microsoft: Envoy appends the client to
      // X-Forwarded-For and "only the rightmost IP is provided by Azure
      // Container Apps", so what is trusted is the subnet the ingress sits in.
      {
        name: 'AGENTX_TRUSTED_PROXIES'
        value: appsPrefix(networkAddressSpace)
      }
      // Ten of the server's 35 user connections, leaving Zitadel's ten, one for
      // each job, and room for the worker (ADR-002 Amendment G1).
      {
        name: 'AGENTX_DB_POOL_MAX'
        value: '10'
      }
    ])
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
    reachesZitadel: false
    // Its projections and its cache are one replica's; a second would also take
    // ten more of the server's connections.
    maxReplicas: 1
    stopSeconds: 30
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
    // Nothing here holds state, but one replica is enough for a pilot and
    // keeps the deployment's shape the same everywhere.
    maxReplicas: 1
    stopSeconds: 30
    files: [
      {
        reads: 'login-client-private-key'
        setting: 'SYSTEM_USER_PRIVATE_KEY_FILE'
      }
    ]
    // ZITADEL_API_URL is added where the app is deployed, not here: the
    // environment's default domain is Azure's to give, and Bicep needs this
    // list settled before the deployment starts.
    reachesZitadel: true
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
]

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

resource deployedJobs 'Microsoft.App/jobs@2026-01-01' = [
  for job in jobs: {
    name: jobName(environment, job.workload)
    location: location
    tags: tags
    // Its own identity and no other, so it can read its own secrets alone.
    identity: {
      type: 'UserAssigned'
      userAssignedIdentities: {
        '${identityIds[job.workload]}': {}
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
        // Read from the vault by the job's own identity, never a value held here.
        secrets: map(secretsOf(job), secret => {
          name: secret
          keyVaultUrl: uri(vault.properties.vaultUri, 'secrets/${secret}')
          identity: identityIds[job.workload]
        })
      }
      template: {
        containers: [
          {
            name: job.workload
            image: job.image
            command: job.command
            args: job.args
            // The smallest pair the Consumption profile offers above its
            // minimum: enough for a short Node or Go process.
            resources: {
              cpu: json('0.5')
              memory: '1Gi'
            }
            env: concat(
              job.settings,
              map(filter(job.files, file => !empty(file.setting)), file => {
                name: file.setting
                value: '${secretsPath}/${file.reads}'
              })
            )
            volumeMounts: empty(job.files)
              ? []
              : [
                  {
                    volumeName: secretsVolume
                    mountPath: secretsPath
                  }
                ]
          }
        ]
        volumes: empty(job.files)
          ? []
          : [
              {
                name: secretsVolume
                storageType: 'Secret'
                // Named one by one: a secret volume with no list mounts every
                // secret the job has.
                secrets: map(job.files, file => {
                  secretRef: file.reads
                  path: file.reads
                })
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
        // the route configs (below), so no app is a door by accident.
        ingress: {
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
          minReplicas: appMinReplicas
          maxReplicas: app.maxReplicas
        }
        terminationGracePeriodSeconds: app.stopSeconds
        containers: [
          {
            name: app.workload
            image: app.image
            command: app.command
            args: app.args
            // The smallest pair the Consumption profile offers above its
            // minimum, as the jobs take.
            resources: {
              cpu: json('0.5')
              memory: '1Gi'
            }
            env: concat(
              app.settings,
              map(filter(app.files, file => !empty(file.setting)), file => {
                name: file.setting
                value: '${secretsPath}/${file.reads}'
              }),
              // Zitadel inside the environment, by the name the platform routes.
              app.reachesZitadel
                ? [
                    {
                      name: 'ZITADEL_API_URL'
                      value: zitadelInternalUrl
                    }
                  ]
                : []
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
// - rules match on a path's prefix, and each sends its matches to the apps it
//   names, unchanged: no rewrite, no revision or label pinned, so a door always
//   reaches the app's live revision
var doors = [
  {
    // The app host: every path to the API, which answers anything it doesn't
    // serve with its own 404 (Product-Documentation/API.md).
    door: 'app'
    host: appHost
    rules: [
      {
        description: 'Every path on the app host goes to the API'
        prefixes: ['/']
        targets: ['api']
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
      rules: map(door.rules, rule => {
        description: rule.description
        routes: map(rule.prefixes, prefix => {
          match: {
            prefix: prefix
          }
        })
        targets: map(rule.targets, workload => {
          containerApp: appName(environment, workload)
        })
      })
    }
    // A door names its apps, so they are made first.
    dependsOn: [
      deployedApps
    ]
  }
]
