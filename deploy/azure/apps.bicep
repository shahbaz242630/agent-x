// Agent X's jobs on Azure (ADR-002 Amendment G2d): the four jobs that prepare a
// deployment, each started by hand. The apps that serve traffic (the API,
// Zitadel and its login pages) and the public doors join this file in G2d-2 and
// G2e. A deployment of its own, into the resource group main.bicep creates and
// after secrets.bicep has written the secrets:
//
//   bicep snapshot deploy/azure/staging.apps.bicepparam --resource-group rg-agentx-staging
//   az deployment group create --resource-group rg-agentx-staging \
//     --parameters deploy/azure/staging.apps.bicepparam   # G3
//
// - each job runs as its own identity (main.bicep created one per app and job)
//   and reads its own secrets alone, by versionless URL, so a rotation reaches
//   it without a redeployment. `GRANTS` in policy.ts holds the one list of who
//   reads what, and checks this file against it
// - a secret reaches a container as a mounted file wherever the program can read
//   one: an environment is copied into crash output and read by every child
//   process. Ours takes every login as a file, and Zitadel's master key has a
//   file form too (`--masterkeyFile`, checked against the image). Only the
//   settings with no file form arrive in the environment, and `policy.ts` lists
//   exactly which (`SECRETS_IN_ENVIRONMENT`)
// - manual trigger only: nothing here runs on a clock or an event. The set-up
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
//   (G4), and Zitadel's by the same pinned reference the compose stack runs
//   (`tooling/checks/images.test.ts` keeps the two equal)
import {
  identityName
  jobName
  jobWorkloads
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

@description('The host name Zitadel is served on, which its first instance is created with. The domain never sits in this repository (Rule Book §7).')
@minLength(4)
param authHost string

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
  jobWorkloads,
  workload => workload,
  workload => resourceId('Microsoft.ManagedIdentity/userAssignedIdentities', identityName(environment, workload))
)

var appsEnvironmentId = resourceId('Microsoft.App/managedEnvironments', names.appsEnvironment)

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
// holds the server admin's login. TLS is checked to the host name, which is the
// server's own inside the private zone; the compose stack has no TLS and so
// says `disable` there.
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
    name: 'ZITADEL_DATABASE_POSTGRES_ADMIN_EXISTINGDATABASE'
    value: 'zitadel'
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
    settings: concat(zitadelDatabase, zitadelLogging)
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
    settings: concat(zitadelDatabase, zitadelLogging, zitadelAddress, zitadelFirstInstance, zitadelPolicy)
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
