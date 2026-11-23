// Agent X's secrets on Azure (ADR-002 Amendment G2c): every secret the apps and
// jobs read, written into the environment's key vault, and read access for each
// app's and job's identity to its own secrets alone. A deployment of its own,
// into the resource group main.bicep creates, run by hand after it (G3) and
// again to rotate a secret:
//
//   bicep snapshot deploy/azure/staging.secrets.bicepparam --resource-group rg-agentx-staging
//   az deployment group create --resource-group rg-agentx-staging \
//     --parameters deploy/azure/staging.secrets.bicepparam   # G3
//
// - written through Azure Resource Manager, which the vault's firewall doesn't
//   cover (Microsoft), so the vault stays closed to all but the apps subnet
// - a secret is written only when its value is given; an empty value leaves it
//   as the vault has it, so rotating one secret touches no other (the
//   parameters file says how a run sets them). Every app that reads a secret
//   restarts with its new version within 30 minutes (Microsoft)
// - Zitadel's master key is created once and never overwritten, whatever a
//   later run brings: Zitadel can't read what it encrypted with another key.
//   So is Zitadel's machine-ID config (AG10), whose header the API checks:
//   each restarts onto a new version in its own time, and a Zitadel copy that
//   starts with a header the API doesn't hold yet can't start.
//   So is each of the app's keys (appKeys in names.bicep): what a key sealed
//   or signed needs it as it was, so a rotation adds a version instead
// - each identity reads only the secrets listed for it below (Key Vault
//   Secrets User on that one secret, modules/secret-access.bicep); the policy
//   holds the same list
// - every value comes from the shell that deploys, never from this repository
//   (Rule Book §7), and none is ever an output
// - every secret a run writes gets its expiry date (PL-25) from
//   secret-expiry.json, Secrets-Register.md's schedule: the first day of the
//   run's month plus its period, so Azure's what-if reads the same all month.
//   Key Vault still serves a secret past its date (Microsoft): a date marks
//   the end of a use period and takes nothing down. A secret not written keeps
//   the date it has
import { appKeys, jobsHalves, jobsOnly, operatorHalves, operatorHolds, operatorOnly, publicHalves, resourceNames, restoreHolds, uniqueSuffix } from 'names.bicep'

targetScope = 'resourceGroup'

@description('Which environment this is.')
@allowed([
  'staging'
  'production'
])
param environment string

@description('The suffix main.bicep was deployed with, so the vault\'s name matches.')
@minLength(4)
@maxLength(6)
param nameSuffix string = uniqueSuffix(subscription().id)

@description('The server admin\'s login (agentx_admin), for the set-up job: the value main.bicep gave the server, from the password manager.')
@secure()
param postgresAdminPassword string

@description('agentx_owner\'s login, for the migration job.')
@secure()
param dbOwnerPassword string

@description('agentx_app\'s login, for the API.')
@secure()
param dbAppPassword string

@description('agentx_backup\'s login.')
@secure()
param dbBackupPassword string

@description('agentx_operator\'s login, for the operator\'s command (PL-57).')
@secure()
param dbOperatorPassword string

@description('The zitadel role\'s login, for Zitadel and its jobs.')
@secure()
param dbZitadelPassword string

@description('Zitadel\'s master key, exactly 32 characters, on every run. Only the first run\'s is kept and a later one is ignored, so a run gives a fresh random one, never the real key again.')
@minLength(32)
@maxLength(32)
@secure()
param zitadelMasterKey string

@description('Zitadel\'s config file for its machine-ID webhook (AG10): the one header its processes ask the API with, a fresh random value on every run. Only the first run\'s is kept, as the master key\'s is.')
@minLength(1)
@secure()
param zitadelMachineConfig string

@description('The first Zitadel admin\'s starting password, from the password manager: Zitadel\'s set-up uses it once.')
@secure()
param zitadelAdminPassword string

@description('The private half of the login pages\' key pair (ADR-003 Amendment G2a), base64 of its PEM text.')
@secure()
param loginClientPrivateKey string

@description('The public half, for Zitadel\'s system user setting, base64 of its PEM text.')
@secure()
param loginClientPublicKey string

@description('The API\'s secret as Zitadel\'s OIDC client (B2-6), which Zitadel gave when the API was registered with it, pasted by a person. Empty leaves the vault\'s as it is.')
@secure()
param apiOidcClientSecret string

@description('The API\'s token for reading a person\'s verified address in Zitadel (B5-3), which Zitadel gave its read-only service user, pasted by a person. Empty leaves the vault\'s as it is.')
@secure()
param directoryToken string

@description('The API\'s token for removing a person\'s second factors in Zitadel once a reset has cooled off (B6-3c), which Zitadel gave its service user with the organisation\'s Org User Manager role, pasted by a person. Empty leaves the vault\'s as it is.')
@secure()
param resetToken string

@description('The Zitadel user IDs that make our own routine changes in it (SA2b; the API\'s AGENTX_IDP_OUR_ACTORS), comma-separated, or none, pasted by a person: kept in the vault because the list tells an attacker which accounts to aim at. deploy.ts sends none for it while the vault has none, so the apps always have it to mount; empty leaves the vault\'s as it is.')
@secure()
param ourActors string

@description('The Zitadel user IDs of the API\'s own service users those changes are made for (SA2b; AGENTX_IDP_OUR_SERVICE_USERS), as ourActors.')
@secure()
param ourServiceUsers string

@description('The key the login pages sign their sessions cookie with (SA5; ZITADEL_SESSION_COOKIE_SECRET), 32 characters or more, made by the deploy tool: given when a run makes it (when the vault lacks it, or by name), empty otherwise.')
@secure()
param loginCookieSecret string

@description('A fresh value for each of the app\'s keys (appKeys), on every run, as JSON: each key\'s name and 32 random bytes as base64url. Only a key the vault doesn\'t hold yet is written; the rest keep their values. Never empty, so a run without them stops before Azure.')
@minLength(2)
@secure()
param appKeyValues string

@description('The month this run writes in (yyyy-MM, UTC), which every expiry date counts from (PL-25): always the default.')
param runMonth string = utcNow('yyyy-MM')

var names = resourceNames(environment, nameSuffix)

// Each secret's expiry period (secret-expiry.json; deploy.ts's secret-expiry.ts reads the same file).
var expiry = loadJsonContent('secret-expiry.json')

// A written secret's attributes: its expiry date where the schedule gives one, counted from the first day of the
// run's month, and nothing otherwise. Its value stays a property of its own, which the policy reads.
func expiring(period string, runMonth string) object =>
  empty(period) ? {} : { exp: dateTimeToEpoch(dateTimeAdd('${runMonth}-01T00:00:00Z', period)) }

// An app key's period: the keys' own, but for a family never rotated in place (the payee index, ADR-014 §3).
func keyPeriod(key string, expiry object) string =>
  contains(expiry.keysNever, substring(key, 0, lastIndexOf(key, '-v'))) ? '' : expiry.keys

// Every secret a run writes when given a value, and who reads each. The
// set-up job reads every database login, since each of its runs sets them all.
// The API's jobs, where they run apart from it (`jobs`, 4D2e D13), read what the
// API does: the same process at another role, whose settings are checked alike
// (sign-in's three together, email's four together), and whose jobs send the
// notices, copy the login service's events and carry out the factor resets.
var secrets = [
  {
    name: 'db-admin-password'
    value: postgresAdminPassword
    readers: ['db-setup']
  }
  {
    name: 'db-owner-password'
    value: dbOwnerPassword
    // The chain repair writes as the owner (4D2e E10), the one job besides the migration.
    // Stage G's identity reads none of these three standing (S204-b): its runner gives it them for a run alone
    // (stage-g.ts create) and takes them back with the copy (stage-g.ts delete).
    readers: ['db-setup', 'migrate', 'chain-restore']
  }
  {
    name: 'db-app-password'
    value: dbAppPassword
    readers: ['db-setup', 'api', 'jobs']
  }
  {
    name: 'db-backup-password'
    value: dbBackupPassword
    readers: ['db-setup']
  }
  {
    name: 'db-operator-password'
    value: dbOperatorPassword
    readers: ['db-setup', 'operator']
  }
  {
    name: 'db-zitadel-password'
    value: dbZitadelPassword
    readers: ['db-setup', 'zitadel-init', 'zitadel-setup', 'zitadel']
  }
  {
    name: 'zitadel-admin-password'
    value: zitadelAdminPassword
    readers: ['zitadel-setup']
  }
  {
    name: 'login-client-private-key'
    value: loginClientPrivateKey
    readers: ['login']
  }
  {
    name: 'login-client-public-key'
    value: loginClientPublicKey
    readers: ['zitadel']
  }
  {
    name: 'api-oidc-client-secret'
    value: apiOidcClientSecret
    readers: ['api', 'jobs']
  }
  {
    name: 'zitadel-directory-token'
    value: directoryToken
    readers: ['api', 'jobs']
  }
  {
    name: 'zitadel-reset-token'
    value: resetToken
    readers: ['api', 'jobs']
  }
  // SA2b: who makes our own routine changes in the login service, and for whom: the API's copier tells those by an
  // info line rather than the login-service alert. The jobs copy the events; the API reads them as the same process.
  {
    name: 'zitadel-our-actors'
    value: ourActors
    readers: ['api', 'jobs']
  }
  {
    name: 'zitadel-our-service-users'
    value: ourServiceUsers
    readers: ['api', 'jobs']
  }
  // SA5: the login pages sign their sessions cookie with it, apart from their login key.
  {
    name: 'login-cookie-secret'
    value: loginCookieSecret
    readers: ['login']
  }
]

// Copied from Communication Services on every run (B5-3): the key the API
// signs each email with. Nobody pastes it, and a run after the service's key
// is rotated in Azure brings the new one.
var copiedKey = {
  name: 'acs-access-key'
  readers: ['api', 'jobs']
}

// The one secret no run writes twice.
var masterKey = {
  name: 'zitadel-masterkey'
  readers: ['zitadel-setup', 'zitadel']
}

// Nor this one (AG10): every Zitadel process reads it at start, the API to check them.
var machineConfig = {
  name: 'zitadel-machine-config'
  readers: ['zitadel-init', 'zitadel-setup', 'zitadel', 'api']
}

// Every secret and who reads it, the master key and the app's keys included.
var access = concat(
  map(secrets, secret => {
    name: secret.name
    readers: secret.readers
  }),
  [masterKey, machineConfig, copiedKey],
  // The API and its jobs read every key but the operator's own, whose public
  // half they read instead (PL-57); the operator's command the audit chains'
  // MAC, the field encryption and its own keys alone, each version of them
  // (ADR-011 §3, B4-6b); the chain repair the MAC alone and the operator's
  // public halves (4D2e E10). The jobs' own key (TR-20) only the app that may
  // hold the jobs reads: production's `jobs` alone, as its API is only ever
  // `web` copies, which read the key's public half; staging's API too, which
  // holds the jobs out of a load run.
  map(appKeys, key => {
    name: key
    readers: concat(
      operatorOnly(key)
        ? ['operator']
        : jobsOnly(key) ? (environment == 'production' ? ['jobs'] : ['api', 'jobs']) : operatorHolds(key) ? ['api', 'jobs', 'operator'] : ['api', 'jobs'],
      restoreHolds(key) ? ['chain-restore'] : []
    )
  }),
  map(operatorHalves, half => {
    name: half
    readers: ['api', 'jobs', 'chain-restore']
  }),
  map(jobsHalves, half => {
    name: half
    readers: ['api']
  })
)

var keyValues = json(appKeyValues)

resource vault 'Microsoft.KeyVault/vaults@2025-05-01' existing = {
  name: names.vault
}

resource written 'Microsoft.KeyVault/vaults/secrets@2025-05-01' = [
  for secret in secrets: if (!empty(secret.value)) {
    parent: vault
    name: secret.name
    properties: {
      value: secret.value
      attributes: expiring(expiry.secrets[secret.name], runMonth)
    }
  }
]

@onlyIfNotExists()
resource created 'Microsoft.KeyVault/vaults/secrets@2025-05-01' = {
  parent: vault
  name: masterKey.name
  properties: {
    value: zitadelMasterKey
    attributes: expiring(expiry.secrets[masterKey.name], runMonth)
  }
}

@onlyIfNotExists()
resource machineConfigCreated 'Microsoft.KeyVault/vaults/secrets@2025-05-01' = {
  parent: vault
  name: machineConfig.name
  properties: {
    value: zitadelMachineConfig
    attributes: expiring(expiry.secrets[machineConfig.name], runMonth)
  }
}

// The email service (communication.bicep), whose key is copied in.
resource communication 'Microsoft.Communication/communicationServices@2026-03-18' existing = {
  name: names.communication
}

resource copied 'Microsoft.KeyVault/vaults/secrets@2025-05-01' = {
  parent: vault
  name: copiedKey.name
  properties: {
    value: communication.listKeys().primaryKey
    attributes: expiring(expiry.secrets[copiedKey.name], runMonth)
  }
}

// The app's keys, each created once (appKeys).
@onlyIfNotExists()
resource keys 'Microsoft.KeyVault/vaults/secrets@2025-05-01' = [
  for key in appKeys: {
    parent: vault
    name: key
    properties: {
      value: keyValues[key]
      attributes: expiring(keyPeriod(key, expiry), runMonth)
    }
  }
]

// Each operator-only and jobs-only key's public half, created once with its
// key, from the same run's value (PL-57, TR-20).
@onlyIfNotExists()
resource halves 'Microsoft.KeyVault/vaults/secrets@2025-05-01' = [
  for half in publicHalves: {
    parent: vault
    name: half
    properties: {
      value: keyValues[half]
      attributes: expiring(expiry.publicHalves, runMonth)
    }
  }
]

// Who reads what, in a template of its own: Azure refuses one that both writes
// a secret and looks it up, and each grant needs its secret looked up as its
// scope (modules/secret-access.bicep).
module readAccess 'modules/secret-access.bicep' = {
  params: {
    environment: environment
    vaultName: names.vault
    access: access
  }
  // A secret exists before anyone is let read it.
  dependsOn: [
    written
    created
    machineConfigCreated
    copied
    keys
    halves
  ]
}
