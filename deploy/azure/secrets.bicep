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
//   So is each of the app's keys (appKeys in names.bicep): what a key sealed
//   or signed needs it as it was, so a rotation adds a version instead
// - each identity reads only the secrets listed for it below (Key Vault
//   Secrets User on that one secret, modules/secret-access.bicep); the policy
//   holds the same list
// - every value comes from the shell that deploys, never from this repository
//   (Rule Book §7), and none is ever an output
import { appKeys, resourceNames, uniqueSuffix } from 'names.bicep'

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

@description('The zitadel role\'s login, for Zitadel and its jobs.')
@secure()
param dbZitadelPassword string

@description('Zitadel\'s master key, exactly 32 characters, on every run. Only the first run\'s is kept and a later one is ignored, so a run gives a fresh random one, never the real key again.')
@minLength(32)
@maxLength(32)
@secure()
param zitadelMasterKey string

@description('The first Zitadel admin\'s starting password, from the password manager: Zitadel\'s set-up uses it once.')
@secure()
param zitadelAdminPassword string

@description('The private half of the login pages\' key pair (ADR-003 Amendment G2a), base64 of its PEM text.')
@secure()
param loginClientPrivateKey string

@description('The public half, for Zitadel\'s system user setting, base64 of its PEM text.')
@secure()
param loginClientPublicKey string

@description('A fresh value for each of the app\'s keys (appKeys), on every run, as JSON: each key\'s name and 32 random bytes as base64url. Only a key the vault doesn\'t hold yet is written; the rest keep their values. Never empty, so a run without them stops before Azure.')
@minLength(2)
@secure()
param appKeyValues string

var names = resourceNames(environment, nameSuffix)

// Every secret a run writes when given a value, and who reads each. The
// set-up job reads every database login, since each of its runs sets them all.
var secrets = [
  {
    name: 'db-admin-password'
    value: postgresAdminPassword
    readers: ['db-setup']
  }
  {
    name: 'db-owner-password'
    value: dbOwnerPassword
    readers: ['db-setup', 'migrate']
  }
  {
    name: 'db-app-password'
    value: dbAppPassword
    readers: ['db-setup', 'api']
  }
  {
    name: 'db-backup-password'
    value: dbBackupPassword
    readers: ['db-setup']
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
]

// The one secret no run writes twice.
var masterKey = {
  name: 'zitadel-masterkey'
  readers: ['zitadel-setup', 'zitadel']
}

// Every secret and who reads it, the master key and the app's keys included.
var access = concat(
  map(secrets, secret => {
    name: secret.name
    readers: secret.readers
  }),
  [masterKey],
  map(appKeys, key => {
    name: key
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
    }
  }
]

@onlyIfNotExists()
resource created 'Microsoft.KeyVault/vaults/secrets@2025-05-01' = {
  parent: vault
  name: masterKey.name
  properties: {
    value: zitadelMasterKey
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
    keys
  ]
}
