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
//   later run brings: Zitadel can't read what it encrypted with another key
// - each identity reads only the secrets listed for it below (Key Vault
//   Secrets User on that one secret); the policy holds the same list
// - every value comes from the shell that deploys, never from this repository
//   (Rule Book §7), and none is ever an output
import { identityName, resourceNames, uniqueSuffix, workloads } from 'names.bicep'

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

var names = resourceNames(environment, nameSuffix)

// Key Vault Secrets User: reads a secret's value and nothing else (Microsoft's
// built-in role, by its id).
var vaultReaderRole = '4633458b-17de-408a-b874-0445c86b69e6'

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

// Every secret and who reads it, the master key included.
var access = concat(map(secrets, secret => {
  name: secret.name
  readers: secret.readers
}), [masterKey])

// One role assignment for each secret and each of its readers: the secret's
// place in `access`, and the reader's in the list of apps and jobs.
var grants = flatten(map(range(0, length(access)), secret => map(access[secret].readers, reader => {
  secret: secret
  reader: indexOf(workloads, reader)
})))

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

// Every secret as the vault has it, written by this run or an earlier one:
// each looked up once, as the scope its readers are given.
resource vaultSecrets 'Microsoft.KeyVault/vaults/secrets@2025-05-01' existing = [
  for secret in access: {
    parent: vault
    name: secret.name
  }
]

// Every app's and job's identity, which main.bicep created: each looked up once.
resource identities 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = [
  for workload in workloads: {
    name: identityName(environment, workload)
  }
]

resource readAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for grant in grants: {
    scope: vaultSecrets[grant.secret]
    name: guid(vaultSecrets[grant.secret].id, identities[grant.reader].id, vaultReaderRole)
    properties: {
      description: '${workloads[grant.reader]} reads ${access[grant.secret].name} (deploy/azure/secrets.bicep)'
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', vaultReaderRole)
      principalId: identities[grant.reader].properties.principalId
      // Said outright, so Azure needn't look the identity up first.
      principalType: 'ServicePrincipal'
    }
    // A secret exists before anyone is let read it.
    dependsOn: [
      written
      created
    ]
  }
]
