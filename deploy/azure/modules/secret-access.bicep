// Who reads which secret (ADR-002 Amendment G2c; secrets.bicep): Key Vault
// Secrets User on each secret, for each of its readers alone.
//
// - a module of its own because a role assignment's scope is the secret, looked
//   up as an existing resource even on a run that doesn't write it, and Azure
//   refuses a template that both writes a secret and looks it up ("defined
//   multiple times", the first real secrets run, S19). A module is a template
//   of its own
// - the identities are main.bicep's, each looked up here once

import { identityName, workloads } from '../names.bicep'

targetScope = 'resourceGroup'

@description('Which environment this is.')
param environment string

@description('The vault secrets.bicep writes into.')
param vaultName string

@description('Every secret and the apps and jobs that read it.')
param access {
  name: string
  readers: string[]
}[]

// Key Vault Secrets User: reads a secret's value and nothing else (Microsoft's
// built-in role, by its id).
var vaultReaderRole = '4633458b-17de-408a-b874-0445c86b69e6'

// One role assignment for each secret and each of its readers: the secret's
// place in `access`, and the reader's in the list of apps and jobs.
var grants = flatten(map(range(0, length(access)), secret => map(access[secret].readers, reader => {
  secret: secret
  reader: indexOf(workloads, reader)
})))

resource vault 'Microsoft.KeyVault/vaults@2025-05-01' existing = {
  name: vaultName
}

// Every secret as the vault has it, written by this run or an earlier one:
// each looked up once, as the scope its readers are given.
resource vaultSecrets 'Microsoft.KeyVault/vaults/secrets@2025-05-01' existing = [
  for secret in access: {
    parent: vault
    name: secret.name
  }
]

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
  }
]
