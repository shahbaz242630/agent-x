// The write-once store for our team's exports of an organisation's audit log
// (ADR-005 §6, Phase 3 E10c; decision 27). The operator's `audit-export` job
// writes each file once, as its own identity (apps/operator/src/azure-blob-store.ts),
// and nothing, us included, can change or delete it until its time is up.
//
// - version-level immutability, set when the account is created (Microsoft:
//   it can't be added later): staging keeps a file a few days, Unlocked;
//   production five years, Locked. A policy can't be created Locked, so
//   production's first foundation runs twice, Unlocked then Locked, and a
//   Locked account can't be deleted until its last file's time is up
// - shared keys off: every request signs in with Entra, so a leaked key reads
//   nothing; no public blob access; no copying in from another tenant
// - on the public route for now (decision 27, PL-43: a private endpoint before
//   the first client or live), but requests only from the apps subnet, through
//   its Storage service endpoint, as the key vault takes them. Nobody reads an
//   export from a laptop or the portal: how one is handed over is decided
//   separately (decision 28)
// - the operator's identity may only add a new file to the one container
//   (`blobs/add/action`): it can't read, overwrite or list, and no one else is
//   given anything here
// - every read, write and delete is logged to the workspace (StorageBlobLogs)

@export()
@description('The account\'s name, which must be unique across Azure: the apps deployment builds the container\'s address from it.')
func evidenceAccountName(short string, nameSuffix string) string => 'stagentx${short}${nameSuffix}'

@export()
@description('The one container the exports are written to.')
func evidenceContainerName() string => 'audit-exports'

param location string
param name string
param tags object
param appsSubnetId string
param workspaceId string
param writerIdentityName string

@description('A custom role\'s name is the whole directory\'s, so it carries the environment and the suffix.')
param writerRoleName string

@description('How many days each file is kept unchangeable.')
@minValue(1)
param retentionDays int

@description('Unlocked can still be shortened or removed; Locked never can (production, after its first run).')
@allowed([
  'Unlocked'
  'Locked'
])
param immutability string

@description('Standard_LRS for staging; Standard_ZRS keeps three copies across the region\'s zones (production).')
@allowed([
  'Standard_LRS'
  'Standard_ZRS'
])
param redundancy string

resource account 'Microsoft.Storage/storageAccounts@2025-01-01' = {
  name: name
  location: location
  tags: tags
  kind: 'StorageV2'
  sku: {
    name: redundancy
  }
  properties: {
    accessTier: 'Hot'
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowSharedKeyAccess: false
    defaultToOAuthAuthentication: true
    allowBlobPublicAccess: false
    allowCrossTenantReplication: false
    allowedCopyScope: 'AAD'
    isHnsEnabled: false
    isSftpEnabled: false
    isLocalUserEnabled: false
    isNfsV3Enabled: false
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'None'
      ipRules: []
      virtualNetworkRules: [
        {
          id: appsSubnetId
          action: 'Allow'
        }
      ]
    }
    encryption: {
      keySource: 'Microsoft.Storage'
      // A second layer of encryption under the service's own; creation only.
      requireInfrastructureEncryption: true
      services: {
        blob: {
          enabled: true
          keyType: 'Account'
        }
      }
    }
    immutableStorageWithVersioning: {
      enabled: true
      immutabilityPolicy: {
        immutabilityPeriodSinceCreationInDays: retentionDays
        state: immutability
        allowProtectedAppendWrites: false
      }
    }
  }
}

// Version-level immutability keeps every version: versioning must be on.
resource blobs 'Microsoft.Storage/storageAccounts/blobServices@2025-01-01' = {
  parent: account
  name: 'default'
  properties: {
    isVersioningEnabled: true
  }
}

resource container 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-01-01' = {
  parent: blobs
  name: evidenceContainerName()
  properties: {
    publicAccess: 'None'
  }
}

// Created by the foundation (environment.bicep) under this name.
resource writer 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: writerIdentityName
}

// Put Blob of a file that isn't there yet, and nothing else (Microsoft:
// `blobs/write` would also overwrite one, `blobs/read` read it back).
resource writerRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(resourceGroup().id, 'evidence-writer')
  properties: {
    roleName: writerRoleName
    description: 'The operator\'s audit export: add a new file to the export container. Nothing else.'
    type: 'CustomRole'
    assignableScopes: [
      resourceGroup().id
    ]
    permissions: [
      {
        actions: []
        notActions: []
        dataActions: [
          'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action'
        ]
        notDataActions: []
      }
    ]
  }
}

resource writes 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: container
  name: guid(container.id, writer.id, writerRole.id)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', writerRole.name)
    principalId: writer.properties.principalId
    principalType: 'ServicePrincipal'
    description: 'operator adds audit exports (deploy/azure/modules/evidence.bicep)'
  }
}

resource audit 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: blobs
  name: 'blob-logs-to-workspace'
  properties: {
    workspaceId: workspaceId
    // Resource-specific tables (StorageBlobLogs), not the shared AzureDiagnostics.
    logAnalyticsDestinationType: 'Dedicated'
    logs: [
      {
        category: 'StorageRead'
        enabled: true
      }
      {
        category: 'StorageWrite'
        enabled: true
      }
      {
        category: 'StorageDelete'
        enabled: true
      }
    ]
  }
}
