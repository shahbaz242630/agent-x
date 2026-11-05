// The write-once store, with two containers: our team's exports of an
// organisation's audit log (`audit-exports`; ADR-005 §6, Phase 3 E10c; decision
// 27), and the audit chains' anchors (`audit-anchors`; 4D2e E, PL-58), kept apart
// from the database so a chain wound back shows, across restarts too. The
// operator's `audit-export` job writes each export once, as its own identity
// (apps/operator/src/azure-blob-store.ts); the API writes each anchor file once,
// as its own (packages/platform/src/storage/write-once.ts). Nothing, us included,
// can change or delete either until its time is up.
//
// - version-level immutability, set when the account is created (Microsoft:
//   it can't be added later), and every container takes the account's policy,
//   so the two keep a file alike: staging a few days, Unlocked;
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
// - the operator's identity may only add a new file to `audit-exports`
//   (`blobs/add/action`): it can't read, overwrite or list. The API's may add a
//   new file to `audit-anchors` and read and list what is there (`blobs/read`, as
//   a restart must), and can't overwrite or delete. The operator's may read and
//   list `audit-anchors` (`blobs/read`), which a chain's recovery plan is
//   checked against (4D2e E9), and add a new file there (`blobs/add/action`):
//   a chain's rebase (4D2e E11), which the API believes only signed with the
//   operator's own `audit-rebase` key; anything else it adds is a file the API
//   reads as spoiled, the alarm: it holds the API's own role there. Neither can
//   overwrite or delete. The chain repair's (4D2e E10) may read and list
//   `audit-anchors` alone: it adds nothing there. No one else is given anything
// - every read, write and delete is logged to the workspace (StorageBlobLogs)

@export()
@description('The account\'s name, which must be unique across Azure: the apps deployment builds the container\'s address from it.')
func evidenceAccountName(short string, nameSuffix string) string => 'stagentx${short}${nameSuffix}'

@export()
@description('The container the exports are written to.')
func evidenceContainerName() string => 'audit-exports'

@export()
@description('The container the audit chains\' anchors are kept in.')
func anchorContainerName() string => 'audit-anchors'

param location string
param name string
param tags object
param appsSubnetId string
param workspaceId string
param writerIdentityName string

@description('A custom role\'s name is the whole directory\'s, so it carries the environment and the suffix.')
param writerRoleName string

@description('The identity that keeps the anchors: the API\'s. Created by the foundation under this name, as the writer\'s is.')
param anchorKeeperIdentityName string

@description('As `writerRoleName`, for the anchors\' role.')
param anchorRoleName string

@description('As `writerRoleName`, for the role the operator reads the anchors with (4D2e E9).')
param anchorReaderRoleName string

@description('The chain repair\'s identity (4D2e E10): it adds its records as the writer does and reads the anchors as the operator does. Created by the foundation under this name.')
param restorerIdentityName string

@description('As `writerRoleName`, for the role the chain repair reads a plan\'s file with (4D2e E10).')
param planReaderRoleName string

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

resource anchorContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-01-01' = {
  parent: blobs
  name: anchorContainerName()
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

resource anchorKeeper 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: anchorKeeperIdentityName
}

// Put Blob of a file that isn't there yet; Get Blob and List Blobs, which a
// restart needs (Microsoft: both are `blobs/read`). Never `blobs/write`, which
// would overwrite one, or `blobs/delete`.
resource anchorRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(resourceGroup().id, 'audit-anchors')
  properties: {
    roleName: anchorRoleName
    description: 'The API\'s audit anchors: add a new file to the anchors container, and read and list them. Nothing else.'
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
          'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'
        ]
        notDataActions: []
      }
    ]
  }
}

resource keepsAnchors 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: anchorContainer
  name: guid(anchorContainer.id, anchorKeeper.id, anchorRole.id)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', anchorRole.name)
    principalId: anchorKeeper.properties.principalId
    principalType: 'ServicePrincipal'
    description: 'api keeps audit anchors (deploy/azure/modules/evidence.bicep)'
  }
}

// Get Blob and List Blobs (both `blobs/read`), and nothing else: the chain
// repair (4D2e E10) checks a repair against the anchors and adds none.
resource anchorReaderRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(resourceGroup().id, 'audit-anchors-reader')
  properties: {
    roleName: anchorReaderRoleName
    description: 'The chain repair: read and list the anchors container. Nothing else.'
    type: 'CustomRole'
    assignableScopes: [
      resourceGroup().id
    ]
    permissions: [
      {
        actions: []
        notActions: []
        dataActions: [
          'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'
        ]
        notDataActions: []
      }
    ]
  }
}

// The operator's identity, the exports' writer above, holds the API's own role
// on the anchors: Get Blob and List Blobs for a chain recovery plan (4D2e E9),
// and Put Blob of a file not there yet for a chain's rebase (4D2e E11). Never
// overwrite or delete.
resource readsAnchors 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: anchorContainer
  name: guid(anchorContainer.id, writer.id, anchorRole.id)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', anchorRole.name)
    principalId: writer.properties.principalId
    principalType: 'ServicePrincipal'
    description: 'operator reads and adds audit anchors (deploy/azure/modules/evidence.bicep)'
  }
}

// The chain repair (4D2e E10, PL-29): its own identity, as its job alone holds
// the owner's login. It adds the records of each repair beside the plans, and
// reads the anchors a repair is checked against; the same two roles, no more.
resource restorer 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: restorerIdentityName
}

resource restorerWrites 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: container
  name: guid(container.id, restorer.id, writerRole.id)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', writerRole.name)
    principalId: restorer.properties.principalId
    principalType: 'ServicePrincipal'
    description: 'chain-restore adds chain repair records (deploy/azure/modules/evidence.bicep)'
  }
}

resource restorerReadsAnchors 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: anchorContainer
  name: guid(anchorContainer.id, restorer.id, anchorReaderRole.id)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', anchorReaderRole.name)
    principalId: restorer.properties.principalId
    principalType: 'ServicePrincipal'
    description: 'chain-restore reads audit anchors (deploy/azure/modules/evidence.bicep)'
  }
}

// Get Blob and List Blobs on the exports container (both `blobs/read`), and
// nothing else: the chain repair reads the plan it is asked to apply, so the
// repair is tied to the plan kept as evidence (4D2e E10). Its job already
// reads the whole database as its owner, so these files tell it nothing more.
resource planReaderRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(resourceGroup().id, 'evidence-plan-reader')
  properties: {
    roleName: planReaderRoleName
    description: 'The chain repair: read and list the export container, for the plan it applies. Nothing else.'
    type: 'CustomRole'
    assignableScopes: [
      resourceGroup().id
    ]
    permissions: [
      {
        actions: []
        notActions: []
        dataActions: [
          'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'
        ]
        notDataActions: []
      }
    ]
  }
}

resource restorerReadsPlans 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: container
  name: guid(container.id, restorer.id, planReaderRole.id)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', planReaderRole.name)
    principalId: restorer.properties.principalId
    principalType: 'ServicePrincipal'
    description: 'chain-restore reads recovery plans (deploy/azure/modules/evidence.bicep)'
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
