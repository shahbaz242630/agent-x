// The write-once store, with four containers: our team's exports of an
// organisation's audit log (`audit-exports`; ADR-005 §6, Phase 3 E10c; decision
// 27), the audit chains' anchors (`audit-anchors`; 4D2e E, PL-58), kept apart
// from the database so a chain wound back shows, across restarts too, and the
// witness log (`audit-witness`; TR-1), where every copy of the API, and the
// operator, puts each chain head it wrote before saying it was done, so a chain
// cut below a head any copy saw shows to every other copy, and that log's hourly
// snapshots (`audit-witness-snapshots`), apart from the heads so that a copy
// that may add a head can't add a snapshot leaving one out. The
// operator's `audit-export` job writes each export once, as its own identity
// (apps/operator/src/azure-blob-store.ts); the API writes each anchor file once,
// as its own (packages/platform/src/storage/write-once.ts). Nothing, us included,
// can change or delete either until its time is up.
//
// - version-level immutability, set when the account is created (Microsoft:
//   it can't be added later), and every container takes the account's policy,
//   so the four keep a file alike: staging a few days, Unlocked;
//   production five years, Locked. A policy can't be created Locked, so
//   production's first foundation runs twice, Unlocked then Locked, and a
//   Locked account can't be deleted until its last file's time is up
// - shared keys off: every request signs in with Entra, so a leaked key reads
//   nothing; no public blob access; no copying in from another tenant
// - off the public route (AZ11; decision 27, PL-43): reached only through its
//   blob private endpoint in the network's endpoints subnet, which only the apps
//   subnet may reach (network.bicep); the network rule below stays as a second
//   lock. Nobody reads an export from a laptop or the portal: how one is handed
//   over is decided separately (decision 28)
// - the operator's identity may add a new file to `audit-exports`
//   (`blobs/add/action`), and read what is there (`blobs/read`, the plans'
//   reader role, as the chain repair's): a rebase after a repair reads that
//   repair's outcome record first (AT13f). It can't overwrite or delete. The identity of the
//   app that holds the jobs (`anchorKeepers`, 4D2e D13) may add a new file to
//   `audit-anchors` and read and list what is there (`blobs/read`, as a restart
//   must), and can't overwrite or delete. The operator's may read and
//   list `audit-anchors` (`blobs/read`), which a chain's recovery plan is
//   checked against (4D2e E9), and add a new file there (`blobs/add/action`):
//   a chain's rebase (4D2e E11), which the API believes only signed with the
//   operator's own `audit-rebase` key; anything else it adds is a file the API
//   reads as spoiled, the alarm: it holds the keepers' own role there. Neither can
//   overwrite or delete. The chain repair's (4D2e E10) may read and list
//   `audit-anchors` alone: it adds nothing there. So may production's API
//   (`anchorReaders`, AT13b), whose `web` copies read the anchors and the
//   signed states' digest beside them and never write. The identities of the
//   apps that run the API (`witnessWriters`: the API, every copy of it, and the
//   jobs app) and the operator's may add a new file to `audit-witness` and read
//   and list what is there: every copy that writes a chain puts its head there,
//   and reads the others'. Each adds only under its own folder (TR-20: a
//   condition on the assignment, so the store refuses the rest): the apps under
//   `e<epoch>/heads/`, the operator under `e<epoch>/operator/` and the signed
//   set-aside list, `e<epoch>/set-aside/`, which a copy broken into could
//   otherwise flood until no start takes a snapshot. The chain repair's may read and list it alone. Only
//   the app that holds the jobs (`anchorKeepers`, as for the anchors) may add a
//   snapshot to `audit-witness-snapshots` and read them; production's API
//   (`anchorReaders`) and the chain repair's may read and list them alone, and
//   the operator's nothing there: a snapshot is what a restarting copy starts
//   from, so whoever may add one could make every copy forget a witnessed head.
//   None can overwrite or delete. No one else is given anything
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

@export()
@description('The container the witness log is kept in (TR-1): the chain heads each copy wrote.')
func witnessContainerName() string => 'audit-witness'

@export()
@description('The container the witness log\'s hourly snapshots are kept in (TR-1), apart from the heads: only the app that holds the jobs adds one.')
func witnessSnapshotsContainerName() string => 'audit-witness-snapshots'

param location string
param name string
param tags object
param appsSubnetId string
param endpointsSubnetId string
param blobZoneId string
param workspaceId string
param writerIdentityName string

@description('Who keeps the anchors, each `{ workload, identity }`: the identity of the app that holds the jobs (4D2e D13), created by the foundation under that name, as the writer\'s is.')
param anchorKeepers array

@description('Who reads the anchors and keeps none, each `{ workload, identity }` (AT13b): production\'s API, whose `web` copies hold its decisions to the signed states\' digest kept beside them. Created by the foundation under that name.')
param anchorReaders array

@description('Who writes the witness log, each `{ workload, identity }` (TR-1): the identities of the apps that run the API, the API (every copy of it, `web` copies too) and the jobs app, in both environments, as every copy writes the chains. Created by the foundation under that name.')
param witnessWriters array

@description('The chain repair\'s identity (4D2e E10): it adds its records as the writer does and reads the anchors as the operator does. Created by the foundation under this name.')
param restorerIdentityName string

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
    publicNetworkAccess: 'Disabled'
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

// The store's one way in (AZ11): its blob service at a private address in the endpoints subnet.
resource endpoint 'Microsoft.Network/privateEndpoints@2025-01-01' = {
  name: 'pe-${name}-blob'
  location: location
  tags: tags
  properties: {
    subnet: {
      id: endpointsSubnetId
    }
    privateLinkServiceConnections: [
      {
        name: 'blob'
        properties: {
          privateLinkServiceId: account.id
          groupIds: [
            'blob'
          ]
        }
      }
    ]
  }
}

// Azure keeps the endpoint's A record in the zone the network resolves through.
resource endpointDns 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2025-01-01' = {
  parent: endpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'blob'
        properties: {
          privateDnsZoneId: blobZoneId
        }
      }
    ]
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

resource witnessContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-01-01' = {
  parent: blobs
  name: witnessContainerName()
  properties: {
    publicAccess: 'None'
  }
}

resource witnessSnapshotsContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-01-01' = {
  parent: blobs
  name: witnessSnapshotsContainerName()
  properties: {
    publicAccess: 'None'
  }
}

// Created by the foundation (environment.bicep) under this name.
resource writer 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: writerIdentityName
}

// Defined in the partner's `access` deployment (modules/roles.bicep, AZ5), never by CI: given here by name.
resource writerRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' existing = {
  name: guid(resourceGroup().id, 'evidence-writer')
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

resource anchorKeeper 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = [
  for keeper in anchorKeepers: {
    name: keeper.identity
  }
]

// Defined in the partner's `access` deployment (modules/roles.bicep, AZ5), never by CI: given here by name.
resource anchorRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' existing = {
  name: guid(resourceGroup().id, 'audit-anchors')
}

resource keepsAnchors 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for (keeper, index) in anchorKeepers: {
    scope: anchorContainer
    name: guid(anchorContainer.id, anchorKeeper[index].id, anchorRole.id)
    properties: {
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', anchorRole.name)
      principalId: anchorKeeper[index].properties.principalId
      principalType: 'ServicePrincipal'
      description: '${keeper.workload} keeps audit anchors (deploy/azure/modules/evidence.bicep)'
    }
  }
]

// Defined in the partner's `access` deployment (modules/roles.bicep, AZ5), never by CI: given here by name.
resource anchorReaderRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' existing = {
  name: guid(resourceGroup().id, 'audit-anchors-reader')
}

// The operator's identity, the exports' writer above, holds the keepers' own role
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

resource anchorReader 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = [
  for reader in anchorReaders: {
    name: reader.identity
  }
]

// Production's `web` copies (AT13b): Get Blob and List Blobs on the anchors, as
// the chain repair reads them, so their decisions are held to the signed states'
// digest the jobs keep there. Never add, overwrite or delete: only the jobs write.
resource readsAnchorsOnly 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for (reader, index) in anchorReaders: {
    scope: anchorContainer
    name: guid(anchorContainer.id, anchorReader[index].id, anchorReaderRole.id)
    properties: {
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', anchorReaderRole.name)
      principalId: anchorReader[index].properties.principalId
      principalType: 'ServicePrincipal'
      description: '${reader.workload} web copies read audit anchors (deploy/azure/modules/evidence.bicep)'
    }
  }
]

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

// The witness log (TR-1). Defined in the partner's `access` deployment (modules/roles.bicep, AZ5), never by CI:
// given here by name. Add a new file, read and list; never overwrite or delete.
resource witnessRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' existing = {
  name: guid(resourceGroup().id, 'audit-witness')
}

// Each writer's identity by its ID, not a second `existing` declaration: the API's and the jobs app's are already
// declared as the anchors' keepers or readers, and Azure refuses a template that declares one resource twice.
func identityOf(name string) string => resourceId('Microsoft.ManagedIdentity/userAssignedIdentities', name)

// What the witness role may add where it is given (TR-20), as conditions on its assignments: a rule written on the
// blob's path, which Azure checks on every Put. The apps add under heads/ alone, never in the operator's folder or the
// set-aside list (policy.ts holds the same words: WITNESS_CONDITIONS).
var blobPath = '@Resource[Microsoft.Storage/storageAccounts/blobServices/containers/blobs:path]'
// add/action alone: Azure refuses a condition naming an action its role doesn't hold (InvalidRoleAssignmentCondition
// on blobs/write at S212's first foundation), and policy.ts keeps write out of the role (WITNESS_ACTIONS).
var adds = '!(ActionMatches{\'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action\'})'
// Each app adds a file under e<epoch>/heads/ alone.
var witnessAppCondition = '((${adds}) OR (${blobPath} StringLike \'e*/heads/*\' AND ${blobPath} StringNotLike \'*/set-aside/*\' AND ${blobPath} StringNotLike \'*/operator/*\'))'
// The operator adds its own heads and the set-aside list alone.
var witnessOperatorCondition = '((${adds}) OR ((${blobPath} StringLike \'e*/operator/*\' OR ${blobPath} StringLike \'e*/set-aside/*\') AND ${blobPath} StringNotLike \'*/heads/*\'))'

// Every copy of the API, `web` copies too, and the jobs app put the heads they wrote and read the others'.
resource writesWitness 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for each in witnessWriters: {
    scope: witnessContainer
    name: guid(witnessContainer.id, identityOf(each.identity), witnessRole.id)
    properties: {
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', witnessRole.name)
      principalId: reference(identityOf(each.identity), '2024-11-30').principalId
      principalType: 'ServicePrincipal'
      description: '${each.workload} writes and reads audit witness heads (deploy/azure/modules/evidence.bicep)'
      condition: witnessAppCondition
      conditionVersion: '2.0'
    }
  }
]

// The operator's commands that write a chain (the hand-off pause above all) put their heads there too.
resource operatorWritesWitness 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: witnessContainer
  name: guid(witnessContainer.id, writer.id, witnessRole.id)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', witnessRole.name)
    principalId: writer.properties.principalId
    principalType: 'ServicePrincipal'
    description: 'operator writes and reads audit witness heads (deploy/azure/modules/evidence.bicep)'
    condition: witnessOperatorCondition
    conditionVersion: '2.0'
  }
}

// The chain repair reads the witnessed heads a repair is checked against, and adds none: the read-only role.
resource restorerReadsWitness 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: witnessContainer
  name: guid(witnessContainer.id, restorer.id, anchorReaderRole.id)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', anchorReaderRole.name)
    principalId: restorer.properties.principalId
    principalType: 'ServicePrincipal'
    description: 'chain-restore reads audit witness heads (deploy/azure/modules/evidence.bicep)'
  }
}

// The witness log's snapshots (TR-1): the app that holds the jobs alone adds one (the anchors' keepers: production's
// jobs app; staging's API too, which holds the jobs out of a load run), with the witness role; never the operator.
resource keepsWitnessSnapshots 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for (keeper, index) in anchorKeepers: {
    scope: witnessSnapshotsContainer
    name: guid(witnessSnapshotsContainer.id, anchorKeeper[index].id, witnessRole.id)
    properties: {
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', witnessRole.name)
      principalId: anchorKeeper[index].properties.principalId
      principalType: 'ServicePrincipal'
      description: '${keeper.workload} writes and reads audit witness snapshots (deploy/azure/modules/evidence.bicep)'
    }
  }
]

// Production's `web` copies start from a snapshot and add none: the read-only role, as the chain repair's.
resource readsWitnessSnapshots 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for (reader, index) in anchorReaders: {
    scope: witnessSnapshotsContainer
    name: guid(witnessSnapshotsContainer.id, anchorReader[index].id, anchorReaderRole.id)
    properties: {
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', anchorReaderRole.name)
      principalId: anchorReader[index].properties.principalId
      principalType: 'ServicePrincipal'
      description: '${reader.workload} reads audit witness snapshots (deploy/azure/modules/evidence.bicep)'
    }
  }
]

resource restorerReadsWitnessSnapshots 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: witnessSnapshotsContainer
  name: guid(witnessSnapshotsContainer.id, restorer.id, anchorReaderRole.id)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', anchorReaderRole.name)
    principalId: restorer.properties.principalId
    principalType: 'ServicePrincipal'
    description: 'chain-restore reads audit witness snapshots (deploy/azure/modules/evidence.bicep)'
  }
}

// Defined in the partner's `access` deployment (modules/roles.bicep, AZ5), never by CI: given here by name.
resource planReaderRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' existing = {
  name: guid(resourceGroup().id, 'evidence-plan-reader')
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

// The operator's identity reads a repair's outcome record before the rebase that follows it (AT13f,
// `chain-rebase --after-restore`): the plans' reader role, the same read the chain repair holds, nothing more.
resource writerReadsRepairs 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: container
  name: guid(container.id, writer.id, planReaderRole.id)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', planReaderRole.name)
    principalId: writer.properties.principalId
    principalType: 'ServicePrincipal'
    description: 'operator reads chain repair records before a rebase (deploy/azure/modules/evidence.bicep)'
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
