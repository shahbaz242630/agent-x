// Where the activity log's background downloads are kept (Phase 3 L5c, partner
// decision 31). The API builds each file a block at a time and later hands it
// out a part at a time, as its own identity (packages/platform/src/storage/
// block-store.ts): `<org>/<export>/<YYYY-MM>-try<n>.<csv|ndjson>.gz`. It never
// deletes one; the lifecycle rule below does, two weeks after.
//
// - shut as the audit exports' store is (evidence.bicep): shared keys off, so
//   every request signs in with Entra; no public blob access; no copying in
//   from another tenant; off the public route (AZ32c-2, PL-43): reached only
//   through its blob private endpoint in the network's endpoints subnet, which
//   only the apps subnet may reach (network.bicep), as the audit exports' store
//   is. So the apps subnet needs no Storage service endpoint and no way out to
//   the region's Storage, which let a container taken over reach any account
//   in the region
// - but not write-once: a month built again after a stop is written over the
//   same name. So no immutability, and versioning off, since a version kept of
//   each overwrite would outlive the lifecycle rule, which deletes the file only
// - one copy in both environments (LRS): a file lost is asked for again, and
//   nothing here is the only copy of anything (the activity log is in Postgres)
// - the identity of each app that runs the API (the API's, and the jobs', 4D2e
//   D13) may read and write a file in the one container and nothing else: it can't delete one, or change the account or its rules
// - every read, write and delete is logged to the workspace (StorageBlobLogs)

@export()
@description('The account\'s name, which must be unique across Azure: the apps deployment builds the container\'s address from it. At most 19 of Azure\'s 24 characters.')
func activityDownloadsAccountName(short string, nameSuffix string) string => 'stagentxdl${short}${nameSuffix}'

@export()
@description('The one container the downloads are kept in.')
func activityDownloadsContainerName() string => 'activity-downloads'

param location string
param name string
param tags object
param endpointsSubnetId string
@description('Microsoft\'s fixed zone for blob private endpoints, linked to the network (network.bicep).')
param blobZoneId string
param workspaceId string
@description('Who keeps the downloads, each `{ workload, identity }`: every app that runs the API (4D2e D13), a `web` copy handing a file out and the jobs building one, created by the foundation (environment.bicep) under that name.')
param keepers array

resource account 'Microsoft.Storage/storageAccounts@2025-01-01' = {
  name: name
  location: location
  tags: tags
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
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
    // No subnet named: the apps subnet has no Storage endpoint (AZ32c-2), and Azure refuses a rule naming one without.
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'None'
      ipRules: []
      virtualNetworkRules: []
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
  }
}

// The store's one way in (AZ32c-2): its blob service at a private address in the endpoints subnet.
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

// Azure keeps the endpoint's A record in the zone the network resolves through, so the API's URL is unchanged.
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

// No versions and no soft delete: either would keep a file past its two weeks.
resource blobs 'Microsoft.Storage/storageAccounts/blobServices@2025-01-01' = {
  parent: account
  name: 'default'
  properties: {
    isVersioningEnabled: false
    deleteRetentionPolicy: {
      enabled: false
    }
  }
}

resource container 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-01-01' = {
  parent: blobs
  name: activityDownloadsContainerName()
  properties: {
    publicAccess: 'None'
  }
}

// Every file deleted 14 days after it is made (decisions 31, 32e). A download
// reads ready 7 days from its last file and is given up past 6 days building,
// so its first file may be 13 days old when the API stops offering it; the
// API refuses every read past its 7 days, and this deletes what it no longer
// reads. Azure runs the rule about once a day, so a file goes within a day
// after.
resource lifecycle 'Microsoft.Storage/storageAccounts/managementPolicies@2025-01-01' = {
  parent: account
  name: 'default'
  properties: {
    policy: {
      rules: [
        {
          name: 'delete-after-two-weeks'
          enabled: true
          type: 'Lifecycle'
          definition: {
            filters: {
              blobTypes: [
                'blockBlob'
              ]
              prefixMatch: [
                '${activityDownloadsContainerName()}/'
              ]
            }
            actions: {
              baseBlob: {
                delete: {
                  daysAfterCreationGreaterThan: 14
                }
              }
            }
          }
        }
      ]
    }
  }
}

resource keeper 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = [
  for each in keepers: {
    name: each.identity
  }
]

// Defined in the partner's `access` deployment (modules/roles.bicep, AZ5), never by CI: given here by name.
resource downloadsRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' existing = {
  name: guid(resourceGroup().id, 'activity-downloads')
}

resource keeps 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for (each, index) in keepers: {
    scope: container
    name: guid(container.id, keeper[index].id, downloadsRole.id)
    properties: {
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', downloadsRole.name)
      principalId: keeper[index].properties.principalId
      principalType: 'ServicePrincipal'
      description: '${each.workload} keeps activity downloads (deploy/azure/modules/activity-downloads.bicep)'
    }
  }
]

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
