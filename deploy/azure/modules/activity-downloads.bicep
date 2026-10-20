// Where the activity log's background downloads are kept (Phase 3 L5c, partner
// decision 31). The API builds each file a block at a time and later hands it
// out a part at a time, as its own identity (packages/platform/src/storage/
// block-store.ts): `<org>/<export>/<YYYY-MM>-try<n>.<csv|ndjson>.gz`. It never
// deletes one; the lifecycle rule below does, two weeks after.
//
// - shut as the audit exports' store is (evidence.bicep): shared keys off, so
//   every request signs in with Entra; no public blob access; no copying in
//   from another tenant; requests only from the apps subnet, through its
//   Storage service endpoint (PL-43: a private endpoint before live)
// - but not write-once: a month built again after a stop is written over the
//   same name. So no immutability, and versioning off, since a version kept of
//   each overwrite would outlive the lifecycle rule, which deletes the file only
// - one copy in both environments (LRS): a file lost is asked for again, and
//   nothing here is the only copy of anything (the activity log is in Postgres)
// - the API's identity may read and write a file in the one container and
//   nothing else: it can't delete one, or change the account or its rules
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
param appsSubnetId string
param workspaceId string
param apiIdentityName string

@description('A custom role\'s name is the whole directory\'s, so it carries the environment and the suffix.')
param roleName string

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
// reads ready 7 days from its last file and builds for under 7 days, so its
// first file may be nearly 14 days old when the API stops offering it; the
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

// Created by the foundation (environment.bicep) under this name.
resource api 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing = {
  name: apiIdentityName
}

// Read a part of a file (Get Blob), and write one a block at a time (Put
// Block, Put Block List), over a file of the same name; nothing else.
resource downloadsRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(resourceGroup().id, 'activity-downloads')
  properties: {
    roleName: roleName
    description: 'The API\'s activity log downloads: read and write a file in the downloads container. Nothing else.'
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
          'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write'
        ]
        notDataActions: []
      }
    ]
  }
}

resource keeps 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: container
  name: guid(container.id, api.id, downloadsRole.id)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', downloadsRole.name)
    principalId: api.properties.principalId
    principalType: 'ServicePrincipal'
    description: 'api keeps activity downloads (deploy/azure/modules/activity-downloads.bicep)'
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
