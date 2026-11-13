// Every custom role our deployments give in the resource group (AZ5): defined
// here, in the partner's own `access` deployment, and given by the foundation
// and the apps deployment by name alone. CI's approved infrastructure deploy
// can't write a role definition, so no approved run can widen a role it, CI's
// release or the job watch is given. Each keeps the name and the words it had
// in the module that gives it (moved, S190), so Azure keeps the same role.
import { jobWatchRoleName, releaseRoleName } from '../names.bicep'

targetScope = 'resourceGroup'

@description('Each role\'s display name, which carries the environment and the suffix: a custom role\'s name is the whole directory\'s.')
param displayNames object

// Put Blob of a file that isn't there yet, and nothing else (Microsoft:
// `blobs/write` would also overwrite one, `blobs/read` read it back).
resource writerRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(resourceGroup().id, 'evidence-writer')
  properties: {
    roleName: displayNames.evidenceWriter
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

// Put Blob of a file that isn't there yet; Get Blob and List Blobs, which a
// restart needs (Microsoft: both are `blobs/read`). Never `blobs/write`, which
// would overwrite one, or `blobs/delete`.
resource anchorRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(resourceGroup().id, 'audit-anchors')
  properties: {
    roleName: displayNames.anchors
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

// Get Blob and List Blobs (both `blobs/read`), and nothing else: the chain
// repair (4D2e E10) checks a repair against the anchors and adds none.
resource anchorReaderRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(resourceGroup().id, 'audit-anchors-reader')
  properties: {
    roleName: displayNames.anchorsReader
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

// Get Blob and List Blobs on the exports container (both `blobs/read`), and
// nothing else: the chain repair reads the plan it is asked to apply (4D2e E10).
resource planReaderRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(resourceGroup().id, 'evidence-plan-reader')
  properties: {
    roleName: displayNames.plansReader
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

// Read a part of a file (Get Blob), and write one a block at a time (Put
// Block, Put Block List), over a file of the same name; nothing else.
resource downloadsRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(resourceGroup().id, 'activity-downloads')
  properties: {
    roleName: displayNames.activityDownloads
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

// CI's role (G4): given on the API and the migration job alone, by the apps
// deployment (policy rule `release-access`). No linked action
// (`managedEnvironments/join`, `userAssignedIdentities/assign`): Azure checks a
// linked action for a linked property a request carries, and CI's partial update
// (a PATCH of the template alone) carries neither (microsoft/azure-container-apps
// issue 530); CI's first run proved it (G4-4).
resource releaseRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: releaseRoleName(resourceGroup().id)
  properties: {
    roleName: displayNames.release
    description: 'CI after a merge: update our image in the API and the migration job, and run the migration. Nothing else.'
    type: 'CustomRole'
    assignableScopes: [
      resourceGroup().id
    ]
    permissions: [
      {
        actions: [
          'Microsoft.App/containerApps/read'
          'Microsoft.App/containerApps/write'
          'Microsoft.App/containerApps/revisions/read'
          'Microsoft.App/jobs/read'
          'Microsoft.App/jobs/write'
          'Microsoft.App/jobs/start/action'
          'Microsoft.App/jobs/executions/read'
          'Microsoft.App/jobs/execution/read'
        ]
        notActions: []
        dataActions: []
        notDataActions: []
      }
    ]
  }
}

// The job-start watch's role (S175): Azure names both read actions on a run
// (`jobs/executions/read` lists them, `jobs/execution/read` reads one).
resource jobWatchRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: jobWatchRoleName(resourceGroup().id)
  properties: {
    roleName: displayNames.jobWatch
    description: 'The job-start watch: read the jobs and their runs. Nothing else.'
    type: 'CustomRole'
    assignableScopes: [
      resourceGroup().id
    ]
    permissions: [
      {
        actions: [
          'Microsoft.App/jobs/read'
          'Microsoft.App/jobs/executions/read'
          'Microsoft.App/jobs/execution/read'
        ]
        notActions: []
        dataActions: []
        notDataActions: []
      }
    ]
  }
}
