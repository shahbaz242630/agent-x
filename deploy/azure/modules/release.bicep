// CI's way into Azure (G4; ADR-002 "Deploying"): after every merge to main, a
// GitHub job updates our image in the API and the migration job, and starts
// the migration. This hand-run deployment makes the identity it signs in as,
// the trust that lets GitHub sign in without a stored credential, and the one
// role it may be given. The apps deployment gives that role on the few
// resources CI may touch (G4-2b); nothing here grants anything.
//
// - the trust names one GitHub subject: a job of this repository in the GitHub
//   environment of this environment's name. GitHub must let only main use that
//   environment before the role is given anywhere (G4-2b): a job on any other
//   branch that names it gets the same subject. Azure compares the subject
//   exactly, and a wrong one fails without an error
// - the role lists what an image update and a migration run need, and nothing
//   that reads a secret, opens a shell in a container, changes a door, or
//   grants access (policy rule `release-identity`)

import { releaseRoleName } from '../names.bicep'

param location string
param tags object
param identityName string
param roleName string

@description('The GitHub subject CI signs in with (names.bicep releaseSubject).')
param subject string

// Usable only by resources in this region, like every identity here (it is
// given to none: it only signs in from GitHub).
resource release 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' = {
  name: identityName
  location: location
  tags: tags
  properties: {
    isolationScope: 'Regional'
  }
}

// One trust per identity keeps it simple: Azure refuses two written at once.
resource github 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials@2024-11-30' = {
  parent: release
  name: 'github'
  properties: {
    issuer: 'https://token.actions.githubusercontent.com'
    subject: subject
    audiences: [
      'api://AzureADTokenExchange'
    ]
  }
}

// Assignable in this resource group only, and given on the API and the
// migration job alone (apps.bicep, policy rule `release-access`). No linked
// action (`managedEnvironments/join`, `userAssignedIdentities/assign`):
// - Azure checks a linked action for a linked property a request carries, on
//   the linked resource itself. CI's partial update (a PATCH of the template
//   alone, never a body read back from Azure) carries neither the environment
//   nor an identity, so it is expected to need neither: a reported REST PATCH
//   of the containers alone did without `join` (microsoft/azure-container-apps
//   issue 530). Nothing public shows a job's PATCH either way
// - CI's first run proves it (G4-4), failing closed if not. If they are
//   needed, they go on the environment and the two identities, not on the
//   app and the job, where they would satisfy nothing
resource role 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: releaseRoleName(resourceGroup().id)
  properties: {
    roleName: roleName
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

@description('The identity CI signs in as: its client ID goes into the GitHub environment (not a secret).')
output clientId string = release.properties.clientId
