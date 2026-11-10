// The job-start watch's way into Azure (Carry-Forward S175): a scheduled GitHub
// workflow (.github/workflows/job-starts.yml) reads every job's recent runs and
// says any that ran other containers than its job's own
// (deploy/azure/job-starts.ts). This makes the identity it signs in as, its
// trust in GitHub, and its one role, given on the resource group: it may read
// the jobs and their runs, and nothing else (policy rule `job-watch`).
//
// - the trust is main's own subject (names.bicep jobWatchSubject): a job of
//   this repository running on main, which a scheduled run and one started by
//   hand there carry, and a run on another branch or a pull request's doesn't.
//   Not CI's environment subject, so the watch names no GitHub environment and
//   nothing about it can widen who signs in as CI
// - the role reads; it can't start, stop, change or list a secret. A job's own
//   read shows its settings' values but never a secret's (those take
//   `listSecrets`), so nothing the watch reads is a secret
// - given on the resource group, not on each job, so a job added later (the
//   load test's) is watched without a deployment of its own

import { jobWatchRoleName } from '../names.bicep'

param location string
param tags object
param identityName string
param roleName string

@description('The GitHub subject the watch signs in with (names.bicep jobWatchSubject).')
param subject string

// Usable only by resources in this region, like every identity here (it is
// given to none: it only signs in from GitHub).
resource watch 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' = {
  name: identityName
  location: location
  tags: tags
  properties: {
    isolationScope: 'Regional'
  }
}

resource github 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials@2024-11-30' = {
  parent: watch
  name: 'github'
  properties: {
    issuer: 'https://token.actions.githubusercontent.com'
    subject: subject
    audiences: [
      'api://AzureADTokenExchange'
    ]
  }
}

// Azure names both read actions on a run (`jobs/executions/read` lists them,
// `jobs/execution/read` reads one), as CI's role does.
resource role 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: jobWatchRoleName(resourceGroup().id)
  properties: {
    roleName: roleName
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

// A custom role is kept at the subscription wherever it is defined, so it is
// named in that form, as apps.bicep names CI's.
var watchRole = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', role.name)

resource readsJobs 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, watch.id, watchRole)
  properties: {
    description: 'The job-start watch reads the jobs and their runs (deploy/azure/modules/job-watch.bicep)'
    roleDefinitionId: watchRole
    principalId: watch.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

@description('The identity the watch signs in as: its client ID goes into the repository secret AZURE_WATCH_CLIENT_ID.')
output clientId string = watch.properties.clientId
