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

@description('The main workspace, which keeps the activity log of the subscription (main.bicep `activity-log-to-workspace`).')
param workspaceId string

@description('Who the alert on the other writes of CI tells.')
param actionGroupId string

@description('The name of that alert.')
param alertName string

@description('The API app, which CI writes on a release.')
param apiName string

@description('The migration job, which CI writes and starts on a release.')
param migrateName string

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

// Anything CI's identity does in Azure but a release's three writes (AZ2): any
// other write, delete or action, and any of the three on another resource, even
// one Azure refused (a refusal is in the activity log too, under the same
// caller). A release writes the API, writes the migration job and starts it,
// nothing else (release.ts); its role allows little more (rule
// `release-identity`), so a line here is CI's sign-in used by something else,
// or a change to the release that needs this list changed with it.
// - who did it is read from the sign-in's own claim naming the identity
//   (`xms_mirid`, its resource id, in every line of CI's in staging's activity
//   log, S188), compared without case: known when this is deployed, where the
//   identity's principal ID is known only after
// - what a write changed it can't see: Microsoft.App writes carry no request
//   body in the activity log (none of 2,500+ in staging's 30 days, S188), so a
//   stolen sign-in that rewrites migrate's command and starts it passes as a
//   release here, and the job-start watch (#594), which compares a run with the
//   job as it is, sees nothing either. Written down (AZ2 report): the fix reads
//   the live API and migrate templates against the commit's
// - the activity log reaches the workspace minutes late, so each run reads the
//   hour before and fires on any line in it: one write tells someone up to four
//   times, and one up to 45 minutes late still does
var apiId = resourceId('Microsoft.App/containerApps', apiName)
var migrateId = resourceId('Microsoft.App/jobs', migrateName)

resource otherWrites 'Microsoft.Insights/scheduledQueryRules@2026-03-01' = {
  name: alertName
  location: location
  tags: tags
  kind: 'LogAlert'
  properties: {
    displayName: 'CI: its Azure sign-in did something besides a release'
    description: 'SEV-1. The Azure identity of CI wrote, deleted or ran something besides the three steps of a release (write the API, write the migration job, start it), or tried to and Azure refused. Either its sign-in is being used by something else, or a change to the release needs this alert changed with it: treat it as a possible break-in until shown otherwise. Runbook: Incident-Response-Playbook.md section B.'
    severity: 1
    enabled: true
    scopes: [workspaceId]
    evaluationFrequency: 'PT15M'
    windowSize: 'PT1H'
    // The table appears with the activity log's first line, which may come after this rule exists.
    skipQueryValidation: true
    criteria: {
      allOf: [
        {
          query: 'AzureActivity | where tostring(parse_json(Claims).xms_mirid) =~ "${release.id}" | where not((OperationNameValue =~ "Microsoft.App/containerApps/write" and _ResourceId =~ "${apiId}") or (OperationNameValue in~ ("Microsoft.App/jobs/write", "Microsoft.App/jobs/start/action") and _ResourceId =~ "${migrateId}")) | summarize Writes = count()'
          timeAggregation: 'Total'
          metricMeasureColumn: 'Writes'
          operator: 'GreaterThan'
          threshold: 0
          failingPeriods: {
            numberOfEvaluationPeriods: 1
            minFailingPeriodsToAlert: 1
          }
        }
      ]
    }
    // Stateless: every window holding one notifies again.
    autoMitigate: false
    actions: {
      actionGroups: [actionGroupId]
    }
  }
}

@description('The identity CI signs in as: its client ID goes into the GitHub environment (not a secret).')
output clientId string = release.properties.clientId
