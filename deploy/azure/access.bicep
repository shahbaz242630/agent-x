// Who may do what, and what Azure itself refuses (AZ5): the partner's own
// deployment, never CI's, so no approved infrastructure deploy can widen a
// role, weaken a guardrail, or stop the record of who changed what.
//
//   node deploy/azure/deploy.ts access   # the partner's own terminal, after the foundation
//
// - every custom role our deployments give (modules/roles.bicep), by the same
//   names they had in the foundation (moved, S190): Azure keeps each role
// - the live database server's delete lock (S185, modules/server-lock.bicep)
// - the main workspace's delete lock (AZ5e, modules/workspace-lock.bicep): the
//   access alarm reads it, so CI may not delete it
// - Azure's own refusals on the resource group (guardrails.bicep, AZ2)
// - the subscription's activity log into the main workspace (ADR-012 §6)
// - the budget
//
// A new environment runs foundation (its grants of these roles fail, the rest
// is made), then access, then foundation again. A new database generation
// (playbook L) runs access after the foundation that made its server, to lock it. The rules (policy.ts) check this
// deployment with the rest of the environment.
import { resourceNames, uniqueSuffix } from 'names.bicep'

targetScope = 'subscription'

@description('Which environment this is (main.bicep).')
@allowed([
  'staging'
  'production'
])
param environment string

@description('As main.bicep\'s: the names that must be unique across Azure.')
@minLength(4)
@maxLength(6)
param nameSuffix string = uniqueSuffix(subscription().id)

@description('Who the budget\'s emails go to: the alert address (main.bicep).')
param alertEmail string

@description('The monthly budget in the subscription\'s currency; emails go out at 50%, 80% and 100% of it, and when the month\'s forecast passes it.')
@minValue(10)
param budgetAmount int

@description('The first day of the budget\'s first month (yyyy-MM-01). Kept fixed: a budget\'s start date is not moved on redeploys.')
param budgetStartDate string

var names = resourceNames(environment, nameSuffix)

// The foundation's workspace, by name: it exists before this runs.
var workspaceId = resourceId(
  subscription().subscriptionId,
  names.group,
  'Microsoft.OperationalInsights/workspaces',
  names.workspace
)

// Each display name as the foundation wrote it, so the roles keep theirs.
module roles 'modules/roles.bicep' = {
  scope: resourceGroup(names.group)
  params: {
    displayNames: {
      evidenceWriter: 'Agent X evidence writer (${environment} ${nameSuffix})'
      anchors: 'Agent X audit anchors (${environment} ${nameSuffix})'
      anchorsReader: 'Agent X audit anchors reader (${environment} ${nameSuffix})'
      plansReader: 'Agent X recovery plans reader (${environment} ${nameSuffix})'
      activityDownloads: 'Agent X activity downloads (${environment} ${nameSuffix})'
      release: names.releaseRole
      jobWatch: names.jobWatchRole
    }
  }
}

// The live database server's delete lock (S185): a lock is no write CI may make, nor lift.
module serverLock 'modules/server-lock.bicep' = {
  scope: resourceGroup(names.group)
  params: {
    serverName: names.server
  }
}

// The main workspace's delete lock (AZ5e): the access alarm reads the activity log from it.
module workspaceLock 'modules/workspace-lock.bicep' = {
  scope: resourceGroup(names.group)
  params: {
    workspaceName: names.workspace
  }
}

// Azure's own refusals on the resource group (AZ2): an app open to the internet or
// over plain http, an image not ours by digest, a job that starts itself, more
// replicas than we run, or a type we don't deploy, whoever sends it.
module guardrails 'modules/guardrails.bicep' = {
  params: {
    environment: environment
    groupName: names.group
  }
}

// Who changed what in this subscription, kept in the same workspace: every
// change is meant to come from this code (ADR-012 §6), so a change from
// anywhere else shows up here. The activity log costs nothing to collect.
resource activityLog 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'activity-log-to-workspace'
  properties: {
    workspaceId: workspaceId
    logs: [
      {
        category: 'Administrative'
        enabled: true
      }
      {
        category: 'Security'
        enabled: true
      }
      {
        category: 'Policy'
        enabled: true
      }
    ]
  }
}

// A cost alarm, not a limit: Azure keeps running when it is passed. Budget
// emails carry costs, never log data.
resource budget 'Microsoft.Consumption/budgets@2024-08-01' = {
  name: 'budget-agentx-${environment}'
  properties: {
    category: 'Cost'
    amount: budgetAmount
    timeGrain: 'Monthly'
    timePeriod: {
      startDate: budgetStartDate
    }
    notifications: {
      actual50: {
        enabled: true
        operator: 'GreaterThan'
        threshold: 50
        thresholdType: 'Actual'
        contactEmails: [alertEmail]
      }
      actual80: {
        enabled: true
        operator: 'GreaterThan'
        threshold: 80
        thresholdType: 'Actual'
        contactEmails: [alertEmail]
      }
      actual100: {
        enabled: true
        operator: 'GreaterThan'
        threshold: 100
        thresholdType: 'Actual'
        contactEmails: [alertEmail]
      }
      forecast100: {
        enabled: true
        operator: 'GreaterThan'
        threshold: 100
        thresholdType: 'Forecasted'
        contactEmails: [alertEmail]
      }
    }
  }
}
