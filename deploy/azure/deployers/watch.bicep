// The alarm on who may do what (AZ5e): a role grant or custom role, a trust in
// an outside sign-in (a federated credential), an Azure Policy rule written or
// deleted, or a lock deleted, anywhere in the subscription, by anything but a
// person: CI's identities, or any app's sign-in. With Approve deploys the
// partner's tap is the main stop, so such a write must be seen at once.
//
// - a person's are left out: the partner's own hand deploys rewrite every grant
//   (524 lines in staging's 14 days to 14 Nov, 57 deployments) and would bury it;
//   the apps' were one deployment's 12 lines, the first Approve (S191). Only the
//   partner, signed in with MFA, writes them by hand
// - here, in the deployers' own group, with its own action group: CI's infra
//   identity is Contributor on staging's group and could delete an alarm there
//   before acting; it has no rights in this group. It reads the main workspace
//   (the subscription's activity log goes there, access.bicep), which deleting
//   would stop every alert at once
// - the activity log reaches the workspace minutes late, so each run reads the
//   hour before: an Approve deploy emails up to four times, as CI's other alarm
// - an attempt Azure refused counts too: an identity trying to widen its rights
targetScope = 'resourceGroup'

param tags object
param short string
param location string

@description('The main workspace, which holds the activity log of the subscription.')
param workspaceId string

@description('The alert address, as the foundation has it.')
param alertEmail string

var watched = [
  'Microsoft.Authorization/roleAssignments/write'
  'Microsoft.Authorization/roleAssignments/delete'
  'Microsoft.Authorization/roleDefinitions/write'
  'Microsoft.Authorization/roleDefinitions/delete'
  'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write'
  'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/delete'
  'Microsoft.Authorization/policyAssignments/write'
  'Microsoft.Authorization/policyAssignments/delete'
  'Microsoft.Authorization/policyDefinitions/write'
  'Microsoft.Authorization/policyDefinitions/delete'
  'Microsoft.Authorization/locks/delete'
]
var operations = join(map(watched, operation => '"${operation}"'), ', ')

// Azure offers no UAE location for action groups (as monitoring.bicep's): the alert carries counts, not data.
resource partner 'Microsoft.Insights/actionGroups@2023-01-01' = {
  name: 'ag-agentx-${short}-deployers'
  location: 'Global'
  tags: tags
  properties: {
    groupShortName: 'agx-${short}-acc'
    enabled: true
    emailReceivers: [
      {
        name: 'partner-email'
        emailAddress: alertEmail
        useCommonAlertSchema: true
      }
    ]
  }
}

resource accessChanged 'Microsoft.Insights/scheduledQueryRules@2026-03-01' = {
  name: 'alert-agentx-${short}-access-changed'
  location: location
  tags: tags
  kind: 'LogAlert'
  properties: {
    displayName: 'Who may do what was changed by an app, not a person'
    description: 'SEV-1. An app or identity (not a person) wrote or deleted a role grant, a custom role, a federated credential (trust in GitHub) or an Azure Policy rule, or deleted a lock, anywhere in the subscription, or tried to and Azure refused. Expected right after the partner taps Approve on an infrastructure deploy. At any other time, treat it as a possible break-in: the activity log names the identity and what it changed. Runbook: Incident-Response-Playbook.md section B.'
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
          query: 'AzureActivity | where CategoryValue == "Administrative" | where OperationNameValue in~ (${operations}) | where Caller !has "@" | summarize Writes = count()'
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
      actionGroups: [partner.id]
    }
  }
}
