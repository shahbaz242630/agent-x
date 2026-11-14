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
//   (the subscription's activity log goes there, access.bicep), which the
//   partner's access locks against deletion (review S192)
// - what could still blind it, the workspace rewritten (its daily cap lowered,
//   so the lines never arrive) or an alarm, action group or log setting deleted,
//   and a trust written, the infra identity's alone, go to Azure's own activity
//   log alert below, which reads no workspace and so no cap
// - and a health alarm if the query itself stops running whole
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

@description('The principal ID of CI infra identity: the activity log names the writes of a managed identity by it.')
param infraPrincipalId string

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
  'Microsoft.Authorization/policySetDefinitions/write'
  'Microsoft.Authorization/policySetDefinitions/delete'
  // An exemption switches a guardrail off without touching it.
  'Microsoft.Authorization/policyExemptions/write'
  'Microsoft.Authorization/policyExemptions/delete'
  'Microsoft.Authorization/locks/delete'
  // The vault is RBAC-only; an access policy would read secrets with no grant.
  'Microsoft.KeyVault/vaults/accessPolicies/write'
]

// What would blind the log alarm, or open a door no Approve shows, by the infra identity (review S192). An approved
// foundation rewrites the workspace and its two trusts: about three emails an Approve, expected then; one in an
// Approve with no foundation step is an anomaly. A cap lowered inside an approved foundation looks routine here
// (AZ5g: a guardrail on the cap). Rewrites of staging's own alert rules and action group are left out on purpose:
// every foundation rewrites them all (monitoring.bicep's alert-rules alarm emails each one); the deletes are here.
var blinding = [
  'Microsoft.OperationalInsights/workspaces/write'
  'Microsoft.OperationalInsights/workspaces/delete'
  'Microsoft.Insights/diagnosticSettings/delete'
  'Microsoft.Insights/actionGroups/delete'
  'Microsoft.Insights/scheduledQueryRules/delete'
  'Microsoft.Insights/activityLogAlerts/delete'
  'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write'
  'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/delete'
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
    // No skipped validation: the table holds the activity log already, so a typo fails the deploy, not silently.
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

// The log alarm's own path cut, or a trust written, by CI's infra identity: Azure's activity log alert reads no
// workspace, so neither a lowered cap nor a deleted workspace hides it. Each event emails once, naming the caller.
resource pathChanged 'Microsoft.Insights/activityLogAlerts@2026-01-01' = {
  name: 'alert-agentx-${short}-access-path-changed'
  location: 'Global'
  tags: tags
  properties: {
    description: 'SEV-1. The infra identity of CI rewrote or deleted the log workspace (its daily cap among the settings), deleted an alert rule, an action group or a log setting, or wrote or deleted a federated credential (trust in GitHub). Expected, about three emails, right after the partner taps Approve on an infrastructure deploy. At any other time the access alarm may be being blinded before a change: treat it as a possible break-in. Runbook: Incident-Response-Playbook.md section B.'
    enabled: true
    scopes: [
      subscription().id
    ]
    condition: {
      allOf: [
        {
          field: 'category'
          equals: 'Administrative'
        }
        {
          field: 'caller'
          equals: infraPrincipalId
        }
        {
          field: 'status'
          equals: 'Succeeded'
        }
        {
          anyOf: [
            for operation in blinding: {
              field: 'operationName'
              equals: operation
            }
          ]
        }
      ]
    }
    actions: {
      actionGroups: [
        {
          actionGroupId: partner.id
        }
      ]
    }
  }
}

// The log alarm reported as no longer running whole (as monitoring.bicep's rulesUnhealthy, for this group).
resource alarmUnhealthy 'Microsoft.Insights/activityLogAlerts@2026-01-01' = {
  name: 'alert-agentx-${short}-access-alarm-unhealthy'
  location: 'Global'
  tags: tags
  properties: {
    description: 'SEV-1. Azure reports the access alarm degraded or unavailable: its query fails (the workspace unreadable, a table renamed) or it was switched off. Until it runs again, an app changing who may do what tells nobody. Runbook: Incident-Response-Playbook.md section I.'
    enabled: true
    scopes: [
      resourceGroup().id
    ]
    condition: {
      allOf: [
        {
          field: 'category'
          equals: 'ResourceHealth'
        }
        {
          field: 'resourceType'
          equals: 'Microsoft.Insights/scheduledQueryRules'
        }
        {
          anyOf: [
            {
              field: 'properties.currentHealthStatus'
              equals: 'Degraded'
            }
            {
              field: 'properties.currentHealthStatus'
              equals: 'Unavailable'
            }
          ]
        }
      ]
    }
    actions: {
      actionGroups: [
        {
          actionGroupId: partner.id
        }
      ]
    }
  }
}
