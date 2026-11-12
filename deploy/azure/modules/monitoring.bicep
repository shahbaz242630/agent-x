// In-country monitoring (ADR-013): the log workspaces in UAE North, their caps,
// and the alerts that watch them. Everything the app and the platform log lands
// in the main one; nothing leaves the UAE but alert notifications, and those
// carry counts only.
//
// A second, small workspace holds only what the database login alerts read
// (4D2e Stage F, PR 9): Postgres's server log and a copy of the Container Apps
// platform's lines. A day that fills the main one's cap stops its collecting,
// and the login alerts went blind with it; this one's own cap is never reached
// by the apps' volume, and reaching it is a SEV-1 of its own.
//
// Alert rules follow ADR-013 rule 3 and the logging standard §5:
// - every query ends in one summarize with no `by`, so it returns one number,
//   never log rows, and no rule splits by a dimension (a policy check enforces
//   both, deploy/azure/policy.ts)
// - every description names its severity and its runbook section in
//   Incident-Response-Playbook.md
// - severities: our SEV-1 is Azure's 1 (Error), SEV-2 is 2 (Warning)

param location string
param short string
param workspaceName string
@description('The login alerts\' own workspace (postgres.bicep reads it).')
param loginWorkspaceName string
param actionGroupName string
param tags object
param alertEmail string
param logDailyCapGb int

// Each workspace, with how its alerts name it and what its cap stopping blinds. The login alerts' cap is 1 GB in
// every environment: what it holds is a few MB a day (Incident-Response-Playbook.md section J), so only a flood of
// logins or connections reaches it, and that flood is itself the thing to look at, at once (SEV-1).
var workspaces = [
  {
    name: workspaceName
    capGb: logDailyCapGb
    alertPrefix: 'log'
    title: 'Log quota'
    what: 'The workspace'
    // Every alert reading this workspace is blind, the tamper and jobs-stopped ones among them (S183: those
    // stay quiet while it is over, so this says it): as loud as the login workspace's.
    blind: 'monitoring is blind until then, the tamper and jobs-stopped alerts among it'
    capSeverity: 1
  }
  {
    name: loginWorkspaceName
    capGb: 1
    alertPrefix: 'login-logs'
    title: 'Login logs'
    what: 'The login alerts\' workspace'
    blind: 'both database login alerts are blind until then, and a login meanwhile is never seen'
    capSeverity: 1
  }
]

resource workspace 'Microsoft.OperationalInsights/workspaces@2025-02-01' = [
  for space in workspaces: {
    name: space.name
    location: location
    tags: tags
    properties: {
      sku: {
        name: 'PerGB2018'
      }
      // Included in the price of Analytics logs (ADR-013 rule 7).
      retentionInDays: 31
      // A backstop, never the main control: the logger's own per-event caps are
      // (ADR-013 rule 6). Hitting it stops collection until the next day.
      workspaceCapping: {
        dailyQuotaGb: space.capGb
      }
      features: {
        // No shared keys: the platform sends logs through diagnostic settings,
        // which need none, so there is no key to leak (ADR-002 Amendment G1).
        disableLocalAuth: true
        // Access follows Azure roles on each resource (ADR-013 rule 8).
        enableLogAccessUsingOnlyResourcePermissions: true
      }
      publicNetworkAccessForIngestion: 'Enabled'
      publicNetworkAccessForQuery: 'Enabled'
    }
  }
]

// One group for every alert. Azure offers no UAE location for action groups;
// "Global" means any region may process them, which is why alerts carry only
// counts and a link that needs an Azure sign-in (ADR-013 rule 3).
resource partner 'Microsoft.Insights/actionGroups@2023-01-01' = {
  name: actionGroupName
  location: 'Global'
  tags: tags
  properties: {
    groupShortName: 'agentx-${short}'
    enabled: true
    emailReceivers: [
      {
        name: 'partner-email'
        emailAddress: alertEmail
        useCommonAlertSchema: true
      }
    ]
    azureAppPushReceivers: [
      {
        name: 'partner-app'
        emailAddress: alertEmail
      }
    ]
  }
}

// The 80% warning (ADR-013 rule 6, SEC-AV-09). Log Analytics has no built-in
// warning before its cap (Microsoft), so this sums the billable data of the
// last 24 hours. That sum is never below what counts towards today's cap, so
// the alert fires no later than the real 80% point. Usage counts in MB.
resource quotaWarning 'Microsoft.Insights/scheduledQueryRules@2026-03-01' = [
  for (space, index) in workspaces: {
    name: 'alert-agentx-${short}-${space.alertPrefix}-quota'
    location: location
    tags: tags
    kind: 'LogAlert'
    properties: {
      displayName: '${space.title}: 80% of the daily cap'
      description: 'SEV-2. ${space.what} took in more than 80% of its daily cap in the last 24 hours; at 100% it stops collecting until the next day. Runbook: Incident-Response-Playbook.md section J.'
      severity: 2
      enabled: true
      scopes: [workspace[index].id]
      evaluationFrequency: 'PT1H'
      windowSize: 'P1D'
      criteria: {
        allOf: [
          {
            query: 'Usage | where IsBillable | summarize IngestedMb = sum(Quantity)'
            timeAggregation: 'Maximum'
            metricMeasureColumn: 'IngestedMb'
            operator: 'GreaterThan'
            threshold: space.capGb * 800
            failingPeriods: {
              numberOfEvaluationPeriods: 1
              minFailingPeriodsToAlert: 1
            }
          }
        ]
      }
      autoMitigate: true
      actions: {
        actionGroups: [partner.id]
      }
    }
  }
]

// The cap itself was reached: Microsoft's own recommended rule, as a count. A
// SEV-1 is stateless (policy.ts), so it notifies on every window with the event.
resource capReached 'Microsoft.Insights/scheduledQueryRules@2026-03-01' = [
  for (space, index) in workspaces: {
    name: 'alert-agentx-${short}-${space.alertPrefix}-cap-reached'
    location: location
    tags: tags
    kind: 'LogAlert'
    properties: {
      displayName: '${space.title}: daily cap reached'
      description: 'SEV-${space.capSeverity}. ${space.what} reached its daily cap and stopped collecting logs until its daily reset; ${space.blind}. Runbook: Incident-Response-Playbook.md section J.'
      severity: space.capSeverity
      enabled: true
      scopes: [workspace[index].id]
      evaluationFrequency: 'PT15M'
      windowSize: 'PT15M'
      criteria: {
        allOf: [
          {
            query: '_LogOperation | where Category =~ "Ingestion" | where Detail contains "OverQuota" | summarize Events = count()'
            timeAggregation: 'Total'
            metricMeasureColumn: 'Events'
            operator: 'GreaterThan'
            threshold: 0
            failingPeriods: {
              numberOfEvaluationPeriods: 1
              minFailingPeriodsToAlert: 1
            }
          }
        ]
      }
      autoMitigate: space.capSeverity != 1
      actions: {
        actionGroups: [partner.id]
      }
    }
  }
]

// MO2: the alert rules themselves. Every rule above, and those in postgres.bicep and environment.bicep, is a resource
// someone with rights could switch off, rewrite or delete, after which it tells nobody; and a rule whose query stops
// running (a table or column renamed) tells nobody either. Activity log alerts watch both: they read Azure's own
// record of changes and health, cost nothing, and need no workspace, so neither workspace's cap blinds them. Each
// notifies once an event, as a stateless SEV-1 does. Global, as Azure offers them; the email names the rule, the
// caller and the caller's address, which ADR-013 Amendment MO2 allows beside rule 3's counts-only.
var group = resourceGroup().id

// Each change that succeeded to an alert rule of any kind, to the action group they notify, or to an alert processing
// rule (one that removes action groups mutes every alert, these two included), by anyone: CI never writes them (its
// role can't), so outside a foundation deploy, which rewrites every rule, each is unexplained. And a diagnostic
// setting deleted: the login alerts would go on running, healthy, over a table nothing reaches. Deploys never delete
// one; writes to them and to the server's settings are left out, as every foundation deploy rewrites those.
var watchedChanges = [
  'Microsoft.Insights/scheduledQueryRules/write'
  'Microsoft.Insights/scheduledQueryRules/delete'
  'Microsoft.Insights/metricAlerts/write'
  'Microsoft.Insights/metricAlerts/delete'
  'Microsoft.Insights/activityLogAlerts/write'
  'Microsoft.Insights/activityLogAlerts/delete'
  'Microsoft.Insights/actionGroups/write'
  'Microsoft.Insights/actionGroups/delete'
  'Microsoft.AlertsManagement/actionRules/write'
  'Microsoft.AlertsManagement/actionRules/delete'
  'Microsoft.Insights/diagnosticSettings/delete'
]

resource rulesChanged 'Microsoft.Insights/activityLogAlerts@2026-01-01' = {
  name: 'alert-agentx-${short}-alert-rules-changed'
  location: 'Global'
  tags: tags
  properties: {
    description: 'SEV-1. An alert rule, the action group or an alert processing rule in this resource group was changed, switched off or deleted, or a log setting of a resource was deleted. A foundation deploy rewrites every rule, one email each; at any other time someone may be silencing the alarms before acting. The email names the rule and who did it. Runbook: Incident-Response-Playbook.md section I.'
    enabled: true
    scopes: [group]
    condition: {
      allOf: [
        {
          field: 'category'
          equals: 'Administrative'
        }
        {
          field: 'status'
          equals: 'Succeeded'
        }
        {
          anyOf: [
            for operation in watchedChanges: {
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

// A log alert rule Azure reports as no longer running whole. Microsoft reports health for rules running every
// 15 minutes or more often; the slower ones (the 80% warnings, the daily summary) stay Unknown, which this never matches.
resource rulesUnhealthy 'Microsoft.Insights/activityLogAlerts@2026-01-01' = {
  name: 'alert-agentx-${short}-alert-rules-unhealthy'
  location: 'Global'
  tags: tags
  properties: {
    description: 'SEV-1. Azure reports a log alert rule in this resource group degraded or unavailable: its query fails (a table or column renamed, a syntax error, too slow), or it was switched off. Until it runs again, what it watches tells nobody. The email names the rule. Runbook: Incident-Response-Playbook.md section I.'
    enabled: true
    scopes: [group]
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
