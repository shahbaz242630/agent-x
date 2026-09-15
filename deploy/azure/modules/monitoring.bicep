// In-country monitoring (ADR-013): the log workspace in UAE North, its cap, and
// the alerts that watch it. Everything the app and the platform log lands here;
// nothing leaves the UAE but alert notifications, and those carry counts only.
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
param actionGroupName string
param tags object
param alertEmail string
param logDailyCapGb int

resource workspace 'Microsoft.OperationalInsights/workspaces@2025-02-01' = {
  name: workspaceName
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
      dailyQuotaGb: logDailyCapGb
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
resource quotaWarning 'Microsoft.Insights/scheduledQueryRules@2026-03-01' = {
  name: 'alert-agentx-${short}-log-quota'
  location: location
  tags: tags
  kind: 'LogAlert'
  properties: {
    displayName: 'Log quota: 80% of the daily cap'
    description: 'SEV-2. The workspace took in more than 80% of its daily cap in the last 24 hours; at 100% it stops collecting until the next day. Runbook: Incident-Response-Playbook.md section D.'
    severity: 2
    enabled: true
    scopes: [workspace.id]
    evaluationFrequency: 'PT1H'
    windowSize: 'P1D'
    criteria: {
      allOf: [
        {
          query: 'Usage | where IsBillable | summarize IngestedMb = sum(Quantity)'
          timeAggregation: 'Maximum'
          metricMeasureColumn: 'IngestedMb'
          operator: 'GreaterThan'
          threshold: logDailyCapGb * 800
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

// The cap itself was reached: Microsoft's own recommended rule, as a count.
resource capReached 'Microsoft.Insights/scheduledQueryRules@2026-03-01' = {
  name: 'alert-agentx-${short}-log-cap-reached'
  location: location
  tags: tags
  kind: 'LogAlert'
  properties: {
    displayName: 'Log quota: daily cap reached'
    description: 'SEV-2. The workspace reached its daily cap and stopped collecting logs until its daily reset; monitoring is blind until then. Runbook: Incident-Response-Playbook.md section D.'
    severity: 2
    enabled: true
    scopes: [workspace.id]
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
    autoMitigate: true
    actions: {
      actionGroups: [partner.id]
    }
  }
}
