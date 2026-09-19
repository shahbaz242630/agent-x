// The Container Apps environment (ADR-002; ADR-002 Amendment G2b): where the
// apps and jobs run, in the apps subnet of our private network (network.bicep).
// This deployment, run by hand with a what-if first, creates the environment
// and one identity per app and job. The apps and jobs themselves come in their
// own deployment (G2d), also run by hand; CI only moves our image (G4).
//
// - workload profiles, Consumption only: nothing is billed while nothing runs,
//   but the network's load balancer and IPs (ADR-002 Amendment G1)
// - external: it has a public IP, and the only public doors will be the route
//   configs (G2e); every app's own ingress stays internal
// - peer-to-peer encryption: traffic inside the environment (the proxy to each
//   app, one app to another) is TLS too, with certificates the platform manages
// - logs go through Azure Monitor (a diagnostic setting, so no shared key;
//   ADR-013 Amendment G1): the apps' console and the platform's system logs.
//   The platform's HTTP log is never sent: it records every client's address
//   and full URL, which our own request logs leave out (ADR-011 §7)
// - every error event the apps write is counted by an alert, and a saved query
//   in the workspace lists them by type
// - an audit chain that fails its check raises a SEV-1 alert of its own

param location string
param name string
param tags object
param appsSubnetId string
param zoneRedundant bool
@description('One per app and job, so each can be given only its own secrets (G2c).')
param identityNames array
param workspaceName string
param workspaceId string
param actionGroupId string
param errorAlertName string
param errorAlertThreshold int
param integrityAlertName string

resource environment 'Microsoft.App/managedEnvironments@2026-01-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    vnetConfiguration: {
      infrastructureSubnetId: appsSubnetId
      internal: false
    }
    workloadProfiles: [
      {
        name: 'Consumption'
        workloadProfileType: 'Consumption'
      }
    ]
    appLogsConfiguration: {
      destination: 'azure-monitor'
    }
    peerTrafficConfiguration: {
      encryption: {
        enabled: true
      }
    }
    publicNetworkAccess: 'Enabled'
    // Microsoft: it can only be set when the environment is created, so each
    // environment's parameters say it outright.
    zoneRedundant: zoneRedundant
  }
}

// Only these two categories, never a category group: `allLogs` would bring the
// HTTP log in with it.
resource appLogs 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: environment
  name: 'app-logs-to-workspace'
  properties: {
    workspaceId: workspaceId
    // Resource-specific tables (ContainerAppConsoleLogs, ContainerAppSystemLogs).
    logAnalyticsDestinationType: 'Dedicated'
    logs: [
      {
        category: 'ContainerAppConsoleLogs'
        enabled: true
      }
      {
        category: 'ContainerAppSystemLogs'
        enabled: true
      }
    ]
  }
}

// Usable only by resources in this region (isolation scope Regional, as
// Microsoft recommends): an app created anywhere else can't take one on.
resource identities 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' = [
  for identityName in identityNames: {
    name: identityName
    location: location
    tags: tags
    properties: {
      isolationScope: 'Regional'
    }
  }
]

// Error events: our logger and the login pages write `"level":"error"`; Zitadel
// writes "ERROR" in its newer lines and "error", "fatal" or "panic" in its
// older ones, so the match ignores case (`in~`). A line that isn't JSON counts
// as nothing here.
var errorLines = 'ContainerAppConsoleLogs | where tostring(parse_json(Log).level) in~ ("error", "fatal", "panic")'

resource workspace 'Microsoft.OperationalInsights/workspaces@2025-02-01' existing = {
  name: workspaceName
}

// Where to look first (Incident-Response-Playbook.md section 2). It returns
// rows, which is fine: a saved query runs only for someone signed in to Azure,
// inside the workspace in UAE North. Saved in the workspace rather than a query
// pack, which is a resource of its own with a region. Each service names its
// fields its own way: the event is our `event`, Zitadel's `msg` or the login
// pages' `message`; the error type is our `err.type`, or Zitadel's `err.id`
// or `err.kind`.
resource errorsByType 'Microsoft.OperationalInsights/workspaces/savedSearches@2025-07-01' = {
  parent: workspace
  name: 'agentx-errors-by-type'
  properties: {
    category: 'Agent X'
    displayName: 'Errors by type'
    query: '${errorLines} | extend Line = parse_json(Log) | summarize Errors = count(), Latest = max(TimeGenerated) by Service = coalesce(tostring(Line.service), ContainerAppName, JobName), Event = coalesce(tostring(Line.event), tostring(Line.msg), tostring(Line.message)), ErrorType = coalesce(tostring(Line.err.type), tostring(Line.err.id), tostring(Line.err.kind)) | order by Latest desc'
    version: 2
  }
}

// The error spike alert (logging standard §5), as a count (ADR-013 rule 3).
resource errorAlert 'Microsoft.Insights/scheduledQueryRules@2026-03-01' = {
  name: errorAlertName
  location: location
  tags: tags
  kind: 'LogAlert'
  properties: {
    displayName: 'Apps: error events'
    description: 'SEV-2. The apps wrote more than ${errorAlertThreshold} error events in 15 minutes; the saved query Errors by type shows which. Runbook: Incident-Response-Playbook.md section A.'
    severity: 2
    enabled: true
    scopes: [workspaceId]
    evaluationFrequency: 'PT15M'
    windowSize: 'PT15M'
    // The table appears with the first app's first log line, after this rule exists.
    skipQueryValidation: true
    criteria: {
      allOf: [
        {
          query: '${errorLines} | summarize Errors = count()'
          timeAggregation: 'Total'
          metricMeasureColumn: 'Errors'
          operator: 'GreaterThan'
          threshold: errorAlertThreshold
          failingPeriods: {
            numberOfEvaluationPeriods: 1
            minFailingPeriodsToAlert: 1
          }
        }
      ]
    }
    // Stateful: it fires once and resolves after a quiet window, rather than
    // notifying every 15 minutes through a long incident.
    autoMitigate: true
    actions: {
      actionGroups: [actionGroupId]
    }
  }
  dependsOn: [appLogs]
}

// The integrity alarm (ADR-012 §2, SEC-DB-11): the API's anchor check found an
// audit chain changed, removed or wound back, or couldn't check it for three
// intervals, or the check itself broke (`audit.integrity_failed`,
// `audit.anchor_check_crashed`). A start refused on a broken platform chain
// logs the first too. Only the count leaves the workspace; the lines say
// which chain and why.
resource integrityAlert 'Microsoft.Insights/scheduledQueryRules@2026-03-01' = {
  name: integrityAlertName
  location: location
  tags: tags
  kind: 'LogAlert'
  properties: {
    displayName: 'Audit: a chain failed its integrity check'
    description: 'SEV-1. The API found an audit chain changed, removed or wound back, could not check it for three intervals, or its check broke (audit.integrity_failed, audit.anchor_check_crashed). Runbook: Incident-Response-Playbook.md section H.'
    severity: 1
    enabled: true
    scopes: [workspaceId]
    evaluationFrequency: 'PT15M'
    windowSize: 'PT15M'
    // The table appears with the first app's first log line, after this rule exists.
    skipQueryValidation: true
    criteria: {
      allOf: [
        {
          query: 'ContainerAppConsoleLogs | where tostring(parse_json(Log).event) in ("audit.integrity_failed", "audit.anchor_check_crashed") | summarize Events = count()'
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
    // Stateless: every 15 minutes the check still fails notifies again.
    autoMitigate: false
    actions: {
      actionGroups: [actionGroupId]
    }
  }
  dependsOn: [appLogs]
}

output name string = environment.name
