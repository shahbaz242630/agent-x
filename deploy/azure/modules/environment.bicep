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
@description('The containers our own logger writes for (the API and its three jobs): only their plain words reach an alert email (decision 30).')
param ownLogNames array
param integrityAlertName string
param tokenRefusedAlertName string
param denialSurgeAlertName string
param holdingsCheckAlertName string
param integrityRunsAlertName string
param agentCancelsAlertName string
param agentCancelCapAlertName string
param dailyWordsAlertName string

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

// Each error line's plain words (decision 29), for the alert to split by.
// Notifications leave the UAE (ADR-013 rule 3), so only our own logger's
// words go: fixed text from plain-words.ts, public in the repo, cut to 300
// characters. Zitadel's and its login pages' lines get the fallback.
var ownLogList = join(map(ownLogNames, logName => '"${logName}"'), ', ')
var saysStages = 'extend Says = iff(coalesce(ContainerAppName, JobName) in (${ownLogList}), substring(tostring(parse_json(Log).says), 0, 300), "") | extend Says = iff(isempty(Says), "A warning or error with no plain words, from the login service or another part: open the saved query What broke, in plain words.", Says)'

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

// What broke, in plain words (decision 29): every warning and error line,
// each kind with its words, how often, and which organisations and requests,
// for the alert email's reader to look up in the country. Lines without words
// (Zitadel's, its login pages') show their own event or message.
resource whatBroke 'Microsoft.OperationalInsights/workspaces/savedSearches@2025-07-01' = {
  parent: workspace
  name: 'agentx-what-broke'
  properties: {
    category: 'Agent X'
    displayName: 'What broke, in plain words'
    query: 'ContainerAppConsoleLogs | extend Line = parse_json(Log) | extend Level = tolower(tostring(Line.level)), Event = coalesce(tostring(Line.event), tostring(Line.msg), tostring(Line.message)), OrgId = tostring(Line.orgId), Request = tostring(Line.correlationId) | where Level in ("warn", "warning", "error", "fatal", "panic") | extend Says = coalesce(tostring(Line.says), strcat("No plain words: ", Event)) | summarize Times = count(), Latest = max(TimeGenerated), Organisations = dcountif(OrgId, isnotempty(OrgId)), OrgIds = make_set_if(OrgId, isnotempty(OrgId), 20), Requests = make_set_if(Request, isnotempty(Request), 5) by Level, Service = coalesce(tostring(Line.service), ContainerAppName, JobName), Event, Says | order by Latest desc'
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
    description: 'SEV-2. The apps wrote more than ${errorAlertThreshold} error events of one kind in 15 minutes; the email names the kind in plain words, and the saved query What broke, in plain words shows which organisations and requests. Runbook: Incident-Response-Playbook.md section A.'
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
          query: '${errorLines} | ${saysStages} | summarize Errors = count() by Says'
          // One email a kind of error, naming it in plain words.
          dimensions: [
            {
              name: 'Says'
              operator: 'Include'
              values: ['*']
            }
          ]
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

// The daily email (decision 29, P4; partner, S128: one email a kind): once a
// day, each kind of warning or error the last day held, by its plain words and
// how many. Stateless, so it notifies every day it sees one; a clean day sends
// nothing. Azure runs it a day apart from when it was created.
resource dailyWords 'Microsoft.Insights/scheduledQueryRules@2026-03-01' = {
  name: dailyWordsAlertName
  location: location
  tags: tags
  kind: 'LogAlert'
  properties: {
    displayName: 'Apps: warnings and errors of the last day'
    description: 'SEV-2. The daily summary: the apps wrote this kind of warning or error in the last 24 hours, named in plain words, with how many times; the saved query What broke, in plain words shows which organisations and requests. Runbook: Incident-Response-Playbook.md section A.'
    severity: 2
    enabled: true
    scopes: [workspaceId]
    evaluationFrequency: 'P1D'
    windowSize: 'P1D'
    skipQueryValidation: true
    criteria: {
      allOf: [
        {
          query: 'ContainerAppConsoleLogs | where tostring(parse_json(Log).level) in~ ("warn", "warning", "error", "fatal", "panic") | ${saysStages} | summarize Times = count() by Says'
          dimensions: [
            {
              name: 'Says'
              operator: 'Include'
              values: ['*']
            }
          ]
          timeAggregation: 'Total'
          metricMeasureColumn: 'Times'
          operator: 'GreaterThan'
          threshold: 0
          failingPeriods: {
            numberOfEvaluationPeriods: 1
            minFailingPeriodsToAlert: 1
          }
        }
      ]
    }
    autoMitigate: false
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
// logs the first too, and so does the operator's command wherever the API
// would (B1c): its job logs to the same table. Only the count leaves the
// workspace; the lines say which chain and why.
resource integrityAlert 'Microsoft.Insights/scheduledQueryRules@2026-03-01' = {
  name: integrityAlertName
  location: location
  tags: tags
  kind: 'LogAlert'
  properties: {
    displayName: 'Audit: a chain failed its integrity check'
    description: 'SEV-1. The API or the operator\'s command found an audit chain changed, removed or wound back, could not check it for three intervals, or its check broke (audit.integrity_failed, audit.anchor_check_crashed). Runbook: Incident-Response-Playbook.md section H.'
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

// The login service refusing a token (partner, S88): the API's tokens at
// Zitadel end a person's sessions there at sign-out, remove a reset's second
// factors, read the factors a person holds and read people's addresses. A
// token that stopped working (expired, revoked, its role taken) would leave
// sign-out quietly ending ours alone, so any refusal tells someone at once.
// Every call logs it as the error type LoginTokenRefused (zitadel-call.ts),
// never for a login service that is only away or waking. Stateful: it fires
// once and resolves after a quiet window.
resource tokenRefusedAlert 'Microsoft.Insights/scheduledQueryRules@2026-03-01' = {
  name: tokenRefusedAlertName
  location: location
  tags: tags
  kind: 'LogAlert'
  properties: {
    displayName: 'Sign-in service: a token was refused'
    description: 'SEV-2. The login service refused one of the API tokens (401 or 403, logged as LoginTokenRefused): sign-out no longer ends the sessions there, resets and the factor checks wait, or notices wait for their addresses. Runbook: Incident-Response-Playbook.md section M.'
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
          query: 'ContainerAppConsoleLogs | where tostring(parse_json(Log).err.type) == "LoginTokenRefused" | summarize Events = count()'
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
      actionGroups: [actionGroupId]
    }
  }
  dependsOn: [appLogs]
}

// A denial surge (Phase 2 E2; Logging-and-Monitoring.md; ADR-014): one
// agent denied over and over is a runaway loop, a prompt injection probing
// its limits, or a mandate gone wrong. The API logs every decision as
// `spend_request.decided` with its decision and agent; REQUIRE_NEW_MANDATE is
// a denial too (PRD §4.2). The query counts each agent's denials in the window
// and returns the highest, one number with no ID dimensions (ADR-013): which
// agent it was is the saved query's to show, inside the workspace, each agent
// ranked by its busiest 15 minutes as the alert counts them (E2b review). More
// than 10 in 15 minutes is well above an agent that is only refused now and
// then. The windows meet end to end, so 10 either side of a boundary, or a slow
// 40 an hour, doesn't fire it: a first number, to tune on real traffic.
// Stateful: it fires once and resolves after a quiet window.
var denialLines = 'ContainerAppConsoleLogs | where tostring(parse_json(Log).event) == "spend_request.decided" | where tostring(parse_json(Log).decision) in ("DENY", "REQUIRE_NEW_MANDATE")'

resource denialsByAgent 'Microsoft.OperationalInsights/workspaces/savedSearches@2025-07-01' = {
  parent: workspace
  name: 'agentx-denials-by-agent'
  properties: {
    category: 'Agent X'
    displayName: 'Denials by agent'
    query: '${denialLines} | extend Line = parse_json(Log) | summarize Denials = count(), Reasons = make_set(tostring(Line.reasons), 10), Latest = max(TimeGenerated) by Organisation = tostring(Line.orgId), Agent = tostring(Line.agentId), Window = bin(TimeGenerated, 15m) | summarize Busiest15m = max(Denials), Total = sum(Denials), Reasons = make_set(Reasons, 10), Latest = max(Latest) by Organisation, Agent | order by Busiest15m desc'
    version: 2
  }
}

resource denialSurgeAlert 'Microsoft.Insights/scheduledQueryRules@2026-03-01' = {
  name: denialSurgeAlertName
  location: location
  tags: tags
  kind: 'LogAlert'
  properties: {
    displayName: 'Spend requests: one agent denied again and again'
    description: 'SEV-2. One agent had more than 10 spend requests denied in 15 minutes (DENY or REQUIRE_NEW_MANDATE): a runaway loop, an agent probing its limits, or a mandate gone wrong. The saved query "Denials by agent" shows which. Runbook: Incident-Response-Playbook.md section F.'
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
          query: '${denialLines} | summarize Denials = count() by Agent = tostring(parse_json(Log).agentId) | summarize Highest = max(Denials)'
          timeAggregation: 'Total'
          metricMeasureColumn: 'Highest'
          operator: 'GreaterThan'
          threshold: 10
          failingPeriods: {
            numberOfEvaluationPeriods: 1
            minFailingPeriodsToAlert: 1
          }
        }
      ]
    }
    autoMitigate: true
    actions: {
      actionGroups: [actionGroupId]
    }
  }
  dependsOn: [appLogs]
}

// The holdings check failing (Phase 2 E1b's review): a page that throws
// (a key version the process doesn't hold, a history too long to read, the
// database away) logs `holdings_check.failed` and starts again from the same
// place next run, so the organisation's later requests go unchecked, with no
// integrity alarm. Any one line tells someone. Stateful, as above.
resource holdingsCheckAlert 'Microsoft.Insights/scheduledQueryRules@2026-03-01' = {
  name: holdingsCheckAlertName
  location: location
  tags: tags
  kind: 'LogAlert'
  properties: {
    displayName: 'Holdings check: a page failed'
    description: 'SEV-2. The holdings check (reservations and order claims against the signed decisions) failed a page and will retry from the same place: until it passes, that organisation is not being checked. Runbook: Incident-Response-Playbook.md section N.'
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
          query: 'ContainerAppConsoleLogs | where tostring(parse_json(Log).event) == "holdings_check.failed" | summarize Events = count()'
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
      actionGroups: [actionGroupId]
    }
  }
  dependsOn: [appLogs]
}

// An integrity job skipping a whole run (Phase 2 E2c, the partner's catch):
// the holdings check, the hold-history check, mandate expiry and request
// expiry (D7) each read the organisation list first, and when that read
// fails, log `<job>.run_failed` and check nothing until the next run; the
// activity log's daily seal (Phase 3 L6b) and its seal check (L6c) log the
// same when a run stops early. Any one line tells someone. Stateful,
// as above. A job that stops running altogether is PL-33.
resource integrityRunsAlert 'Microsoft.Insights/scheduledQueryRules@2026-03-01' = {
  name: integrityRunsAlertName
  location: location
  tags: tags
  kind: 'LogAlert'
  properties: {
    displayName: 'Integrity jobs: a run failed'
    description: 'SEV-2. The holdings check, the hold-history check, mandate expiry, request expiry or request voids could not read the organisation list and skipped a whole run, or the daily seal of the activity log or its seal check stopped early: nothing was checked, expired or sealed until a run passes. Runbook: Incident-Response-Playbook.md section O.'
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
          query: 'ContainerAppConsoleLogs | where tostring(parse_json(Log).event) in ("access_log_seal.run_failed", "access_log_seal_check.run_failed", "hold_history.run_failed", "holdings_check.run_failed", "mandate_expiry.run_failed", "request_expiry.run_failed", "request_void.run_failed") | summarize Events = count()'
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
      actionGroups: [actionGroupId]
    }
  }
  dependsOn: [appLogs]
}

// An agent cancelling its own requests again and again (Phase 2 G6; partner
// decision 11b): asking, reading the decision and cancelling maps where its
// hidden approval line lies. The API caps an agent at 10 of its own cancels a
// day and logs each as `spend_request.cancelled` with `by` and the agent; a
// person's are never logged here. The query counts each agent's in the window
// and returns the highest, one number with no ID dimensions (ADR-013); the
// saved query shows which agent. More than 5 in 15 minutes is half its day's
// cap at once: a first number, to tune on real traffic. Stateful, as above.
var agentCancelLines = 'ContainerAppConsoleLogs | where tostring(parse_json(Log).event) == "spend_request.cancelled" | where tostring(parse_json(Log)["by"]) == "agent"'

resource agentCancelsByAgent 'Microsoft.OperationalInsights/workspaces/savedSearches@2025-07-01' = {
  parent: workspace
  name: 'agentx-agent-cancels-by-agent'
  properties: {
    category: 'Agent X'
    displayName: 'Own cancels by agent'
    query: '${agentCancelLines} | extend Line = parse_json(Log) | summarize Cancels = count(), Latest = max(TimeGenerated) by Organisation = tostring(Line.orgId), Agent = tostring(Line.agentId), Window = bin(TimeGenerated, 15m) | summarize Busiest15m = max(Cancels), Total = sum(Cancels), Latest = max(Latest) by Organisation, Agent | order by Busiest15m desc'
    version: 2
  }
}

resource agentCancelsAlert 'Microsoft.Insights/scheduledQueryRules@2026-03-01' = {
  name: agentCancelsAlertName
  location: location
  tags: tags
  kind: 'LogAlert'
  properties: {
    displayName: 'Spend requests: one agent cancelling its own again and again'
    description: 'SEV-2. One agent cancelled more than 5 of its own spend requests in 15 minutes: it may be asking and cancelling to find its approval line, or looping. The saved query "Own cancels by agent" shows which. Runbook: Incident-Response-Playbook.md section F.'
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
          query: '${agentCancelLines} | summarize Cancels = count() by Agent = tostring(parse_json(Log).agentId) | summarize Highest = max(Cancels)'
          timeAggregation: 'Total'
          metricMeasureColumn: 'Highest'
          operator: 'GreaterThan'
          threshold: 5
          failingPeriods: {
            numberOfEvaluationPeriods: 1
            minFailingPeriodsToAlert: 1
          }
        }
      ]
    }
    autoMitigate: true
    actions: {
      actionGroups: [actionGroupId]
    }
  }
  dependsOn: [appLogs]
}

// An agent reaching its day's cap of own cancels (Phase 2 G6, the partner's
// catch): one cancelling slowly and steadily never trips the burst alert
// above, but at 10 a day it reaches the cap, and the API logs
// `spend_request.agent_cancels_spent` for each cancel the cap refuses. Any
// one line tells someone. Stateful, as above.
resource agentCancelCapAlert 'Microsoft.Insights/scheduledQueryRules@2026-03-01' = {
  name: agentCancelCapAlertName
  location: location
  tags: tags
  kind: 'LogAlert'
  properties: {
    displayName: 'Spend requests: an agent reached its cap of own cancels'
    description: 'SEV-2. An agent cancelled 10 of its own spend requests in 24 hours and was refused another: steady asking and cancelling, which may be mapping its approval line. The saved query "Own cancels by agent" shows which. Runbook: Incident-Response-Playbook.md section F.'
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
          query: 'ContainerAppConsoleLogs | where tostring(parse_json(Log).event) == "spend_request.agent_cancels_spent" | summarize Events = count()'
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
      actionGroups: [actionGroupId]
    }
  }
  dependsOn: [appLogs]
}

output name string = environment.name
