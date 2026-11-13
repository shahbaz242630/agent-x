// What the platform is doing, in counts (4D2e Stage F, PR 10; logging levels 2
// and 6): one workbook of charts and a few saved queries as measures, all read
// from the log lines the apps already write. No new tool, nothing collected
// that isn't already, and no targets until real traffic says what normal is.
// Sent with the foundation: since AZ5, by CI after the partner's Approve.
//
// - both live in the main workspace's region and read only that workspace, as
//   the other saved queries do (environment.bicep): opening them needs an
//   Azure sign-in, and their rows never leave the UAE (ADR-013 rule 3)
// - counts only: lines by event, level and outcome, never an organisation's
//   or an agent's ID, so a chart shows how much, not who
// - requests come from `http.minute`, each process's exact counts a minute,
//   which sampling and the logger's caps never thin (request-log.ts)

param location string
param tags object
param workspaceName string
param workspaceId string

// Our logger's lines, each with its event; Zitadel's carry none and fall out of every filter on it.
var lines = 'ContainerAppConsoleLogs | extend Line = parse_json(Log) | extend Event = tostring(Line.event)'

// The hand-off's outcomes: an accepted or refused answer by its kind, or the line's own event.
var handoffOutcomes = '${lines} | where Event in ("handoff.handed_off", "handoff.failed", "handoff.denied", "handoff.marked_unknown", "handoff.refused_late") | extend Outcome = iff(Event == "handoff.handed_off", strcat("handed off: ", tostring(Line.answer)), Event)'

// One chart of the workbook, over the time range its reader picks.
func chart(name string, title string, query string, visualization string) object => {
  type: 3
  name: name
  content: {
    version: 'KqlItem/1.0'
    title: title
    query: query
    size: 0
    queryType: 0
    resourceType: 'microsoft.operationalinsights/workspaces'
    timeContextFromParameter: 'TimeRange'
    timeContext: {
      durationMs: 86400000
    }
    visualization: visualization
  }
}

var workbookContent = {
  version: 'Notebook/1.0'
  items: [
    {
      type: 1
      name: 'about'
      content: {
        json: '## Agent X: counts\nRead from the apps\' own log lines in this workspace. Counts only: no organisation or agent is named. Requests are exact (`http.minute`); everything else is a count of lines. No targets yet: what normal is waits for real traffic.'
      }
    }
    {
      type: 9
      name: 'range'
      content: {
        version: 'KqlParameterItem/1.0'
        style: 'pills'
        queryType: 0
        resourceType: 'microsoft.operationalinsights/workspaces'
        parameters: [
          {
            id: 'time-range'
            version: 'KqlParameterItem/1.0'
            name: 'TimeRange'
            label: 'Time range'
            type: 4
            isRequired: true
            value: {
              durationMs: 86400000
            }
            typeSettings: {
              selectableValues: [
                { durationMs: 3600000 }
                { durationMs: 21600000 }
                { durationMs: 86400000 }
                { durationMs: 604800000 }
              ]
            }
          }
        ]
      }
    }
    chart(
      'requests',
      'Requests a minute, by how they ended',
      '${lines} | where Event == "http.minute" | summarize Requests = sum(toint(Line.requests)), Refused4xx = sum(toint(Line.s4xx)), Failed5xx = sum(toint(Line.s5xx)), RateLimited = sum(toint(Line.rateLimited)), Aborted = sum(toint(Line.aborted)) by bin(TimeGenerated, 1m)',
      'timechart'
    )
    chart(
      'decisions',
      'Payment decisions, by decision',
      '${lines} | where Event == "spend_request.decided" | summarize Decisions = count() by Decision = tostring(Line.decision), bin(TimeGenerated, 5m)',
      'timechart'
    )
    chart(
      'handoffs',
      'Hand-offs to the bank, by outcome',
      '${handoffOutcomes} | summarize HandOffs = count() by Outcome, bin(TimeGenerated, 5m)',
      'timechart'
    )
    chart(
      'problems',
      'Warnings and errors, by level',
      'ContainerAppConsoleLogs | extend Level = tolower(tostring(parse_json(Log).level)) | where Level in ("warn", "warning", "error", "fatal", "panic") | summarize Lines = count() by Level, bin(TimeGenerated, 15m)',
      'timechart'
    )
    chart(
      'pulses',
      'Background jobs: pulses and finished anchor checks',
      '${lines} | where Event in ("jobs.pulse", "audit.anchor_check_done") | summarize Lines = count() by Event, bin(TimeGenerated, 15m)',
      'timechart'
    )
    chart(
      'kinds',
      'Warnings and errors, by event',
      '${lines} | where tostring(Line.level) in ("warn", "error") | summarize Lines = count() by Event | order by Lines desc',
      'table'
    )
  ]
  isLocked: false
  fallbackResourceIds: [workspaceId]
}

// Shared in the resource group, so anyone who may read the workspace sees it; its name is a GUID, as Azure requires.
resource workbook 'Microsoft.Insights/workbooks@2023-06-01' = {
  name: guid(workspaceId, 'agentx-counts')
  location: location
  tags: tags
  kind: 'shared'
  properties: {
    displayName: 'Agent X: counts'
    category: 'workbook'
    sourceId: workspaceId
    serializedData: string(workbookContent)
    version: 'Notebook/1.0'
  }
}

resource workspace 'Microsoft.OperationalInsights/workspaces@2025-02-01' existing = {
  name: workspaceName
}

// The measures (level 6): each an hour at a time, to watch against itself until there are targets.
var measures = [
  {
    name: 'agentx-measure-request-failures'
    displayName: 'Measure: requests failed on our side, an hour'
    query: '${lines} | where Event == "http.minute" | summarize Requests = sum(toint(Line.requests)), Failed5xx = sum(toint(Line.s5xx)) by Hour = bin(TimeGenerated, 1h) | extend FailedPercent = round(100.0 * Failed5xx / Requests, 3) | order by Hour desc'
  }
  {
    name: 'agentx-measure-decision-time'
    displayName: 'Measure: time to decide a payment, an hour'
    query: '${lines} | where Event == "spend_request.decided" | extend Ms = toreal(Line.durationMs) | summarize Decisions = count(), P50Ms = percentile(Ms, 50), P95Ms = percentile(Ms, 95), P99Ms = percentile(Ms, 99) by Hour = bin(TimeGenerated, 1h) | order by Hour desc'
  }
  {
    name: 'agentx-measure-handoff-outcomes'
    displayName: 'Measure: hand-offs the bank accepted, an hour'
    query: '${handoffOutcomes} | summarize HandOffs = count(), Accepted = countif(Outcome == "handed off: accepted") by Hour = bin(TimeGenerated, 1h) | extend AcceptedPercent = round(100.0 * Accepted / HandOffs, 1) | order by Hour desc'
  }
  {
    name: 'agentx-measure-job-gaps'
    displayName: 'Measure: longest gap between job pulses, an hour, by process'
    // Each copy of the API pulses on its own, so a gap is read only between one process's pulses, never across two.
    query: '${lines} | where Event == "jobs.pulse" | extend Process = coalesce(ContainerAppName, JobName), Replica = tostring(ContainerGroupName) | sort by Process asc, Replica asc, TimeGenerated asc | extend GapMinutes = iff(prev(Process) == Process and prev(Replica) == Replica, (TimeGenerated - prev(TimeGenerated)) / 1m, real(null)) | summarize Pulses = count(), LongestGapMinutes = max(GapMinutes) by Process, Replica, Hour = bin(TimeGenerated, 1h) | order by Hour desc, Process asc, Replica asc'
  }
]

resource measure 'Microsoft.OperationalInsights/workspaces/savedSearches@2025-07-01' = [
  for item in measures: {
    parent: workspace
    name: item.name
    properties: {
      category: 'Agent X measures'
      displayName: item.displayName
      query: item.query
      version: 2
    }
  }
]
