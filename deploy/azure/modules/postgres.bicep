// The environment's one Postgres server (ADR-002): PostgreSQL 18, private
// access only. It will hold two databases, `agentx` and `zitadel`, each with its
// own roles and no cross-access. G2's set-up job creates both from
// db/bootstrap, as the compose stack does, so this module creates none.
//
// - no public address: the server sits in the delegated database subnet and
//   its name resolves only inside the network (network.bicep)
// - password logins only, from the secret store (ADR-002, ADR-010: portable);
//   no Microsoft Entra logins
// - the server admin is break-glass (ADR-002): never the app, never routine
//   work. A login by it or by the backup role raises an alert (ADR-012 §2),
//   and so does one by the owner role anywhere but the migration job, and a
//   refused login as any of the three (MO2)
// - TLS 1.3 at least, on every connection

param location string
param name string
param tags object
@secure()
param adminPassword string
param sku object
@description('The zone the server runs in, stated so a deploy never leaves the choice to Azure (4D2d P5). Azure moves a server only by a new one or a failover, so it is the zone the server is in.')
param zone string
@description('Whether the load run\'s measurements are on (D2c, 4D2d P5): Query Store and its wait sampling. Only on a size that isn\'t Burstable.')
param measured bool
@description('The disk\'s size as the server has it: 32 on a new one, more once autogrow has acted.')
@minValue(32)
param diskGb int
param backupRetentionDays int
param geoRedundantBackup bool
param subnetId string
param privateDnsZoneId string
@description('The login alerts\' own workspace (monitoring.bicep): the server log goes there, and the alerts read it there, so the main workspace reaching its cap never blinds them (4D2e Stage F).')
param loginWorkspaceId string
param actionGroupId string
@description('The migration job, the one thing that logs in as the owner role (apps.bicep).')
param migrateJobName string
@description('The Container Apps environment that job runs in, whose platform lines record its starts.')
param appsEnvironmentId string

// Fixed: Azure never lets a server's admin login change, and the alert below matches it by name.
var adminLogin = 'agentx_admin'

// Owns the app's tables and runs the migrations (db/bootstrap/roles.sql).
var ownerRole = 'agentx_owner'

resource server 'Microsoft.DBforPostgreSQL/flexibleServers@2025-08-01' = {
  name: name
  location: location
  tags: tags
  sku: sku
  properties: {
    version: '18'
    availabilityZone: zone
    administratorLogin: adminLogin
    // Empty only from CI's approved infrastructure deploy (AZ5), which never holds it: Azure then keeps the server's own.
    administratorLoginPassword: empty(adminPassword) ? null : adminPassword
    authConfig: {
      activeDirectoryAuth: 'Disabled'
      passwordAuth: 'Enabled'
    }
    // A server in a network can't also take public connections (Microsoft), so
    // there is no public-access setting to send, as in Microsoft's own example.
    network: {
      delegatedSubnetResourceId: subnetId
      privateDnsZoneArmResourceId: privateDnsZoneId
    }
    storage: {
      // What the server has now, which deploy.ts reads: autogrow changes it, and Azure refuses a smaller size.
      storageSizeGB: diskGb
      // A full disk stops every write (4D2e A). Azure grows it with 20% free at this size (Microsoft), and it can
      // never shrink, so the alert below says when it is getting there.
      autoGrow: 'Enabled'
    }
    backup: {
      backupRetentionDays: backupRetentionDays
      // Can't be changed once the server exists (Microsoft), so each
      // environment's parameters say it outright (ADR-002, R-08).
      geoRedundantBackup: geoRedundantBackup ? 'Enabled' : 'Disabled'
    }
    // Burstable servers have no standby.
    highAvailability: {
      mode: 'Disabled'
    }
    // Sundays at 02:00 UTC (06:00 in the UAE).
    maintenanceWindow: {
      customWindow: 'Enabled'
      dayOfWeek: 0
      startHour: 2
      startMinute: 0
    }
  }
}

var settings = [
  {
    name: 'require_secure_transport'
    value: 'on'
  }
  {
    name: 'ssl_min_protocol_version'
    value: 'TLSv1.3'
  }
  // Every login leaves a line, which the alert below reads.
  {
    name: 'log_connections'
    value: 'on'
  }
  // Every line starts with its time and its session (`2026-09-16 19:02:12
  // UTC-6aaae7b4.1dc3-`): Azure's default, held here because the alert below
  // matches it. Azure keeps the log's time zone at UTC and doesn't let it change.
  {
    name: 'log_line_prefix'
    value: '%t-%c-'
  }
  // The load run's measurements, each sent either way so a plain foundation
  // turns them off again. Microsoft: "Don't enable query store on the
  // Burstable pricing tier as it causes performance problems." Query Store
  // keeps each query's plan too, so auto_explain (a restart of its own, past
  // the resize's) isn't needed. No slow-statement log either: at saturation
  // it could fill the login workspace's 1 GB a day, and the login alerts would
  // go blind until the next day (S159 review); Query Store keeps each query's
  // slowest time inside the server.
  {
    name: 'pg_qs.query_capture_mode'
    value: measured ? 'top' : 'none'
  }
  {
    name: 'pg_qs.store_query_plans'
    value: measured ? 'on' : 'off'
  }
  {
    name: 'pgms_wait_sampling.query_capture_mode'
    value: measured ? 'all' : 'none'
  }
  {
    name: 'track_io_timing'
    value: measured ? 'on' : 'off'
  }
  // Azure keeps a server's connection limit through a resize: the load size
  // read 50 on run day 5, 35 for everyone, and refused the API's twenty beside
  // Zitadel's ten and the load job (S167). So it is stated. The API's two
  // copies in a restart, Zitadel and the job come to 56. Takes effect only on
  // a restart, which deploy.ts does when Azure says one is waiting. 120 since
  // S183: three web copies of twelve, each twice in a restart, the jobs' six
  // twice, Zitadel's ten and two come to 96, under 120 less Azure's 15.
  {
    name: 'max_connections'
    value: measured ? '120' : '50'
  }
  // MO5: what a stall like the soak's 5 s commit pause leaves behind, so it can be named. Each checkpoint writes two
  // lines, its start and how long its writes and syncs took (Postgres 18's default, stated here because Azure may
  // differ). A lock waited on for longer than deadlock_timeout writes who held it and the queue, and again when
  // granted; 1 s is Postgres's default and also when it looks for a deadlock, so it isn't raised to quieten these.
  // Both go to the login workspace with the rest of the server's log: a few MB a day; a lock storm writes about
  // 3 KB a wait, so its 1 GB cap needs some 300,000 waits over a second in one day (Incident-Response-Playbook §J).
  {
    name: 'log_checkpoints'
    value: 'on'
  }
  {
    name: 'log_lock_waits'
    value: 'on'
  }
  {
    name: 'deadlock_timeout'
    value: '1000'
  }
  // The server's own count of sessions by what they wait on (Lock, IO, LWLock), the oldest transaction and deadlocks,
  // each minute, as Azure metrics kept 93 days: nothing goes to a workspace and nothing is billed. Beside the metrics
  // always there (CPU and its credits, IOPS, disk queue depth, IOPS and bandwidth used), a stall reads as one of them.
  {
    name: 'metrics.collector_database_activity'
    value: 'on'
  }
]

// One at a time: the server refuses a second change while one is in progress.
@batchSize(1)
resource setting 'Microsoft.DBforPostgreSQL/flexibleServers/configurations@2025-08-01' = [
  for item in settings: {
    parent: server
    name: item.name
    properties: {
      value: item.value
      source: 'user-override'
    }
  }
]

// Its delete lock (S184/S185) is the partner's `access` deployment's (modules/server-lock.bicep, AZ5): CI's approved
// deploy can't write a lock, and must never be able to lift one.

// Kept under its old name, so a deploy moves the one setting to the login workspace rather than adding a second
// beside it that would go on filling the main one.
resource serverLogs 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: server
  name: 'logs-to-workspace'
  properties: {
    workspaceId: loginWorkspaceId
    // Resource-specific tables (PGSQLServerLogs), not the shared AzureDiagnostics.
    logAnalyticsDestinationType: 'Dedicated'
    logs: [
      {
        category: 'PostgreSQLLogs'
        enabled: true
      }
    ]
  }
}

// How a login's line starts, up to the message, as log_line_prefix above
// writes it: `2026-09-16 19:02:12 UTC-6aaae7b4.1dc3-LOG:  `. Both login alerts
// match from here: anchored at "connection authorized" alone, the pattern
// matched none of the set-up job's real logins (the first real run, S19).
var lineStart = '^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} UTC-[0-9a-f]+[.][0-9a-f]+-'
var loginLineStart = '${lineStart}LOG:  '

// What each login alert reads before its judged moment: Azure's most, two days, so a line that reaches the workspace
// late is still in view when it arrives (MO2). Reading costs nothing more; a rule's price follows how often it runs.
var lateLinesRead = 'P2D'

// The login alerts that count lines take those that arrived over the last 30 minutes, run every 15: a run starting up
// to 15 minutes late leaves no gap, and a line may notify twice, never not at all (MO2).
var arrivedLately = 'where ingestion_time() > ago(30m)'

// The roles whose refused logins raise the alert below: the two above and the owner.
var privilegedRoles = '${adminLogin}|agentx_backup|${ownerRole}'

// ADR-012 §2: a login by the server admin or the backup role raises an alert.
// The set-up job's own login (G2) is one of them, and expected. Counted by when
// a line arrived over the last 30 minutes of a 15-minute rhythm, reading two
// days back: a late line is still seen, and one may notify twice, never not at
// all (MO2; by when it happened, a line arriving after its window was missed).
resource privilegedLogin 'Microsoft.Insights/scheduledQueryRules@2026-03-01' = {
  name: 'alert-${name}-privileged-login'
  location: location
  tags: tags
  kind: 'LogAlert'
  properties: {
    displayName: 'Database: login by the server admin or the backup role'
    description: 'SEV-1. The break-glass server admin or the backup role logged in to Postgres; every such use needs a recorded reason (ADR-002, ADR-012 §2). Runbook: Incident-Response-Playbook.md section B.'
    severity: 1
    enabled: true
    scopes: [loginWorkspaceId]
    evaluationFrequency: 'PT15M'
    windowSize: 'PT15M'
    overrideQueryTimeRange: lateLinesRead
    // The table appears with the server's first log line, after this rule exists.
    skipQueryValidation: true
    criteria: {
      allOf: [
        {
          query: 'PGSQLServerLogs | ${arrivedLately} | where Message matches regex @"${loginLineStart}connection authorized: user=(${adminLogin}|agentx_backup) " | summarize Logins = count()'
          timeAggregation: 'Total'
          metricMeasureColumn: 'Logins'
          operator: 'GreaterThan'
          threshold: 0
          failingPeriods: {
            numberOfEvaluationPeriods: 1
            minFailingPeriodsToAlert: 1
          }
        }
      ]
    }
    // Stateless: every 15 minutes with such a login notifies again. A stateful
    // alert stays fired and says nothing about a second login while it lasts.
    autoMitigate: false
    actions: {
      actionGroups: [actionGroupId]
    }
  }
  dependsOn: [serverLogs]
}

// MO2: a privileged login that was refused, which the two alerts on logins that got in never see. Postgres writes one
// FATAL line for each, whatever log_connections says: a wrong password (also what it says for a role that doesn't
// exist), or a connection its rules refuse (no TLS, an address not allowed). Quotes in the pattern are RE2's \x22, as
// Kusto's verbatim strings can't hold one. Judged by when a line arrives, over the last 30 minutes of a 15-minute
// rhythm: a late line is still seen, and one may notify twice, never not at all.
var quote = '\\x22'
var refusedLines = '${lineStart}FATAL:  (password authentication failed for user|no pg_hba[.]conf entry for host ${quote}[^${quote}]*${quote}, user|pg_hba[.]conf rejects connection for host ${quote}[^${quote}]*${quote}, user) ${quote}(${privilegedRoles})${quote}'

resource refusedLogin 'Microsoft.Insights/scheduledQueryRules@2026-03-01' = {
  name: 'alert-${name}-privileged-login-refused'
  location: location
  tags: tags
  kind: 'LogAlert'
  properties: {
    displayName: 'Database: a login as the owner, the server admin or the backup role was refused'
    description: 'SEV-1. Postgres refused a login as the owner role, the server admin or the backup role (a wrong password, or a connection its rules don\'t allow). Nothing got in, but someone inside the network may be trying those logins, or a job is still using a password changed since. Check who and from where before anything else. Runbook: Incident-Response-Playbook.md section I.'
    severity: 1
    enabled: true
    scopes: [loginWorkspaceId]
    evaluationFrequency: 'PT15M'
    windowSize: 'PT15M'
    overrideQueryTimeRange: lateLinesRead
    // The table appears with the server's first log line, after this rule exists.
    skipQueryValidation: true
    criteria: {
      allOf: [
        {
          query: 'PGSQLServerLogs | ${arrivedLately} | where Message matches regex @"${refusedLines}" | summarize Refused = count()'
          timeAggregation: 'Total'
          metricMeasureColumn: 'Refused'
          operator: 'GreaterThan'
          threshold: 0
          failingPeriods: {
            numberOfEvaluationPeriods: 1
            minFailingPeriodsToAlert: 1
          }
        }
      ]
    }
    // Stateless, like the alerts beside it.
    autoMitigate: false
    actions: {
      actionGroups: [actionGroupId]
    }
  }
  dependsOn: [serverLogs]
}

// MO6: the login alerts above read the server's lines in the login workspace. A rewritten log setting (its categories
// switched off, or the lines sent to another workspace) leaves them running, healthy, over a table nothing reaches:
// the rule watch (monitoring.bicep) sees a setting deleted, never one rewritten, as every foundation deploy writes
// them. The server writes a line every few minutes at its quietest (staging, 4-12 Nov 2026: about 50,000 a day,
// the longest gap 12 minutes), so an hour with none arriving says the lines have stopped. Counted by when lines
// arrive, as the alerts beside it; the workspace over its cap counts as a line, as its own alert says so.
var noLinesFor = '60m'

resource linesQuiet 'Microsoft.Insights/scheduledQueryRules@2026-03-01' = {
  name: 'alert-${name}-login-lines-quiet'
  location: location
  tags: tags
  kind: 'LogAlert'
  properties: {
    displayName: 'Database: no server log lines arriving'
    description: 'SEV-1. No line of the database server\'s log has reached the login alerts\' workspace for an hour, where the server writes one every few minutes. Until lines arrive again the login alerts see nothing: the server\'s log setting may have been rewritten (categories off, or another workspace), or the server is down. Runbook: Incident-Response-Playbook.md section I.'
    severity: 1
    enabled: true
    scopes: [loginWorkspaceId]
    evaluationFrequency: 'PT15M'
    windowSize: 'PT1H'
    // A day back, for the workspace's own word on its cap (as the jobs' dead-man alerts read theirs).
    overrideQueryTimeRange: 'P1D'
    // The table appears with the server's first log line, after this rule exists.
    skipQueryValidation: true
    criteria: {
      allOf: [
        {
          query: 'union (PGSQLServerLogs | where ingestion_time() > ago(${noLinesFor})), (_LogOperation | where Category =~ "Ingestion" | where Detail contains "Ingestion status" | summarize arg_max(TimeGenerated, Detail) | where Detail contains "OverQuota" or TimeGenerated > ago(${noLinesFor})) | summarize Lines = count()'
          timeAggregation: 'Total'
          metricMeasureColumn: 'Lines'
          operator: 'LessThan'
          threshold: 1
          failingPeriods: {
            numberOfEvaluationPeriods: 1
            minFailingPeriodsToAlert: 1
          }
        }
      ]
    }
    // Stateless, as every SEV-1: each 15 minutes the lines stay away notifies again.
    autoMitigate: false
    actions: {
      actionGroups: [actionGroupId]
    }
  }
  dependsOn: [serverLogs]
}

// ADR-012 §2, Phase 1 A3e-2: the owner role can rewrite the walls the app's
// checks stand on (the S32 probe), so a login by it outside a deploy raises a
// SEV-1 alert. The migration job is the one thing that logs in as it, with one
// connection as it starts: each of its first 19 runs on staging logged in
// within half a second of Azure's `ContainerStarted` line for the run (S33).
// So each owner login is paired with the nearest start of that job, in this
// environment, and the two are a deploy only when the start is within two
// minutes and nothing else is paired with it. The alert counts the rest: a
// login with no start near it, two logins paired with one start (someone
// logging in beside a release), and a start with no login (a run that died
// before it connected, or login lines the pattern no longer matches, which
// would otherwise quieten both login alerts at once).
//
// Azure's lines for the job reach the workspace up to 9 minutes after they
// happen, Postgres's within 4 (S33), so a login or a start is judged once it is
// 20 minutes old, or once it arrives if it arrives later than that (MO2: judged
// by its age alone, a line over about 35 minutes late was never judged at all).
// The band is the last 30 minutes of those moments, which two runs 15 minutes
// apart both see: anything unpaired notifies twice, the first time within
// about 35 minutes of the login, or within 15 of a late line arriving. Each
// run reads the two days before it (overrideQueryTimeRange, Azure's most), so
// a late line and whatever it is paired with are in view. Whatever breaks the
// pairing on either side (the job renamed, Azure rewording a line or leaving
// out the run's name, the migration opening a second connection) fires it on
// every release. A query that stops running at all turns the rule unhealthy,
// which the alert-rule watch in monitoring.bicep reports.
var ownerLoginQuery = join(
  [
    'let near = 2m;'
    'let starts = ContainerAppSystemLogs'
    '    | where _ResourceId =~ "${appsEnvironmentId}" and JobName == "${migrateJobName}" and Reason == "ContainerStarted" and isnotempty(ReplicaName)'
    '    | project Start = TimeGenerated, Run = ReplicaName, Judged = max_of(ingestion_time(), TimeGenerated + 20m);'
    'let logins = PGSQLServerLogs'
    '    | where Message matches regex @"${loginLineStart}connection authorized: user=${ownerRole} "'
    '    | project Login = TimeGenerated, Message, Judged = max_of(ingestion_time(), TimeGenerated + 20m);'
    'let paired = logins'
    '    | extend Key = 1'
    '    | join kind=leftouter (starts | project-away Judged | extend Key = 1) on Key'
    '    | extend Gap = coalesce(abs(Login - Start), 1d)'
    '    | summarize arg_min(Gap, Run) by Login, Message, Judged;'
    'let claims = paired'
    '    | where Gap <= near'
    '    | summarize Claims = count() by Run;'
    'let strays = paired'
    '    | where Judged between (ago(30m) .. now())'
    '    | join kind=leftouter claims on Run'
    '    | where Gap > near or Claims > 1'
    '    | project Run;'
    'let unclaimed = starts'
    '    | where Judged between (ago(30m) .. now())'
    '    | join kind=leftanti claims on Run'
    '    | project Run;'
    'union strays, unclaimed'
    '| summarize Unpaired = count()'
  ],
  '\n'
)

resource ownerLogin 'Microsoft.Insights/scheduledQueryRules@2026-03-01' = {
  name: 'alert-${name}-owner-login'
  location: location
  tags: tags
  kind: 'LogAlert'
  properties: {
    displayName: 'Database: login by the owner role outside a deploy'
    description: 'SEV-1. The owner role logged in to Postgres other than as the migration job starting, so someone else may hold its login and could rewrite the tables\' walls; or a start of that job had no login beside it (ADR-012 §2). Runbook: Incident-Response-Playbook.md section I.'
    severity: 1
    enabled: true
    scopes: [loginWorkspaceId]
    evaluationFrequency: 'PT15M'
    windowSize: 'PT15M'
    overrideQueryTimeRange: lateLinesRead
    // Both tables appear with their first log lines, after this rule exists.
    skipQueryValidation: true
    criteria: {
      allOf: [
        {
          query: ownerLoginQuery
          timeAggregation: 'Total'
          metricMeasureColumn: 'Unpaired'
          operator: 'GreaterThan'
          threshold: 0
          failingPeriods: {
            numberOfEvaluationPeriods: 1
            minFailingPeriodsToAlert: 1
          }
        }
      ]
    }
    // Stateless, like the alert above.
    autoMitigate: false
    actions: {
      actionGroups: [actionGroupId]
    }
  }
  dependsOn: [serverLogs]
}

// Before autogrow's 80%: a growing disk costs more each month and can't shrink, so a person should know (4D2e A).
// A metric, not a log query: it still fires when the logs have stopped at their daily cap.
resource diskFilling 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'alert-${name}-disk'
  location: 'global'
  tags: tags
  properties: {
    description: 'SEV-2. The database server\'s disk is over 75% full; autogrow takes it to the next size at 80%, and a disk can never shrink. Runbook: Incident-Response-Playbook.md section P.'
    severity: 2
    enabled: true
    scopes: [server.id]
    evaluationFrequency: 'PT15M'
    windowSize: 'PT15M'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'disk-used'
          criterionType: 'StaticThresholdCriterion'
          metricNamespace: 'Microsoft.DBforPostgreSQL/flexibleServers'
          metricName: 'storage_percent'
          timeAggregation: 'Maximum'
          operator: 'GreaterThan'
          threshold: 75
        }
      ]
    }
    autoMitigate: true
    actions: [
      {
        actionGroupId: actionGroupId
      }
    ]
  }
}

output host string = server.properties.fullyQualifiedDomainName
