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
//   and so does one by the owner role anywhere but the migration job
// - TLS 1.3 at least, on every connection

param location string
param name string
param tags object
@secure()
param adminPassword string
param sku object
param backupRetentionDays int
param geoRedundantBackup bool
param subnetId string
param privateDnsZoneId string
param workspaceId string
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
    administratorLogin: adminLogin
    administratorLoginPassword: adminPassword
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
      storageSizeGB: 32
      autoGrow: 'Disabled'
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

resource serverLogs 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: server
  name: 'logs-to-workspace'
  properties: {
    workspaceId: workspaceId
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
var loginLineStart = '^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} UTC-[0-9a-f]+[.][0-9a-f]+-LOG:  '

// ADR-012 §2: a login by the server admin or the backup role raises an alert.
// The set-up job's own login (G2) is one of them, and expected.
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
    scopes: [workspaceId]
    evaluationFrequency: 'PT15M'
    windowSize: 'PT15M'
    // The table appears with the server's first log line, after this rule exists.
    skipQueryValidation: true
    criteria: {
      allOf: [
        {
          query: 'PGSQLServerLogs | where Message matches regex @"${loginLineStart}connection authorized: user=(${adminLogin}|agentx_backup) " | summarize Logins = count()'
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
// happen, Postgres's within 4 (S33), so logins and starts are judged only once
// 20 minutes old, over a band of 30 minutes that two runs 15 minutes apart
// both see: anything unpaired notifies twice, the first time within about 35
// minutes. Each run reads the hour before it (overrideQueryTimeRange), so
// whatever a judged login or start is paired with is always in view. Whatever
// breaks the pairing on either side (the job renamed, Azure rewording a line
// or leaving out the run's name, the migration opening a second connection)
// fires it on every release. A query that stops running at all is another
// matter (Carry-Forward.md).
var ownerLoginQuery = join(
  [
    'let near = 2m;'
    'let starts = ContainerAppSystemLogs'
    '    | where _ResourceId =~ "${appsEnvironmentId}" and JobName == "${migrateJobName}" and Reason == "ContainerStarted" and isnotempty(ReplicaName)'
    '    | project Start = TimeGenerated, Run = ReplicaName;'
    'let logins = PGSQLServerLogs'
    '    | where Message matches regex @"${loginLineStart}connection authorized: user=${ownerRole} "'
    '    | project Login = TimeGenerated, Message;'
    'let paired = logins'
    '    | extend Key = 1'
    '    | join kind=leftouter (starts | extend Key = 1) on Key'
    '    | extend Gap = coalesce(abs(Login - Start), 1d)'
    '    | summarize arg_min(Gap, Run) by Login, Message;'
    'let claims = paired'
    '    | where Gap <= near'
    '    | summarize Claims = count() by Run;'
    'let strays = paired'
    '    | where Login between (ago(50m) .. ago(20m))'
    '    | join kind=leftouter claims on Run'
    '    | where Gap > near or Claims > 1'
    '    | project Run;'
    'let unclaimed = starts'
    '    | where Start between (ago(50m) .. ago(20m))'
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
    scopes: [workspaceId]
    evaluationFrequency: 'PT15M'
    windowSize: 'PT15M'
    overrideQueryTimeRange: 'PT1H'
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

output host string = server.properties.fullyQualifiedDomainName
