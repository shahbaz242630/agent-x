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
//   work. A login by it or by the backup role raises an alert (ADR-012 §2)
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

// Fixed: Azure never lets a server's admin login change, and the alert below matches it by name.
var adminLogin = 'agentx_admin'

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
          query: 'PGSQLServerLogs | where Message matches regex @"^connection authorized: user=(${adminLogin}|agentx_backup) " | summarize Logins = count()'
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
    autoMitigate: true
    actions: {
      actionGroups: [actionGroupId]
    }
  }
  dependsOn: [serverLogs]
}

output host string = server.properties.fullyQualifiedDomainName
