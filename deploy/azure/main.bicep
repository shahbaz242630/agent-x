// Agent X on Azure (ADR-002; ADR-002 Amendment G1): one deployment per
// environment, each in its own subscription, everything in UAE North (ADR-009).
// This is the foundation: the private network, the database server, the key
// vault, the log workspace with its cap and alerts, the Container Apps
// environment with one identity per app and job, CI's identity and role (G4),
// the activity log and the budget. The secrets (secrets.bicep), the apps and
// jobs (apps.bicep) and the doors' certificates are deployments of their own,
// into the resource group this one creates.
//
//   bicep snapshot deploy/azure/staging.bicepparam   # what it would create
//   az deployment sub create --location uaenorth \
//     --parameters deploy/azure/staging.bicepparam   # G3, once the partner signs in
//
// How it is laid out:
// - the database has no public address: it lives in its own delegated subnet
//   and only the apps subnet may reach its port (ADR-002, decided here)
// - the app gets secrets from the key vault through the platform, never an SDK
//   (ADR-010); the vault takes requests only from the apps subnet
// - every log, error and metric stays in the workspace in UAE North; alerts
//   carry counts only, because Azure sends notifications from outside the UAE
//   (ADR-013 rule 3)
// - names of people and addresses never sit in this repository: the bicepparam
//   file reads them from the shell that deploys (Rule Book §7)
import { networkAddressSpace, releaseSubject, resourceNames, resourceTags, shortName, uniqueSuffix } from 'names.bicep'

targetScope = 'subscription'

@description('Which environment this is. Staging holds synthetic data only (ADR-009).')
@allowed([
  'staging'
  'production'
])
param environment string

@description('The Azure region for every resource. UAE deployments use uaenorth (ADR-009).')
param location string

@description('Makes the names that must be unique across Azure (the key vault, the database server) unique. Change it only to start afresh: a deleted key vault keeps its name for 90 days.')
@minLength(4)
@maxLength(6)
param nameSuffix string = uniqueSuffix(subscription().id)

@description('Who alert emails and Azure mobile app pushes go to: the Azure account the partner signs in with.')
param alertEmail string

@description('The workspace\'s daily cap in GB, a cost backstop set well above normal volume; an alert fires at 80% of it (ADR-013 rule 6).')
@minValue(1)
@maxValue(100)
param logDailyCapGb int

@description('The monthly budget in the subscription\'s currency; emails go out at 50%, 80% and 100% of it, and when the month\'s forecast passes it.')
@minValue(10)
param budgetAmount int

@description('The first day of the budget\'s first month (yyyy-MM-01). Kept fixed: a budget\'s start date is not moved on redeploys.')
param budgetStartDate string

@description('The server admin\'s password: break-glass only, kept in the password manager (ADR-002). Never used by the app.')
@secure()
param postgresAdminPassword string

@description('The database compute size (ADR-002: Burstable B1ms to start).')
param postgresSku object = {
  name: 'Standard_B1ms'
  tier: 'Burstable'
}

@description('How many days of point-in-time restore the server keeps: 7 to 35 (ADR-002: 35 in production).')
@minValue(7)
@maxValue(35)
param postgresBackupRetentionDays int

@description('Whether backups are also kept in the paired region. It can\'t be changed once the server exists, so each environment states it (ADR-002, R-08).')
param postgresGeoRedundantBackup bool

@description('Whether the Container Apps environment spreads over availability zones. It can only be set when the environment is created (Microsoft), so each environment states it.')
param appsZoneRedundant bool

@description('The apps\' error alert fires above this many error events in 15 minutes (logging standard §5).')
@minValue(0)
param appErrorAlertThreshold int

var short = shortName(environment)

// The same tags every deployment of this environment gives its resources.
var tags = resourceTags(environment)

// Every name, once (names.bicep). The modules create their resources under
// these names, and the secrets deployment finds them by the same.
var names = resourceNames(environment, nameSuffix)

resource group 'Microsoft.Resources/resourceGroups@2025-04-01' = {
  name: names.group
  location: location
  tags: tags
}

// The ids one module hands another, built here from the same names rather than
// passed on as module outputs. So a snapshot resolves every one of them, and
// the policy can check each points at a resource this deployment creates.
var ids = {
  workspace: resourceId(subscription().subscriptionId, group.name, 'Microsoft.OperationalInsights/workspaces', names.workspace)
  actionGroup: resourceId(subscription().subscriptionId, group.name, 'Microsoft.Insights/actionGroups', names.actionGroup)
  appsSubnet: resourceId(subscription().subscriptionId, group.name, 'Microsoft.Network/virtualNetworks/subnets', names.network, 'apps')
  databaseSubnet: resourceId(subscription().subscriptionId, group.name, 'Microsoft.Network/virtualNetworks/subnets', names.network, 'database')
  databaseZone: resourceId(subscription().subscriptionId, group.name, 'Microsoft.Network/privateDnsZones', names.databaseZone)
}

module monitoring 'modules/monitoring.bicep' = {
  scope: group
  params: {
    location: location
    short: short
    workspaceName: names.workspace
    actionGroupName: names.actionGroup
    tags: tags
    alertEmail: alertEmail
    logDailyCapGb: logDailyCapGb
  }
}

module network 'modules/network.bicep' = {
  scope: group
  params: {
    location: location
    name: names.network
    appsRulesName: names.appsRules
    databaseRulesName: names.databaseRules
    databaseZoneName: names.databaseZone
    tags: tags
    addressSpace: networkAddressSpace
  }
}

module vault 'modules/keyvault.bicep' = {
  scope: group
  params: {
    location: location
    name: names.vault
    tags: tags
    appsSubnetId: ids.appsSubnet
    workspaceId: ids.workspace
  }
  // The subnet's service endpoint and the workspace must exist first.
  dependsOn: [
    network
    monitoring
  ]
}

module database 'modules/postgres.bicep' = {
  scope: group
  params: {
    location: location
    name: names.server
    tags: tags
    adminPassword: postgresAdminPassword
    sku: postgresSku
    backupRetentionDays: postgresBackupRetentionDays
    geoRedundantBackup: postgresGeoRedundantBackup
    subnetId: ids.databaseSubnet
    privateDnsZoneId: ids.databaseZone
    workspaceId: ids.workspace
    actionGroupId: ids.actionGroup
  }
  // The delegated subnet, the zone linked to the network, the workspace and the action group must exist first.
  dependsOn: [
    network
    monitoring
  ]
}

module appsEnvironment 'modules/environment.bicep' = {
  scope: group
  params: {
    location: location
    name: names.appsEnvironment
    tags: tags
    appsSubnetId: ids.appsSubnet
    zoneRedundant: appsZoneRedundant
    identityNames: names.identities
    workspaceName: names.workspace
    workspaceId: ids.workspace
    actionGroupId: ids.actionGroup
    errorAlertName: names.appErrors
    errorAlertThreshold: appErrorAlertThreshold
    integrityAlertName: names.auditIntegrity
  }
  // The apps subnet with its rules, the workspace and the action group must exist first.
  dependsOn: [
    network
    monitoring
  ]
}

// CI's identity, its trust in GitHub and the one role it may be given (G4).
module release 'modules/release.bicep' = {
  scope: group
  params: {
    location: location
    tags: tags
    identityName: names.release
    roleName: names.releaseRole
    subject: releaseSubject(environment)
  }
}

// Who changed what in this subscription, kept in the same workspace: every
// change is meant to come from this code (ADR-012 §6), so a change from
// anywhere else shows up here. The activity log costs nothing to collect.
resource activityLog 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'activity-log-to-workspace'
  properties: {
    workspaceId: ids.workspace
    logs: [
      {
        category: 'Administrative'
        enabled: true
      }
      {
        category: 'Security'
        enabled: true
      }
      {
        category: 'Policy'
        enabled: true
      }
    ]
  }
  dependsOn: [monitoring]
}

// A cost alarm, not a limit: Azure keeps running when it is passed. Budget
// emails carry costs, never log data.
resource budget 'Microsoft.Consumption/budgets@2024-08-01' = {
  name: 'budget-agentx-${environment}'
  properties: {
    category: 'Cost'
    amount: budgetAmount
    timeGrain: 'Monthly'
    timePeriod: {
      startDate: budgetStartDate
    }
    notifications: {
      actual50: {
        enabled: true
        operator: 'GreaterThan'
        threshold: 50
        thresholdType: 'Actual'
        contactEmails: [alertEmail]
      }
      actual80: {
        enabled: true
        operator: 'GreaterThan'
        threshold: 80
        thresholdType: 'Actual'
        contactEmails: [alertEmail]
      }
      actual100: {
        enabled: true
        operator: 'GreaterThan'
        threshold: 100
        thresholdType: 'Actual'
        contactEmails: [alertEmail]
      }
      forecast100: {
        enabled: true
        operator: 'GreaterThan'
        threshold: 100
        thresholdType: 'Forecasted'
        contactEmails: [alertEmail]
      }
    }
  }
}

output resourceGroupName string = group.name
output workspaceId string = ids.workspace
output appsSubnetId string = ids.appsSubnet
output keyVaultName string = vault.outputs.name
output databaseHost string = database.outputs.host
output appsEnvironmentName string = appsEnvironment.outputs.name
output releaseClientId string = release.outputs.clientId
