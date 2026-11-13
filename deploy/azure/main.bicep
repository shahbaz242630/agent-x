// Agent X on Azure (ADR-002; ADR-002 Amendment G1): one deployment per
// environment, each in its own subscription, everything in UAE North (ADR-009).
// This is the foundation: the private network and the DNS policy watching its
// lookups, the database server, the key
// vault, the log workspace with its cap and alerts, the Container Apps
// environment with one identity per app and job, CI's identity (G4) and the
// email service (B5-2). The roles, the guardrails, the activity log and the
// budget are the partner's `access` deployment (AZ5). The secrets (secrets.bicep), the apps and
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
import { appName, identityName, jobName, jobWatchSubject, networkAddressSpace, releaseSubject, resourceNames, resourceTags, shortName, uniqueSuffix } from 'names.bicep'
import { evidenceAccountName } from 'modules/evidence.bicep'
import { activityDownloadsAccountName } from 'modules/activity-downloads.bicep'

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

@description('The server admin\'s password: break-glass only, kept in the password manager (ADR-002). Never used by the app.')
@secure()
param postgresAdminPassword string

@description('The database compute size: normal (ADR-002: Burstable B1ms to start), or load for the load test\'s run alone (D2c, PL-38).')
@allowed([
  'normal'
  'load'
])
param databaseSize string

@description('The database disk as the server has it now, which deploy.ts reads: never smaller, which Azure refuses.')
param databaseDiskGb int

// The load size: 2 vCores, General Purpose (D2c: offered in UAE North and within quota, S152). Its storage, backups and
// network stay the server's own; only the compute changes, with a restart of a few minutes.
var postgresSkus = {
  normal: {
    name: 'Standard_B1ms'
    tier: 'Burstable'
  }
  load: {
    name: 'Standard_D2ads_v5'
    tier: 'GeneralPurpose'
  }
}

@description('The zone the database server runs in: the one it is in (4D2d P5; staging\'s, zone 2, Azure chose at creation).')
@allowed([
  '1'
  '2'
  '3'
])
param postgresZone string

@description('How many days of point-in-time restore the server keeps: 7 to 35 (ADR-002: 35 in production).')
@minValue(7)
@maxValue(35)
param postgresBackupRetentionDays int

@description('Whether backups are also kept in the paired region. It can\'t be changed once the server exists, so each environment states it (ADR-002, R-08).')
param postgresGeoRedundantBackup bool

@description('Whether the Container Apps environment spreads over availability zones. It can only be set when the environment is created (Microsoft), so each environment states it.')
param appsZoneRedundant bool

@description('Whether the jobs always run here, so the alerts on their lines missing are on (4D2e D, policy.ts).')
param alwaysOn bool

@description('The apps\' error alert fires above this many error events in 15 minutes (logging standard §5).')
@minValue(0)
param appErrorAlertThreshold int

@description('How many days each audit export is kept unchangeable (decision 27: five years live, days on staging).')
@minValue(1)
param evidenceRetentionDays int

@description('Unlocked on staging; production is created Unlocked, then Locked by a second run (modules/evidence.bicep).')
@allowed([
  'Unlocked'
  'Locked'
])
param evidenceImmutability string

@description('The audit exports\' copies: Standard_LRS on staging, Standard_ZRS live.')
@allowed([
  'Standard_LRS'
  'Standard_ZRS'
])
param evidenceRedundancy string

var short = shortName(environment)

// The same tags every deployment of this environment gives its resources.
var tags = resourceTags(environment)

// Every name, once (names.bicep). The modules create their resources under
// these names, and the secrets deployment finds them by the same.
var names = resourceNames(environment, nameSuffix)

// The login alerts' own small workspace (modules/monitoring.bicep). Named here, not in names.bicep, as the budget is:
// only the foundation uses it, and a change there asks every hand deploy to run again.
var loginWorkspaceName = 'log-agentx-${short}-logins'

// The apps that run the API (4D2e D13), each by its work and identity: `api`, and
// `jobs`, which holds the API's jobs where they run apart from it.
var apiKeeper = {
  workload: 'api'
  identity: identityName(environment, 'api')
}
var jobsKeeper = {
  workload: 'jobs'
  identity: identityName(environment, 'jobs')
}

// Who keeps the chains' anchors: the app that holds the jobs. Production always
// runs them apart, in `jobs`; staging's API holds them out of a load run and
// `jobs` in one (apps --load-run), so both may keep them there.
var anchorKeepers = environment == 'production' ? [jobsKeeper] : [apiKeeper, jobsKeeper]

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
  loginWorkspace: resourceId(subscription().subscriptionId, group.name, 'Microsoft.OperationalInsights/workspaces', loginWorkspaceName)
  actionGroup: resourceId(subscription().subscriptionId, group.name, 'Microsoft.Insights/actionGroups', names.actionGroup)
  network: resourceId(subscription().subscriptionId, group.name, 'Microsoft.Network/virtualNetworks', names.network)
  appsSubnet: resourceId(subscription().subscriptionId, group.name, 'Microsoft.Network/virtualNetworks/subnets', names.network, 'apps')
  databaseSubnet: resourceId(subscription().subscriptionId, group.name, 'Microsoft.Network/virtualNetworks/subnets', names.network, 'database')
  databaseZone: resourceId(subscription().subscriptionId, group.name, 'Microsoft.Network/privateDnsZones', names.databaseZone)
  appsEnvironment: resourceId(subscription().subscriptionId, group.name, 'Microsoft.App/managedEnvironments', names.appsEnvironment)
}

module monitoring 'modules/monitoring.bicep' = {
  scope: group
  params: {
    location: location
    short: short
    workspaceName: names.workspace
    loginWorkspaceName: loginWorkspaceName
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

// Every lookup the network makes, watched in the workspace (S68 audit finding 14).
module dnsPolicy 'modules/dns-policy.bicep' = {
  scope: group
  params: {
    location: location
    // Named here, not in names.bicep, as the budget is: only the foundation
    // uses them, and a change there asks every hand deploy to run again.
    policyName: 'dnspr-agentx-${environment}'
    domainListName: 'dnsdl-agentx-${environment}-every-name'
    allowedListName: 'dnsdl-agentx-${environment}-allowed'
    tags: tags
    networkId: ids.network
    workspaceId: ids.workspace
    actionGroupId: ids.actionGroup
    blockedAlertName: 'alert-agentx-${short}-dns-blocked'
  }
  // The network, the workspace and the action group must exist first.
  dependsOn: [
    network
    monitoring
  ]
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
    sku: postgresSkus[databaseSize]
    zone: postgresZone
    measured: databaseSize == 'load'
    diskGb: databaseDiskGb
    backupRetentionDays: postgresBackupRetentionDays
    geoRedundantBackup: postgresGeoRedundantBackup
    subnetId: ids.databaseSubnet
    privateDnsZoneId: ids.databaseZone
    // Its server log goes to the login alerts' own workspace, which the main one's cap can't stop (4D2e Stage F).
    loginWorkspaceId: ids.loginWorkspace
    actionGroupId: ids.actionGroup
    // The apps deployment creates the job under this name, in this environment; the owner-login alert pairs its starts with the owner's logins.
    migrateJobName: jobName(environment, 'migrate')
    appsEnvironmentId: ids.appsEnvironment
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
    loginWorkspaceId: ids.loginWorkspace
    actionGroupId: ids.actionGroup
    errorAlertName: names.appErrors
    errorAlertThreshold: appErrorAlertThreshold
    ownLogNames: [
      appName(environment, 'api')
      // The API's jobs where they run apart from it (4D2e D13): the same logger.
      appName(environment, 'jobs')
      jobName(environment, 'db-setup')
      jobName(environment, 'migrate')
      jobName(environment, 'operator')
      jobName(environment, 'chain-restore')
    ]
    integrityAlertName: names.auditIntegrity
    tokenRefusedAlertName: names.tokenRefused
    denialSurgeAlertName: names.denialSurge
    holdingsCheckAlertName: names.holdingsCheck
    // Named here, not in names.bicep, so only foundation reads it (Phase 2 E2c).
    integrityRunsAlertName: 'alert-agentx-${short}-integrity-runs'
    agentCancelsAlertName: 'alert-agentx-${short}-agent-cancels'
    agentCancelCapAlertName: 'alert-agentx-${short}-agent-cancel-cap'
    decisionsSuppressedAlertName: 'alert-agentx-${short}-decisions-suppressed'
    dailyWordsAlertName: 'alert-agentx-${short}-daily-words'
    handoffQueueAlertName: 'alert-agentx-${short}-handoff-queue'
    loginServiceAlertName: 'alert-agentx-${short}-login-service'
    platformFullAlertName: 'alert-agentx-${short}-platform-full'
    anchorStoppedAlertName: 'alert-agentx-${short}-anchor-stopped'
    jobsStoppedAlertName: 'alert-agentx-${short}-jobs-stopped'
    alwaysOn: alwaysOn
    anchorStoreAlertName: 'alert-agentx-${short}-anchor-store'
    recordsFillingAlertName: 'alert-agentx-${short}-records-filling'
    dailyCheckAlertName: 'alert-agentx-${short}-daily-check'
    fullPassAlertName: 'alert-agentx-${short}-full-pass'
  }
  // The apps subnet with its rules, the workspace and the action group must exist first.
  dependsOn: [
    network
    monitoring
  ]
}

// The write-once store for our team's audit exports (ADR-005 §6, E10c) and the
// audit chains' anchors (4D2e E, PL-58). Its
// names are written in modules/evidence.bicep, not in names.bicep, so a change
// to them asks for no secrets or certificates deploy.
module evidence 'modules/evidence.bicep' = {
  scope: group
  params: {
    location: location
    name: evidenceAccountName(short, nameSuffix)
    tags: tags
    appsSubnetId: ids.appsSubnet
    workspaceId: ids.workspace
    writerIdentityName: identityName(environment, 'operator')
    anchorKeepers: anchorKeepers
    restorerIdentityName: identityName(environment, 'chain-restore')
    retentionDays: evidenceRetentionDays
    immutability: evidenceImmutability
    redundancy: evidenceRedundancy
  }
  // The subnet's Storage endpoint, the workspace and the operator's and the anchors' keepers' identities must exist first.
  dependsOn: [
    network
    monitoring
    appsEnvironment
  ]
}

// Where the activity log's background downloads are kept a week (Phase 3 L5c,
// decision 31), read and written by the apps that run the API alone. Named in its module, as
// the evidence store is, so a change to it asks for no secrets or
// certificates deploy.
module activityDownloads 'modules/activity-downloads.bicep' = {
  scope: group
  params: {
    location: location
    name: activityDownloadsAccountName(short, nameSuffix)
    tags: tags
    appsSubnetId: ids.appsSubnet
    workspaceId: ids.workspace
    keepers: [apiKeeper, jobsKeeper]
  }
  // The subnet's Storage endpoint, the workspace and the keepers' identities must exist first.
  dependsOn: [
    network
    monitoring
    appsEnvironment
  ]
}

// What the platform is doing, in counts: one workbook and the measures' saved queries (4D2e Stage F, PR 10).
module metrics 'modules/metrics.bicep' = {
  scope: group
  params: {
    location: location
    tags: tags
    workspaceName: names.workspace
    workspaceId: ids.workspace
  }
  // The workspace must exist first.
  dependsOn: [monitoring]
}

// Email for the admins' notices, its data kept in the UAE (B5-2).
module communication 'modules/communication.bicep' = {
  scope: group
  params: {
    emailServiceName: names.emailService
    communicationName: names.communication
    tags: tags
  }
}

// CI's identity, its trust in GitHub and the one role it may be given (G4).
module release 'modules/release.bicep' = {
  scope: group
  params: {
    location: location
    tags: tags
    identityName: names.release
    subject: releaseSubject(environment)
    workspaceId: ids.workspace
    actionGroupId: ids.actionGroup
    // Named here, not in names.bicep, so only foundation reads it (AZ2).
    alertName: 'alert-agentx-${short}-release-writes'
    apiName: appName(environment, 'api')
    migrateName: jobName(environment, 'migrate')
  }
  // The workspace and the action group must exist first.
  dependsOn: [monitoring]
}

// The job-start watch's identity, its trust in GitHub and its read-only role (S175).
module jobWatch 'modules/job-watch.bicep' = {
  scope: group
  params: {
    location: location
    tags: tags
    identityName: names.jobWatch
    subject: jobWatchSubject()
  }
}

// The custom roles, the guardrails (Azure Policy), the activity log's setting and
// the budget are the partner's own `access` deployment (access.bicep, AZ5):
// CI's approved infrastructure deploy may write none of them.

output resourceGroupName string = group.name
output workspaceId string = ids.workspace
output appsSubnetId string = ids.appsSubnet
output keyVaultName string = vault.outputs.name
output databaseHost string = database.outputs.host
output appsEnvironmentName string = appsEnvironment.outputs.name
output releaseClientId string = release.outputs.clientId
output jobWatchClientId string = jobWatch.outputs.clientId
