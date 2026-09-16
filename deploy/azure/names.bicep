// Every name an Agent X deployment gives Azure, once (ADR-002 Amendment G2c).
// The foundation (main.bicep) creates its resources under these names; the
// secrets deployment (secrets.bicep) and the apps and jobs (apps.bicep) find
// the vault, the environment and the identities by them. Nothing here depends
// on a deployment, so all three import it.

// Every app, each with an identity of its own: the API, Zitadel and its login
// pages. The worker joins in Phase 4.
@export()
var appWorkloads = [
  'api'
  'zitadel'
  'login'
]

// Every job, each with an identity of its own: the jobs that set up a server's
// roles and databases, migrate the app's database, and build Zitadel's (init,
// then setup). Each is started by hand, never on a schedule (apps.bicep).
@export()
var jobWorkloads = [
  'db-setup'
  'migrate'
  'zitadel-init'
  'zitadel-setup'
]

// Everything that runs, so each can be given only its own secrets (G2c).
@export()
var workloads = concat(appWorkloads, jobWorkloads)

@export()
@description('The environment\'s three letters, for the names Azure keeps short.')
func shortName(environment string) string => environment == 'production' ? 'prd' : 'stg'

@export()
@description('Six characters from the subscription\'s ID, so the names that must be unique across Azure are.')
func uniqueSuffix(subscriptionId string) string => take(uniqueString(subscriptionId), 6)

@export()
@description('The identity an app or job runs as.')
func identityName(environment string, workload string) string => 'id-agentx-${shortName(environment)}-${workload}'

@export()
@description('A job, by the work it does. Azure allows 32 characters, which the longest of these uses 28 of.')
func jobName(environment string, workload string) string => 'job-agentx-${shortName(environment)}-${workload}'

@export()
@description('An app, by the work it does. Also its address inside the environment, since an app with internal ingress answers at `<name>.internal.<the environment\'s default domain>`.')
func appName(environment string, workload string) string => 'ca-agentx-${shortName(environment)}-${workload}'

@export()
@description('The private network\'s address space (network.bicep divides it). Written here rather than in main.bicep alone, because the apps deployment needs the apps subnet\'s range and must not spell it a second time.')
var networkAddressSpace = '10.40.0.0/16'

@export()
@description('The apps subnet\'s range: the Container Apps environment sits in it, and the API trusts it as the proxy in front of it (ADR-011 §4). A /24, which `AGENTX_TRUSTED_PROXIES` accepts (it refuses anything wider than /16).')
func appsPrefix(addressSpace string) string => cidrSubnet(addressSpace, 24, 0)

@export()
@description('The tags every resource with a location carries, so a stray resource stands out (policy rule `tags`).')
func resourceTags(environment string) object => {
  product: 'agent-x'
  environment: environment
  'managed-by': 'deploy/azure'
}

// The database server, and the private zone the network resolves it in
// (postgres.bicep): built here so that the host name below is the same two
// parts, never a second spelling of them.
func serverName(environment string, nameSuffix string) string => 'psql-agentx-${shortName(environment)}-${nameSuffix}'

func databaseZoneName(environment string) string => 'agentx-${environment}.private.postgres.database.azure.com'

@export()
@description('Every name, for an environment and its suffix.')
func resourceNames(environment string, nameSuffix string) object => {
  group: 'rg-agentx-${environment}'
  workspace: 'log-agentx-${shortName(environment)}'
  actionGroup: 'ag-agentx-${shortName(environment)}'
  network: 'vnet-agentx-${environment}'
  appsRules: 'nsg-agentx-${environment}-apps'
  databaseRules: 'nsg-agentx-${environment}-database'
  databaseZone: databaseZoneName(environment)
  vault: 'kv-agentx-${shortName(environment)}-${nameSuffix}'
  server: serverName(environment, nameSuffix)
  // A server in a private network answers only to this name, its own inside the
  // zone linked to the network. G3 confirms it against the foundation's
  // `databaseHost` output, which Azure fills in.
  databaseHost: '${serverName(environment, nameSuffix)}.${databaseZoneName(environment)}'
  appsEnvironment: 'cae-agentx-${environment}'
  appErrors: 'alert-agentx-${shortName(environment)}-app-errors'
  identities: map(workloads, workload => identityName(environment, workload))
  jobs: map(jobWorkloads, workload => jobName(environment, workload))
}
