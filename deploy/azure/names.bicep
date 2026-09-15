// Every name an Agent X deployment gives Azure, once (ADR-002 Amendment G2c).
// The foundation (main.bicep) creates its resources under these names; the
// secrets deployment (secrets.bicep) finds the vault and the identities by
// them. Nothing here depends on a deployment, so both import it.

// Every app and job, each with an identity of its own: the API; Zitadel and its
// login pages; the jobs that set up a server's roles and databases, migrate the
// app's database, and build Zitadel's (init, then setup). The worker joins in
// Phase 4.
@export()
var workloads = [
  'api'
  'zitadel'
  'login'
  'db-setup'
  'migrate'
  'zitadel-init'
  'zitadel-setup'
]

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
@description('Every name, for an environment and its suffix.')
func resourceNames(environment string, nameSuffix string) object => {
  group: 'rg-agentx-${environment}'
  workspace: 'log-agentx-${shortName(environment)}'
  actionGroup: 'ag-agentx-${shortName(environment)}'
  network: 'vnet-agentx-${environment}'
  appsRules: 'nsg-agentx-${environment}-apps'
  databaseRules: 'nsg-agentx-${environment}-database'
  databaseZone: 'agentx-${environment}.private.postgres.database.azure.com'
  vault: 'kv-agentx-${shortName(environment)}-${nameSuffix}'
  server: 'psql-agentx-${shortName(environment)}-${nameSuffix}'
  appsEnvironment: 'cae-agentx-${environment}'
  appErrors: 'alert-agentx-${shortName(environment)}-app-errors'
  identities: map(workloads, workload => identityName(environment, workload))
}
