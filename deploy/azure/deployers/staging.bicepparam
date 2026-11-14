// Staging's deployers (AZ5): deployed by the partner alone, after the foundation, with
// node deploy/azure/infra.ts deployers. Nothing here names a person or a domain.
using 'deployers.bicep'

param environment = 'staging'
param location = 'uaenorth'
// Asked by infra.ts deployers, as access asks it: the address stays out of the repository.
param alertEmail = readEnvironmentVariable('AGENTX_AZURE_ALERT_EMAIL')
