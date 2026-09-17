// Staging's certificates (0e G2e-3; certificates.bicep), deployed after the
// apps once each host's DNS records point at the environment. The two hosts
// come from the shell that deploys, never from this repository (Rule Book §7):
// the same AGENTX_AZURE_AUTH_HOST and AGENTX_AZURE_APP_HOST the apps
// deployment reads, so a certificate is for the host its door serves.
using 'certificates.bicep'

param environment = 'staging'
param location = 'uaenorth'
param authHost = readEnvironmentVariable('AGENTX_AZURE_AUTH_HOST')
param appHost = readEnvironmentVariable('AGENTX_AZURE_APP_HOST')
