// Agent X's certificates on Azure (ADR-002 Amendment G2e): a free managed
// certificate for each public door's host, issued by DigiCert and renewed by
// Azure, which the door binds by itself (`Auto`, apps.bicep). A deployment of
// its own, into the resource group main.bicep creates, after the apps and once
// each host's DNS records point at the environment (G3b), so a certificate that
// can't be issued yet never holds up an apps deployment:
//
//   bicep snapshot deploy/azure/staging.certificates.bicepparam --resource-group rg-agentx-staging
//   az deployment group create --resource-group rg-agentx-staging \
//     --parameters deploy/azure/staging.certificates.bicepparam   # G3b
//
// - one certificate per door, named for the door, for exactly the host the
//   door serves; the policy rule `door-certificates` holds the two together
// - HTTP validation: a door's host has an A record for the environment's IP and
//   a TXT record `asuid.<host>` with its verification code (Microsoft, for a
//   custom domain on a route config), and Microsoft pairs an A record with
//   HTTP validation. DigiCert then fetches a token from the host itself, so
//   the host must answer while a certificate is issued and at every renewal
// - the hosts come from the shell that deploys, never from this repository
//   (Rule Book §7), the same variables the apps deployment reads
import { certificateName, resourceNames, resourceTags, uniqueSuffix } from 'names.bicep'

targetScope = 'resourceGroup'

@description('Which environment this is.')
@allowed([
  'staging'
  'production'
])
param environment string

@description('The region every resource is in: UAE deployments use uaenorth (ADR-009).')
param location string

@description('The suffix main.bicep was deployed with, so the names match.')
@minLength(4)
@maxLength(6)
param nameSuffix string = uniqueSuffix(subscription().id)

@description('The host name Zitadel is served on: the auth door\'s. The domain never sits in this repository (Rule Book §7).')
@minLength(4)
param authHost string

@description('The host name the API is served on: the app door\'s. The domain never sits in this repository (Rule Book §7).')
@minLength(4)
param appHost string

var names = resourceNames(environment, nameSuffix)

// Each door by its name in apps.bicep, with the host it serves.
var doorHosts = [
  {
    door: 'app'
    host: appHost
  }
  {
    door: 'auth'
    host: authHost
  }
]

// The environment the foundation created (G2b), which holds the doors.
resource appsEnvironment 'Microsoft.App/managedEnvironments@2026-01-01' existing = {
  name: names.appsEnvironment
}

resource doorCertificates 'Microsoft.App/managedEnvironments/managedCertificates@2026-01-01' = [
  for door in doorHosts: {
    parent: appsEnvironment
    name: certificateName(environment, door.door)
    location: location
    tags: resourceTags(environment)
    properties: {
      subjectName: door.host
      domainControlValidation: 'HTTP'
    }
  }
]
