// The two identities CI's infrastructure deploy signs in as (AZ5), each trusting
// one GitHub environment's jobs alone. Azure compares a subject exactly, and a
// wrong one fails without an error. Nothing runs as either: they only sign in
// from GitHub, so each is usable in this region alone, as every identity here.

param location string
param tags object
param infraName string
@description('A job of this repository in GitHub\'s `staging-infra` environment, which only main may use and the partner approves.')
param infraSubject string
param whatIfName string
@description('A job of this repository in GitHub\'s `staging-whatif` environment, which only main may use.')
param whatIfSubject string

resource infra 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' = {
  name: infraName
  location: location
  tags: tags
  properties: {
    isolationScope: 'Regional'
  }
}

// One trust per identity: Azure refuses two written at once.
resource infraTrust 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials@2024-11-30' = {
  parent: infra
  name: 'github'
  properties: {
    issuer: 'https://token.actions.githubusercontent.com'
    subject: infraSubject
    audiences: [
      'api://AzureADTokenExchange'
    ]
  }
}

resource whatIf 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' = {
  name: whatIfName
  location: location
  tags: tags
  properties: {
    isolationScope: 'Regional'
  }
}

resource whatIfTrust 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials@2024-11-30' = {
  parent: whatIf
  name: 'github'
  properties: {
    issuer: 'https://token.actions.githubusercontent.com'
    subject: whatIfSubject
    audiences: [
      'api://AzureADTokenExchange'
    ]
  }
}

output infraPrincipalId string = infra.properties.principalId
output infraClientId string = infra.properties.clientId
output whatIfPrincipalId string = whatIf.properties.principalId
output whatIfClientId string = whatIf.properties.clientId
