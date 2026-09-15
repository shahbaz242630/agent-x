// The environment's secret store (ADR-002; Security-Handoff §11). The platform
// hands its secrets to the containers as environment variables or files; the
// app has no Key Vault SDK (ADR-010). G2 adds the secrets and gives each app's
// identity read access to its own, one secret at a time.
//
// - access by Azure roles only, never access policies
// - purge protection: a deleted secret or vault stays recoverable for 90 days,
//   and nobody can purge it sooner, us included
// - requests only from the apps subnet: the apps read their secrets through
//   it, and nobody reads them from a browser or a laptop (the password manager
//   holds the copies people need). How G2 writes the secrets in is decided there
// - every read and change is logged to the workspace (AZKVAuditLogs)

param location string
param name string
param tags object
param appsSubnetId string
param workspaceId string

resource vault 'Microsoft.KeyVault/vaults@2025-05-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
    enablePurgeProtection: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    // Nothing else may fetch secrets on the vault's behalf.
    enabledForDeployment: false
    enabledForDiskEncryption: false
    enabledForTemplateDeployment: false
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'None'
      ipRules: []
      virtualNetworkRules: [
        {
          id: appsSubnetId
          ignoreMissingVnetServiceEndpoint: false
        }
      ]
    }
  }
}

resource audit 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: vault
  name: 'audit-to-workspace'
  properties: {
    workspaceId: workspaceId
    // Resource-specific tables (AZKVAuditLogs), not the shared AzureDiagnostics.
    logAnalyticsDestinationType: 'Dedicated'
    logs: [
      {
        categoryGroup: 'audit'
        enabled: true
      }
    ]
  }
}

output name string = vault.name
