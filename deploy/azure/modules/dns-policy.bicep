// Every name lookup the network makes, watched (S68 audit finding 14; ADR-002,
// ADR-013). The apps subnet's rules let Azure's DNS out on port 53 (network.bicep),
// and a lookup of a name we don't own carries whatever is written into it to
// that name's server, so a container that was taken over could send data out
// that way, past the allowlist. A DNS resolver policy sees every lookup
// Azure's DNS answers for the network, public and private, and can allow,
// alert on or block each by name.
//
// This first step only watches: one rule, at the lowest priority (65000,
// leaving 100–64999 for the rules above it), alerts on every name ('.'), so
// each lookup lands in the workspace's DNSQueryLogs and nothing is refused.
// The next step reads a few days of those lookups, allows the names the
// apps and jobs need in a rule above it, and turns this one to Block
// (Carry-Forward). Blocking before that could stop Azure's own services in the
// environment, which Microsoft warns of.
//
// Cost: $0.60 per million lookups once a rule exists (Azure's price list,
// 30 Sep 2026); staging makes well under a million a month.

param location string
param policyName string
param domainListName string
param tags object
param networkId string
param workspaceId string

resource policy 'Microsoft.Network/dnsResolverPolicies@2025-05-01' = {
  name: policyName
  location: location
  tags: tags
  properties: {}
}

// '.' is every name (Microsoft: "a rule that applies to the '.' domain").
resource everyName 'Microsoft.Network/dnsResolverDomainLists@2025-05-01' = {
  name: domainListName
  location: location
  tags: tags
  properties: {
    domains: ['.']
  }
}

resource watchEveryLookup 'Microsoft.Network/dnsResolverPolicies/dnsSecurityRules@2025-05-01' = {
  parent: policy
  name: 'watch-every-lookup'
  location: location
  tags: tags
  properties: {
    priority: 65000
    action: {
      actionType: 'Alert'
    }
    dnsResolverDomainLists: [
      {
        id: everyName.id
      }
    ]
    dnsSecurityRuleState: 'Enabled'
  }
}

// One policy per network (Microsoft), in the network's own region.
resource networkLink 'Microsoft.Network/dnsResolverPolicies/virtualNetworkLinks@2025-05-01' = {
  parent: policy
  name: 'network'
  location: location
  tags: tags
  properties: {
    virtualNetwork: {
      id: networkId
    }
  }
}

// Every lookup and the rule's action on it, in the workspace (DNSQueryLogs).
resource lookups 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: policy
  name: 'lookups-to-workspace'
  properties: {
    workspaceId: workspaceId
    logAnalyticsDestinationType: 'Dedicated'
    logs: [
      {
        category: 'DnsResponse'
        enabled: true
      }
    ]
  }
}
