// Every name lookup the network makes, watched (S68 audit finding 14; ADR-002,
// ADR-013). The apps subnet's rules let Azure's DNS out on port 53 (network.bicep),
// and a lookup of a name we don't own carries whatever is written into it to
// that name's server, so a container that was taken over could send data out
// that way, past the allowlist. A DNS resolver policy sees every lookup
// Azure's DNS answers for the network, public and private, and can allow,
// alert on or block each by name.
//
// Two rules. Above, at priority 1000, the names the network needs are allowed
// (dns-allowed.json, read from three days of lookups: S78); 100-999, which
// Azure reads first, stay free for blocks that must beat it (Microsoft's threat
// lists, a bad name under an allowed zone). Below, at the lowest priority
// (65000), every other name ('.') is alerted on, so each lookup lands in the
// workspace's DNSQueryLogs and nothing is refused yet: a lookup no allowed
// name covers shows that rule's list in ResolverPolicyDomainListId. Once a few
// days show none but the expected ones, that rule turns to Block
// (Carry-Forward). Blocking before that could stop Azure's own services in the
// environment, which Microsoft warns of.
//
// What Block can't promise (review, S78): Azure follows CNAME chains, so a
// name can be resolved, and its labels reach its own server, before any rule
// judges it; and a name pointing at an allowed one is answered. Block decides
// which lookups are answered. Whether it stops labels leaving is tested from a
// container before it is relied on (Carry-Forward).
//
// Cost: $0.60 per million lookups once a rule exists (Azure's price list,
// 30 Sep 2026); staging makes well under a million a month.

param location string
param policyName string
param domainListName string
param allowedListName string
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

resource allowed 'Microsoft.Network/dnsResolverDomainLists@2025-05-01' = {
  name: allowedListName
  location: location
  tags: tags
  properties: {
    domains: map(loadJsonContent('../dns-allowed.json', 'domains'), entry => entry.domain)
  }
}

resource allowNeededNames 'Microsoft.Network/dnsResolverPolicies/dnsSecurityRules@2025-05-01' = {
  parent: policy
  name: 'allow-needed-names'
  location: location
  tags: tags
  properties: {
    priority: 1000
    action: {
      actionType: 'Allow'
    }
    dnsResolverDomainLists: [
      {
        id: allowed.id
      }
    ]
    dnsSecurityRuleState: 'Enabled'
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
  // One rule at a time: a policy's rules are written one after another.
  dependsOn: [
    allowNeededNames
  ]
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
