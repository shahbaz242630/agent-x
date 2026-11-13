// Every name lookup the network makes, watched (S68 audit finding 14; ADR-002,
// ADR-013). The apps subnet's rules let Azure's DNS out on port 53 (network.bicep),
// and a lookup of a name we don't own carries whatever is written into it to
// that name's server, so a container that was taken over could send data out
// that way, past the allowlist. A DNS resolver policy sees every lookup
// Azure's DNS answers for the network, public and private, and can allow,
// alert on or block each by name.
//
// Two rules. Above, at priority 1000, the names the network needs are allowed
// (dns-allowed.json, read from the lookups: S78, S84, S98, S188); 100-999,
// which Azure reads first, stay free for blocks that must beat it (Microsoft's
// threat lists, a bad name under an allowed zone). Below, at the lowest
// priority (65000), every other name ('.') is blocked (AZ1, S188), and each
// lookup still lands in the workspace's DNSQueryLogs: a lookup no allowed name
// covers shows that rule's list in ResolverPolicyDomainListId. Microsoft warns
// that blocking every name can stop Azure's own services, so the rule went to
// Block only after the 31 days of logs kept (13 Oct to 13 Nov 2026) showed
// every lookup's chain ending at a listed name but k6's usage report (turned
// off), and the alert below tells someone, within one 15 minute window, of
// any lookup it refuses but the expected leftovers.
//
// What Block can't promise (review, S78; S188): Azure resolves a CNAME chain
// before any rule judges it, so a name's labels reach its own server however
// the rule answers; and staging's logs show the action set by the chain's last
// name alone (Microsoft says a rule applies to a name anywhere in the chain;
// dns-allowed.json lists the middle hops seen too, but not two old asked
// names a stricter reading would block), and two asked names no entry covers
// were allowed for their chains' ends, so a name of anyone's pointing at an
// allowed one is likely answered. Block decides which lookups are
// answered. Whether it stops labels leaving is tested from a container before
// it is relied on (Azure.md, "DNS Block: the proof").
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
param actionGroupId string
param blockedAlertName string

// The lookups the catch-all refuses that are expected, each answered no-such-name before Block too, their labels
// reaching only servers no customer runs: reverse lookups of private addresses, the root's NS, the nodes' bare
// names and CoreDNS's loop check (a HINFO of two random numbers). Exactly policy.ts's DNS_EXPECTED_LEFTOVERS.
var expectedLeftovers = 'where not((QueryType == "PTR" and (QueryName endswith ".10.in-addr.arpa." or QueryName endswith ".100.100.in-addr.arpa.")) or (QueryType == "NS" and QueryName == ".") or (QueryType == "HINFO" and QueryName matches regex "^[0-9]+[.][0-9]+[.]$") or QueryName matches regex "^aks-[a-z0-9]+-[0-9]+-vmss[0-9A-Z]{6}[.]$")'

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
      actionType: 'Block'
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

// Any lookup the catch-all blocks but the expected leftovers (AZ1, S188; partner S98): Microsoft adds storage stamps
// and moves the names behind its services, and an unlisted one blocked can stop the key vault, sign-in, image pulls or
// a database's backups; a taken-over container's lookups land here too. Only the count leaves the workspace; the
// lines say which name and from where. Stateless: every window holding one notifies again.
resource blockedAlert 'Microsoft.Insights/scheduledQueryRules@2026-03-01' = {
  name: blockedAlertName
  location: location
  tags: tags
  kind: 'LogAlert'
  properties: {
    displayName: 'DNS: a lookup was blocked'
    description: 'SEV-1. The DNS policy blocked a lookup that no allowed name covers and that is not one of the expected leftovers: a Microsoft name the allowlist lacks (the vault, sign-in, image pulls or a database\'s backups may be failing) or a container looking up a name it should not. Runbook: Incident-Response-Playbook.md section W.'
    severity: 1
    enabled: true
    scopes: [workspaceId]
    evaluationFrequency: 'PT15M'
    windowSize: 'PT15M'
    // The table appears with the policy's first logged lookup, after this rule exists.
    skipQueryValidation: true
    criteria: {
      allOf: [
        {
          query: 'DNSQueryLogs | where ResolverPolicyDomainListId endswith "/${everyName.name}" | ${expectedLeftovers} | summarize Lookups = count()'
          timeAggregation: 'Total'
          metricMeasureColumn: 'Lookups'
          operator: 'GreaterThan'
          threshold: 0
          failingPeriods: {
            numberOfEvaluationPeriods: 1
            minFailingPeriodsToAlert: 1
          }
        }
      ]
    }
    autoMitigate: false
    actions: {
      actionGroups: [actionGroupId]
    }
  }
  dependsOn: [lookups]
}
