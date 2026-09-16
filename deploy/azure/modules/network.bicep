// The private network (ADR-002: "the production database isn't reachable from
// the internet"; the method, chosen in G1: VNet integration). Staging uses the
// same layout, so what production depends on is proven before it exists.
//
// - apps: the Container Apps environment (environment.bicep), delegated to it.
//   Its address range is also what the API trusts as its proxy (ADR-011 §4,
//   set with the apps). Only the load balancer's probes and the subnet itself
//   may reach it from the network
// - database: the Postgres server, delegated to it, with a private DNS zone so
//   the server's name resolves to its private address inside the network.
//   Only the apps subnet, and the server's own subnet, may reach its port
// A server's networking can't be changed after it is created, and neither can
// an environment's subnet size (Microsoft), so both are fixed here.

import { appsPrefix as appsSubnetPrefix } from '../names.bicep'

param location string
param name string
param appsRulesName string
param databaseRulesName string
param databaseZoneName string
param tags object
param addressSpace string

// The one spelling of the apps subnet's range: the apps deployment reads the
// same function for what the API trusts as its proxy.
var appsPrefix = appsSubnetPrefix(addressSpace)
var databasePrefix = cidrSubnet(addressSpace, 24, 1)

// GitHub's published addresses for pulling our image, refreshed by hand
// (deploy/azure/github-ranges.ts says where they come from and how). Loaded at
// build time, so the compiled template — and the check that reads it — hold the
// exact list this deployment would create.
var githubRegistry = loadJsonContent('../github-ranges.json', 'registry.prefixes')
var githubDownloads = loadJsonContent('../github-ranges.json', 'downloads.prefixes')

// Microsoft's inbound list for a workload profiles environment. The apps take
// public traffic through the environment's public IP, which Microsoft says
// doesn't pass through the subnet, so these rules can't filter it (the route
// configs are the public doors). What they do: nothing else in the network (the
// database subnet, a subnet added later) reaches the apps.
//
// Outbound (G2d-3) is an allowlist. Azure's default rules let a subnet reach
// the whole internet, so a container that was taken over could send anything
// anywhere, out of the UAE (ADR-009, ADR-013). The rules below name what the
// apps and jobs actually need and deny the rest after them. Chosen over a NAT
// gateway (~$33/month plus $0.045/GB) and an Azure Firewall (~$913/month in
// UAE North), which name hosts rather than addresses; the allowlist costs
// nothing (partner decision, ADR-002 Amendment G2d-3). Revisit before
// production, where a firewall's names would survive GitHub changing an
// address. Inbound rules are numbered from 100, outbound from 200.
resource appsRules 'Microsoft.Network/networkSecurityGroups@2025-01-01' = {
  name: appsRulesName
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'allow-load-balancer-probes'
        properties: {
          description: 'Azure\'s load balancer probes the environment\'s nodes on these ports (Microsoft).'
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: 'AzureLoadBalancer'
          sourcePortRange: '*'
          destinationAddressPrefix: appsPrefix
          destinationPortRange: '30000-32767'
        }
      }
      {
        name: 'allow-within-subnet'
        properties: {
          description: 'The environment\'s own traffic: its proxy, the apps and the jobs reaching each other inside the subnet.'
          priority: 110
          direction: 'Inbound'
          access: 'Allow'
          protocol: '*'
          sourceAddressPrefix: appsPrefix
          sourcePortRange: '*'
          destinationAddressPrefix: appsPrefix
          destinationPortRange: '*'
        }
      }
      {
        name: 'deny-rest-of-network'
        properties: {
          description: 'Overrides Azure\'s default rule that lets the whole network in.'
          priority: 4000
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: 'VirtualNetwork'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
      {
        name: 'allow-out-within-subnet'
        properties: {
          description: 'The environment\'s own traffic between its nodes, which Microsoft requires.'
          priority: 200
          direction: 'Outbound'
          access: 'Allow'
          protocol: '*'
          sourceAddressPrefix: appsPrefix
          sourcePortRange: '*'
          destinationAddressPrefix: appsPrefix
          destinationPortRange: '*'
        }
      }
      {
        // Microsoft: traffic to this address isn't subject to an NSG unless a
        // rule names the AzurePlatformDNS tag, and denying it stops the
        // environment working — no rule here names that tag. The allow is kept
        // so the dependency is written down rather than relied on silently. One
        // rule with protocol `*`, because a rule takes one protocol and
        // Microsoft asks for both TCP and UDP.
        name: 'allow-out-azure-dns'
        properties: {
          description: 'Azure\'s own DNS, over TCP and UDP: it resolves the database\'s private name and every host below.'
          priority: 210
          direction: 'Outbound'
          access: 'Allow'
          protocol: '*'
          sourceAddressPrefix: appsPrefix
          sourcePortRange: '*'
          destinationAddressPrefix: '168.63.129.16'
          destinationPortRange: '53'
        }
      }
      {
        name: 'allow-out-database'
        properties: {
          description: 'The apps and jobs reach Postgres in its own subnet, and nothing else in the network.'
          priority: 220
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: appsPrefix
          sourcePortRange: '*'
          destinationAddressPrefix: databasePrefix
          destinationPortRange: '5432'
        }
      }
      {
        // The regional tag, so a container that was taken over can't reach a key
        // vault in another country (ADR-009). G3 confirms Azure accepts it.
        name: 'allow-out-key-vault'
        properties: {
          description: 'Every secret an app or job reads, through the subnet\'s Key Vault service endpoint, in this region only.'
          priority: 230
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: appsPrefix
          sourcePortRange: '*'
          destinationAddressPrefix: 'AzureKeyVault.${location}'
          destinationPortRange: '443'
        }
      }
      {
        // Not the regional tag: Microsoft's own list names AzureMonitor plain,
        // and ingestion uses global endpoints too. What keeps the data in the
        // UAE is the workspace's own region (ADR-013), not this rule.
        name: 'allow-out-monitor'
        properties: {
          description: 'The apps\' console logs on their way to the workspace (Microsoft\'s required list).'
          priority: 240
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: appsPrefix
          sourcePortRange: '*'
          destinationAddressPrefix: 'AzureMonitor'
          destinationPortRange: '443'
        }
      }
      {
        name: 'allow-out-entra'
        properties: {
          description: 'Where each identity gets the token it reads its own secrets with (Microsoft\'s required list).'
          priority: 250
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: appsPrefix
          sourcePortRange: '*'
          destinationAddressPrefix: 'AzureActiveDirectory'
          destinationPortRange: '443'
        }
      }
      {
        name: 'allow-out-platform-images'
        properties: {
          description: 'Microsoft Artifact Registry, which the platform pulls its own system containers from (Microsoft\'s required list).'
          priority: 260
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: appsPrefix
          sourcePortRange: '*'
          destinationAddressPrefix: 'MicrosoftContainerRegistry'
          destinationPortRange: '443'
        }
      }
      {
        name: 'allow-out-platform-images-front-door'
        properties: {
          description: 'Microsoft names this a dependency of MicrosoftContainerRegistry; the platform\'s pull fails without it.'
          priority: 270
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: appsPrefix
          sourcePortRange: '*'
          destinationAddressPrefix: 'AzureFrontDoor.FirstParty'
          destinationPortRange: '443'
        }
      }
      {
        // GitHub has no service tag, so these are its published addresses.
        name: 'allow-out-github-registry'
        properties: {
          description: 'ghcr.io, for the pull token and the image manifest: GitHub\'s published addresses (github-ranges.json).'
          priority: 280
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: appsPrefix
          sourcePortRange: '*'
          destinationAddressPrefixes: githubRegistry
          destinationPortRange: '443'
        }
      }
      {
        // Without this rule a pull reads the manifest and then hangs on the
        // first layer: ghcr.io answers every blob with a 307 to this host, and
        // its addresses are in none of meta's package ranges (github-ranges.ts).
        name: 'allow-out-github-downloads'
        properties: {
          description: 'Where ghcr.io redirects every layer download; a second set of GitHub addresses, pinned by hand (github-ranges.json).'
          priority: 290
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: appsPrefix
          sourcePortRange: '*'
          destinationAddressPrefixes: githubDownloads
          destinationPortRange: '443'
        }
      }
      {
        name: 'deny-out-rest'
        properties: {
          description: 'Overrides Azure\'s default rules that let the subnet reach the whole internet: nothing leaves but what is allowed above.'
          priority: 4000
          direction: 'Outbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
    ]
  }
}

resource databaseRules 'Microsoft.Network/networkSecurityGroups@2025-01-01' = {
  name: databaseRulesName
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'allow-postgres-from-apps'
        properties: {
          description: 'The apps (the API, the worker, the jobs, the login service) reach Postgres; nothing else in the network does.'
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: appsPrefix
          sourcePortRange: '*'
          destinationAddressPrefix: databasePrefix
          destinationPortRange: '5432'
        }
      }
      {
        // Microsoft: a server's own features (high availability among them) need
        // port 5432 open inside its subnet, so a rule that denies the network
        // must let the subnet reach itself.
        name: 'allow-postgres-within-subnet'
        properties: {
          description: 'The server\'s own traffic inside its subnet, which Microsoft requires when an NSG denies the rest.'
          priority: 110
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: databasePrefix
          sourcePortRange: '*'
          destinationAddressPrefix: databasePrefix
          destinationPortRange: '5432'
        }
      }
      {
        name: 'deny-rest-of-network'
        properties: {
          description: 'Overrides Azure\'s default rule that lets the whole network in.'
          priority: 4000
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: 'VirtualNetwork'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
    ]
  }
}

resource network 'Microsoft.Network/virtualNetworks@2025-01-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: [addressSpace]
    }
    subnets: [
      {
        name: 'apps'
        properties: {
          addressPrefix: appsPrefix
          networkSecurityGroup: {
            id: appsRules.id
          }
          delegations: [
            {
              name: 'container-apps'
              properties: {
                serviceName: 'Microsoft.App/environments'
              }
            }
          ]
          // Lets the key vault take requests from this subnet and refuse the rest (keyvault.bicep).
          serviceEndpoints: [
            {
              service: 'Microsoft.KeyVault'
              locations: [location]
            }
          ]
        }
      }
      {
        name: 'database'
        properties: {
          addressPrefix: databasePrefix
          networkSecurityGroup: {
            id: databaseRules.id
          }
          // Azure adds this endpoint itself when the first server is created
          // (Microsoft: it carries the server's write-ahead log to Azure Storage).
          // Declared here, so a redeploy of the network keeps it.
          serviceEndpoints: [
            {
              service: 'Microsoft.Storage'
            }
          ]
          delegations: [
            {
              name: 'postgres'
              properties: {
                serviceName: 'Microsoft.DBforPostgreSQL/flexibleServers'
              }
            }
          ]
        }
      }
    ]
  }
}

// The zone's name must end in private.postgres.database.azure.com (Microsoft).
resource databaseDns 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: databaseZoneName
  location: 'global'
  tags: tags
}

resource databaseDnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: databaseDns
  name: network.name
  location: 'global'
  tags: tags
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: network.id
    }
  }
}
