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

param location string
param name string
param appsRulesName string
param databaseRulesName string
param databaseZoneName string
param tags object
param addressSpace string

var appsPrefix = cidrSubnet(addressSpace, 24, 0)
var databasePrefix = cidrSubnet(addressSpace, 24, 1)

// Microsoft's inbound list for a workload profiles environment. The apps take
// public traffic through the environment's public IP, which Microsoft says
// doesn't pass through the subnet, so these rules can't filter it (the route
// configs are the public doors). What they do: nothing else in the network (the
// database subnet, a subnet added later) reaches the apps. Outbound stays at
// Azure's defaults: the image comes from ghcr.io, which has no service tag.
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
