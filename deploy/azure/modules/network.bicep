// The private network (ADR-002: "the production database isn't reachable from
// the internet"; the method, chosen in G1: VNet integration). Staging uses the
// same layout, so what production depends on is proven before it exists.
//
// - apps: the Container Apps environment (G2), delegated to it. Its address
//   range is also what the API trusts as its proxy (ADR-011 §4, set in G2)
// - database: the Postgres server, delegated to it, with a private DNS zone so
//   the server's name resolves to its private address inside the network.
//   Only the apps subnet may reach its port
// A server's networking can't be changed after it is created, and neither can
// an environment's subnet size (Microsoft), so both are fixed here.

param location string
param environment string
param tags object
param addressSpace string

var appsPrefix = cidrSubnet(addressSpace, 24, 0)
var databasePrefix = cidrSubnet(addressSpace, 24, 1)

resource databaseRules 'Microsoft.Network/networkSecurityGroups@2025-01-01' = {
  name: 'nsg-agentx-${environment}-database'
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
  name: 'vnet-agentx-${environment}'
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
  name: 'agentx-${environment}.private.postgres.database.azure.com'
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

resource appsSubnet 'Microsoft.Network/virtualNetworks/subnets@2025-01-01' existing = {
  parent: network
  name: 'apps'
}

resource databaseSubnet 'Microsoft.Network/virtualNetworks/subnets@2025-01-01' existing = {
  parent: network
  name: 'database'
}

output appsSubnetId string = appsSubnet.id
output appsSubnetPrefix string = appsPrefix
output databaseSubnetId string = databaseSubnet.id
// The server needs the zone linked to the network before it is created; the
// module that creates it waits for this whole module, the link included.
output databaseDnsZoneId string = databaseDns.id
