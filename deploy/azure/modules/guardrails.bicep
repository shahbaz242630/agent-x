// Azure's own refusals on the resource group (AZ2, Carry-Forward "CI's reach on
// Azure"): Azure Policy rules with the Deny effect, so a write that breaks one
// is refused by Azure itself, whoever sends it: CI's release identity (which may
// write the API and the migration job), a person in the portal, or a template.
// policy.ts checks our templates before they ship; these hold what reaches Azure
// by any other way. Policy rule `azure-policy` runs each rule here over every
// resource the deployments create, which must all pass, and over a bad example
// of its own, which it must refuse:
//
// - the conditions use only aliases Azure lists for Microsoft.App
//   (`az provider show --namespace Microsoft.App --expand resourceTypes/aliases`,
//   S188), the two ingress ones as Azure's own built-in definitions use them
// - Azure judges a PATCH on the resource as it would be after it, merged with
//   what is stored (AZ2b, proved on staging S191: CI's partial update of the
//   containers alone left a `maxReplicas exists: false` audit silent). So the
//   replica and job rules (AZ2e) also refuse a field that is missing: Azure's
//   default for a missing maxReplicas is 10, and a create must name them all.
//   The image conditions keep their `exists`, inside a count of the containers
// - numbers are compared by list (`notIn`), never `greater`: Azure throws on a
//   type it can't compare, and a failed evaluation is a refusal
// - a `count` walks an array alias (`…containers[*]`), as Microsoft's page
//   requires, and its `where` reads each element's image
// - Indexed mode, as Azure's built-in "Allowed resource types": only types with
//   tags and a location are judged, so a deployment's own record, a role
//   assignment or a DNS record Azure writes for the database is never refused
// - every value is written out in the rule, never a parameter or variable: a
//   snapshot leaves an expression inside a policy rule unresolved, and the
//   checks read the rules as Azure will get them
// - what Azure Policy can't see is written down, not pretended: a job started
//   with its containers replaced (a POST, which policy never reads; the
//   job-start watch sees it, playbook T), and a door (`httpRouteConfigs`, which
//   has no alias), which CI's role can't write (rule `role-actions`)

targetScope = 'subscription'

@description('The environment, which names the rules: one subscription each, so the names never meet another environment\'s.')
param environment string

@description('The resource group the rules are given on: the foundation\'s, everything Agent X runs.')
param groupName string

var prefix = 'agentx-${environment}'

// An app open to the internet: the public doors are the route configs alone (ADR-002 Amendment G2e).
resource appsInternal 'Microsoft.Authorization/policyDefinitions@2025-01-01' = {
  name: '${prefix}-apps-internal'
  properties: {
    policyType: 'Custom'
    mode: 'Indexed'
    displayName: 'Agent X: no app open to the internet'
    description: 'An app\'s ingress stays internal: the public doors are the route configs alone (ADR-002 Amendment G2e).'
    metadata: {
      category: 'Agent X'
    }
    policyRule: {
      if: {
        allOf: [
          {
            field: 'type'
            equals: 'Microsoft.App/containerApps'
          }
          {
            field: 'Microsoft.App/containerApps/configuration.ingress.external'
            equals: true
          }
        ]
      }
      then: {
        effect: 'deny'
      }
    }
  }
}

// An app over plain http, even inside the environment (ADR-002 Amendment G2d).
resource appsHttps 'Microsoft.Authorization/policyDefinitions@2025-01-01' = {
  name: '${prefix}-apps-https'
  properties: {
    policyType: 'Custom'
    mode: 'Indexed'
    displayName: 'Agent X: no app over plain http'
    description: 'An app\'s ingress refuses plain http, even inside the environment (ADR-002 Amendment G2d).'
    metadata: {
      category: 'Agent X'
    }
    policyRule: {
      if: {
        allOf: [
          {
            field: 'type'
            equals: 'Microsoft.App/containerApps'
          }
          {
            field: 'Microsoft.App/containerApps/configuration.ingress.allowInsecure'
            equals: true
          }
        ]
      }
      then: {
        effect: 'deny'
      }
    }
  }
}

// An image that is not ours by digest, nor Zitadel's by tag and digest (SEC-SC-02), wherever an app or a job
// names one (each `[*].image` alias). Azure's `like` takes one wildcard, so the digest is a condition of its own.
resource ourImages 'Microsoft.Authorization/policyDefinitions@2025-01-01' = {
  name: '${prefix}-images'
  properties: {
    policyType: 'Custom'
    mode: 'Indexed'
    displayName: 'Agent X: only our images, by digest'
    description: 'Every app and job runs our image or Zitadel\'s, each named by digest (SEC-SC-02).'
    metadata: {
      category: 'Agent X'
    }
    policyRule: {
      if: {
        anyOf: [
          {
            allOf: [
              {
                field: 'type'
                equals: 'Microsoft.App/containerApps'
              }
              {
                anyOf: [
                  {
                    count: {
                      field: 'Microsoft.App/containerApps/template.containers[*]'
                      where: {
                        allOf: [
                          {
                            field: 'Microsoft.App/containerApps/template.containers[*].image'
                            exists: true
                          }
                          {
                            anyOf: [
                              {
                                field: 'Microsoft.App/containerApps/template.containers[*].image'
                                notContains: '@sha256:'
                              }
                              {
                                allOf: [
                                  {
                                    field: 'Microsoft.App/containerApps/template.containers[*].image'
                                    notLike: 'ghcr.io/shahbaz242630/agent-x@sha256:*'
                                  }
                                  {
                                    field: 'Microsoft.App/containerApps/template.containers[*].image'
                                    notLike: 'ghcr.io/shahbaz242630/agent-x-load@sha256:*'
                                  }
                                  {
                                    field: 'Microsoft.App/containerApps/template.containers[*].image'
                                    notLike: 'ghcr.io/zitadel/zitadel:*'
                                  }
                                  {
                                    field: 'Microsoft.App/containerApps/template.containers[*].image'
                                    notLike: 'ghcr.io/zitadel/zitadel-login:*'
                                  }
                                ]
                              }
                            ]
                          }
                        ]
                      }
                    }
                    greater: 0
                  }
                  {
                    count: {
                      field: 'Microsoft.App/containerApps/template.initContainers[*]'
                      where: {
                        allOf: [
                          {
                            field: 'Microsoft.App/containerApps/template.initContainers[*].image'
                            exists: true
                          }
                          {
                            anyOf: [
                              {
                                field: 'Microsoft.App/containerApps/template.initContainers[*].image'
                                notContains: '@sha256:'
                              }
                              {
                                allOf: [
                                  {
                                    field: 'Microsoft.App/containerApps/template.initContainers[*].image'
                                    notLike: 'ghcr.io/shahbaz242630/agent-x@sha256:*'
                                  }
                                  {
                                    field: 'Microsoft.App/containerApps/template.initContainers[*].image'
                                    notLike: 'ghcr.io/shahbaz242630/agent-x-load@sha256:*'
                                  }
                                  {
                                    field: 'Microsoft.App/containerApps/template.initContainers[*].image'
                                    notLike: 'ghcr.io/zitadel/zitadel:*'
                                  }
                                  {
                                    field: 'Microsoft.App/containerApps/template.initContainers[*].image'
                                    notLike: 'ghcr.io/zitadel/zitadel-login:*'
                                  }
                                ]
                              }
                            ]
                          }
                        ]
                      }
                    }
                    greater: 0
                  }
                ]
              }
            ]
          }
          {
            allOf: [
              {
                field: 'type'
                equals: 'Microsoft.App/jobs'
              }
              {
                anyOf: [
                  {
                    count: {
                      field: 'Microsoft.App/jobs/template.containers[*]'
                      where: {
                        allOf: [
                          {
                            field: 'Microsoft.App/jobs/template.containers[*].image'
                            exists: true
                          }
                          {
                            anyOf: [
                              {
                                field: 'Microsoft.App/jobs/template.containers[*].image'
                                notContains: '@sha256:'
                              }
                              {
                                allOf: [
                                  {
                                    field: 'Microsoft.App/jobs/template.containers[*].image'
                                    notLike: 'ghcr.io/shahbaz242630/agent-x@sha256:*'
                                  }
                                  {
                                    field: 'Microsoft.App/jobs/template.containers[*].image'
                                    notLike: 'ghcr.io/shahbaz242630/agent-x-load@sha256:*'
                                  }
                                  {
                                    field: 'Microsoft.App/jobs/template.containers[*].image'
                                    notLike: 'ghcr.io/zitadel/zitadel:*'
                                  }
                                  {
                                    field: 'Microsoft.App/jobs/template.containers[*].image'
                                    notLike: 'ghcr.io/zitadel/zitadel-login:*'
                                  }
                                ]
                              }
                            ]
                          }
                        ]
                      }
                    }
                    greater: 0
                  }
                  {
                    count: {
                      field: 'Microsoft.App/jobs/template.initContainers[*]'
                      where: {
                        allOf: [
                          {
                            field: 'Microsoft.App/jobs/template.initContainers[*].image'
                            exists: true
                          }
                          {
                            anyOf: [
                              {
                                field: 'Microsoft.App/jobs/template.initContainers[*].image'
                                notContains: '@sha256:'
                              }
                              {
                                allOf: [
                                  {
                                    field: 'Microsoft.App/jobs/template.initContainers[*].image'
                                    notLike: 'ghcr.io/shahbaz242630/agent-x@sha256:*'
                                  }
                                  {
                                    field: 'Microsoft.App/jobs/template.initContainers[*].image'
                                    notLike: 'ghcr.io/shahbaz242630/agent-x-load@sha256:*'
                                  }
                                  {
                                    field: 'Microsoft.App/jobs/template.initContainers[*].image'
                                    notLike: 'ghcr.io/zitadel/zitadel:*'
                                  }
                                  {
                                    field: 'Microsoft.App/jobs/template.initContainers[*].image'
                                    notLike: 'ghcr.io/zitadel/zitadel-login:*'
                                  }
                                ]
                              }
                            ]
                          }
                        ]
                      }
                    }
                    greater: 0
                  }
                ]
              }
            ]
          }
        ]
      }
      then: {
        effect: 'deny'
      }
    }
  }
}

// A job that starts itself, or runs more than one replica a run (ADR-002 Amendment G2d).
resource jobsByHand 'Microsoft.Authorization/policyDefinitions@2025-01-01' = {
  name: '${prefix}-jobs-by-hand'
  properties: {
    policyType: 'Custom'
    mode: 'Indexed'
    displayName: 'Agent X: jobs started by hand, one replica a run'
    description: 'Every job is started by hand and runs one replica a run (ADR-002 Amendment G2d): one that starts itself would use its secrets unwatched.'
    metadata: {
      category: 'Agent X'
    }
    policyRule: {
      if: {
        allOf: [
          {
            field: 'type'
            equals: 'Microsoft.App/jobs'
          }
          {
            anyOf: [
              {
                field: 'Microsoft.App/jobs/configuration.triggerType'
                notEquals: 'Manual'
              }
              {
                field: 'Microsoft.App/jobs/configuration.manualTriggerConfig.parallelism'
                notIn: [
                  0
                  1
                ]
              }
              {
                field: 'Microsoft.App/jobs/configuration.manualTriggerConfig.replicaCompletionCount'
                notIn: [
                  0
                  1
                ]
              }
            ]
          }
        ]
      }
      then: {
        effect: 'deny'
      }
    }
  }
}

// An app above four replicas, the most any environment runs (production's Zitadel; staging's load run three web copies),
// or the jobs app above one (4D2e D12-D13). A missing maxReplicas is refused too (AZ2e): Azure's default would be 10,
// and a PATCH is judged merged with the stored app (AZ2b), so CI's partial update still carries the stored number.
resource appReplicas 'Microsoft.Authorization/policyDefinitions@2025-01-01' = {
  name: '${prefix}-app-replicas'
  properties: {
    policyType: 'Custom'
    mode: 'Indexed'
    displayName: 'Agent X: app replicas capped'
    description: 'The jobs app runs one replica, and no app more than four, the most any environment runs (4D2e D12-D13). An app without maxReplicas is refused: Azure would take 10.'
    metadata: {
      category: 'Agent X'
    }
    policyRule: {
      if: {
        allOf: [
          {
            field: 'type'
            equals: 'Microsoft.App/containerApps'
          }
          {
            anyOf: [
              {
                field: 'Microsoft.App/containerApps/template.scale.maxReplicas'
                notIn: [
                  0
                  1
                  2
                  3
                  4
                ]
              }
              {
                allOf: [
                  {
                    field: 'name'
                    like: '*-jobs'
                  }
                  {
                    field: 'Microsoft.App/containerApps/template.scale.maxReplicas'
                    notIn: [
                      0
                      1
                    ]
                  }
                ]
              }
            ]
          }
        ]
      }
      then: {
        effect: 'deny'
      }
    }
  }
}

// A type the deployments don't create (Indexed, as Azure's built-in "Allowed resource types"): every type they do
// (policy rule `azure-policy` holds the list to the snapshot exactly), the deployments' own records, and AZ11's private
// endpoint, its zone group and the network interface Azure makes for it, allowed a foundation before the endpoint lands.
// Never Microsoft.AlertsManagement/actionRules: one in the group could mute every alarm, the access alarm's among
// them (AZ5e review S192), and this rule is all that keeps CI's Contributor from making one (policy.test.ts holds it).
resource allowedTypes 'Microsoft.Authorization/policyDefinitions@2025-01-01' = {
  name: '${prefix}-allowed-types'
  properties: {
    policyType: 'Custom'
    mode: 'Indexed'
    displayName: 'Agent X: only the types we deploy'
    description: 'Only the resource types the deployments create may be made here (Indexed, as Azure\'s built-in Allowed resource types).'
    metadata: {
      category: 'Agent X'
    }
    policyRule: {
      if: {
        not: {
          field: 'type'
          in: [
            'Microsoft.App/containerApps'
            'Microsoft.App/jobs'
            'Microsoft.App/managedEnvironments'
            'Microsoft.App/managedEnvironments/httpRouteConfigs'
            'Microsoft.App/managedEnvironments/managedCertificates'
            'Microsoft.Authorization/locks'
            'Microsoft.Authorization/policyAssignments'
            'Microsoft.Authorization/policyDefinitions'
            'Microsoft.Authorization/roleAssignments'
            'Microsoft.Authorization/roleDefinitions'
            'Microsoft.Communication/communicationServices'
            'Microsoft.Communication/emailServices'
            'Microsoft.Communication/emailServices/domains'
            'Microsoft.Consumption/budgets'
            'Microsoft.DBforPostgreSQL/flexibleServers'
            'Microsoft.DBforPostgreSQL/flexibleServers/configurations'
            'Microsoft.Insights/actionGroups'
            'Microsoft.Insights/activityLogAlerts'
            'Microsoft.Insights/diagnosticSettings'
            'Microsoft.Insights/metricAlerts'
            'Microsoft.Insights/scheduledQueryRules'
            'Microsoft.Insights/workbooks'
            'Microsoft.KeyVault/vaults'
            'Microsoft.KeyVault/vaults/secrets'
            'Microsoft.ManagedIdentity/userAssignedIdentities'
            'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials'
            'Microsoft.Network/dnsResolverDomainLists'
            'Microsoft.Network/dnsResolverPolicies'
            'Microsoft.Network/dnsResolverPolicies/dnsSecurityRules'
            'Microsoft.Network/dnsResolverPolicies/virtualNetworkLinks'
            'Microsoft.Network/networkInterfaces'
            'Microsoft.Network/networkSecurityGroups'
            'Microsoft.Network/privateDnsZones'
            'Microsoft.Network/privateDnsZones/virtualNetworkLinks'
            'Microsoft.Network/privateEndpoints'
            'Microsoft.Network/privateEndpoints/privateDnsZoneGroups'
            'Microsoft.Network/virtualNetworks'
            'Microsoft.OperationalInsights/workspaces'
            'Microsoft.OperationalInsights/workspaces/savedSearches'
            'Microsoft.Resources/deployments'
            'Microsoft.Resources/resourceGroups'
            'Microsoft.Storage/storageAccounts'
            'Microsoft.Storage/storageAccounts/blobServices'
            'Microsoft.Storage/storageAccounts/blobServices/containers'
            'Microsoft.Storage/storageAccounts/managementPolicies'
          ]
        }
      }
      then: {
        effect: 'deny'
      }
    }
  }
}

// Given on the resource group, where every Agent X resource is, and nowhere
// wider: the subscription's other groups (Azure's own NetworkWatcherRG, the
// Container Apps environment's infrastructure group) are left alone. Each with
// the words a refused request gets back: what was refused and what to do.
module given 'guardrail-assignments.bicep' = {
  scope: resourceGroup(groupName)
  params: {
    rules: [
      {
        name: appsInternal.name
        displayName: appsInternal.properties.displayName
        message: 'Refused: this app would be open to the internet (ingress external), which only the public doors may be. Nothing changed; deploy the app as deploy/azure/apps.bicep writes it.'
        definitionId: appsInternal.id
      }
      {
        name: appsHttps.name
        displayName: appsHttps.properties.displayName
        message: 'Refused: this app would answer over plain http (allowInsecure). Nothing changed; deploy the app as deploy/azure/apps.bicep writes it.'
        definitionId: appsHttps.id
      }
      {
        name: ourImages.name
        displayName: ourImages.properties.displayName
        message: 'Refused: an app or job would run an image that is not ours or Zitadel\'s by digest. Nothing changed; deploy a signed image of ours by its digest.'
        definitionId: ourImages.id
      }
      {
        name: jobsByHand.name
        displayName: jobsByHand.properties.displayName
        message: 'Refused: this job would start itself (a schedule or an event) or run more than one replica a run. Nothing changed; deploy the job as deploy/azure/apps.bicep writes it.'
        definitionId: jobsByHand.id
      }
      {
        name: appReplicas.name
        displayName: appReplicas.properties.displayName
        message: 'Refused: an app would run more replicas than Agent X ever runs here (the jobs app one). Nothing changed; deploy the app as deploy/azure/apps.bicep writes it.'
        definitionId: appReplicas.id
      }
      {
        name: allowedTypes.name
        displayName: allowedTypes.properties.displayName
        message: 'Refused: Agent X deploys no resource of this type. Nothing changed; a new type is added to deploy/azure/modules/guardrails.bicep first, through a pull request.'
        definitionId: allowedTypes.id
      }
    ]
  }
}
