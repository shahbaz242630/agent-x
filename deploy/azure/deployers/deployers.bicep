// Who deploys staging's infrastructure from GitHub (AZ5, decision 40): the
// hand deploys foundation, secrets --keys, apps and the set-up job move from the
// partner's terminal to one tap of Approve in GitHub's `staging-infra`
// environment. Deployed by the partner alone, never by CI, so no identity here
// can change its own trust or rights:
//
//   node deploy/azure/infra.ts deployers   # from the partner's own terminal
//
// - two identities, in a resource group of their own, which the foundation's
//   deployments never touch and the infra identity's rights on staging's group
//   don't reach
// - the infra identity: trusted only for a job in GitHub's `staging-infra`
//   environment (main only, the partner the required reviewer). It holds what
//   the partner's deploy uses on staging's group (Contributor, the foundation's
//   own role and policy writes, and grants limited to the roles our Bicep gives,
//   never to itself) and, on the subscription, only the deployment itself and
//   the three things the foundation writes there: the budget, the activity log's
//   setting and the policy rules. Nothing on billing, no other group
// - the what-if identity: trusted only for a job in `staging-whatif` (main only,
//   no reviewer), the plan the partner reads before approving. It reads staging's
//   group and asks Azure's what-if; it changes nothing
//
// The subjects are the immutable form names.bicep's githubRepository() writes;
// infra.test.ts holds the two equal (names.bicep is read by every deployment,
// so it is left as it is).
import { resourceTags } from '../names.bicep'

targetScope = 'subscription'

@description('The environment the identities deploy. Staging alone today; production gets its own, with a second reviewer.')
@allowed([
  'staging'
])
param environment string

@description('The region the identities are made in, as every resource here (ADR-009).')
param location string

var short = 'stg'
var repository = 'repo:shahbaz242630@205810405/agent-x@1368211207'
var tags = resourceTags(environment)
var stagingGroupName = 'rg-agentx-${environment}'
var infraName = 'id-agentx-${short}-infra'
var whatIfName = 'id-agentx-${short}-whatif'

resource deployers 'Microsoft.Resources/resourceGroups@2025-04-01' = {
  name: 'rg-agentx-${environment}-deployers'
  location: location
  tags: tags
}

module identities 'identities.bicep' = {
  scope: deployers
  params: {
    location: location
    tags: tags
    infraName: infraName
    infraSubject: '${repository}:environment:${environment}-infra'
    whatIfName: whatIfName
    whatIfSubject: '${repository}:environment:${environment}-whatif'
  }
}

// The deployment itself and the foundation's three subscription-level writes: its budget, the activity log's
// setting and the policy rules (guardrails.bicep). The resource group's own write is Contributor's, on the group.
resource infraSubscriptionRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(subscription().id, 'agentx-${environment}-infra-subscription')
  properties: {
    roleName: 'Agent X infra deploy (${environment}, subscription)'
    description: 'CI\'s approved infrastructure deploy (AZ5): the foundation\'s deployment and its budget, activity log setting and policy rules. Nothing else on the subscription.'
    type: 'CustomRole'
    assignableScopes: [
      subscription().id
    ]
    permissions: [
      {
        actions: [
          'Microsoft.Resources/deployments/read'
          'Microsoft.Resources/deployments/write'
          'Microsoft.Resources/deployments/validate/action'
          'Microsoft.Resources/deployments/whatIf/action'
          'Microsoft.Resources/deployments/cancel/action'
          'Microsoft.Resources/deployments/operations/read'
          'Microsoft.Resources/deployments/operationstatuses/read'
          'Microsoft.Resources/subscriptions/resourceGroups/read'
          'Microsoft.Consumption/budgets/read'
          'Microsoft.Consumption/budgets/write'
          'Microsoft.Insights/diagnosticSettings/read'
          'Microsoft.Insights/diagnosticSettings/write'
          'Microsoft.Authorization/policyDefinitions/read'
          'Microsoft.Authorization/policyDefinitions/write'
        ]
        notActions: []
        dataActions: []
        notDataActions: []
      }
    ]
  }
}

// What-if reads all a deployment would touch: the group's resources by Reader there, the subscription's few here.
resource whatIfRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(subscription().id, 'agentx-${environment}-whatif')
  properties: {
    roleName: 'Agent X infra what-if (${environment})'
    description: 'The plan before an approved infrastructure deploy (AZ5): Azure\'s what-if, and reading what the foundation writes on the subscription. It changes nothing.'
    type: 'CustomRole'
    assignableScopes: [
      subscription().id
    ]
    permissions: [
      {
        actions: [
          'Microsoft.Resources/deployments/read'
          'Microsoft.Resources/deployments/whatIf/action'
          'Microsoft.Resources/deployments/validate/action'
          'Microsoft.Resources/deployments/operationstatuses/read'
          'Microsoft.Resources/subscriptions/resourceGroups/read'
          'Microsoft.Consumption/budgets/read'
          'Microsoft.Insights/diagnosticSettings/read'
          'Microsoft.Authorization/policyDefinitions/read'
          'Microsoft.Authorization/policyAssignments/read'
          'Microsoft.Authorization/roleDefinitions/read'
          'Microsoft.Authorization/roleAssignments/read'
        ]
        notActions: []
        dataActions: []
        notDataActions: []
      }
    ]
  }
}

resource infraOnSubscription 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, 'agentx-${environment}-infra', infraSubscriptionRole.id)
  properties: {
    description: 'The approved infrastructure deploy (deploy/azure/deployers/deployers.bicep)'
    roleDefinitionId: infraSubscriptionRole.id
    principalId: identities.outputs.infraPrincipalId
    principalType: 'ServicePrincipal'
  }
}

resource whatIfOnSubscription 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, 'agentx-${environment}-whatif', whatIfRole.id)
  properties: {
    description: 'The plan before an approved infrastructure deploy (deploy/azure/deployers/deployers.bicep)'
    roleDefinitionId: whatIfRole.id
    principalId: identities.outputs.whatIfPrincipalId
    principalType: 'ServicePrincipal'
  }
}

// Their rights on staging's own group, which the foundation made before this runs.
module onStaging 'staging-access.bicep' = {
  scope: resourceGroup(stagingGroupName)
  params: {
    environment: environment
    // Known before the deployment, so each grant's name is too (what-if reads it).
    infraId: resourceId(subscription().subscriptionId, deployers.name, 'Microsoft.ManagedIdentity/userAssignedIdentities', infraName)
    whatIfId: resourceId(subscription().subscriptionId, deployers.name, 'Microsoft.ManagedIdentity/userAssignedIdentities', whatIfName)
    infraPrincipalId: identities.outputs.infraPrincipalId
    whatIfPrincipalId: identities.outputs.whatIfPrincipalId
  }
}

@description('The infra identity\'s client ID: the `staging-infra` environment\'s AZURE_CLIENT_ID variable (not a secret).')
output infraClientId string = identities.outputs.infraClientId

@description('The what-if identity\'s client ID: the `staging-whatif` environment\'s AZURE_CLIENT_ID variable (not a secret).')
output whatIfClientId string = identities.outputs.whatIfClientId
