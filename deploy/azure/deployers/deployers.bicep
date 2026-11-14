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
//   environment (main only, the partner the required reviewer). On staging's
//   group, Contributor and grants limited to the roles our Bicep gives, never to
//   itself (staging-access.bicep); on the subscription, the deployment record
//   alone, as the foundation is a subscription deployment (it makes the group).
//   No role definition, policy, activity log setting or budget: those are the
//   partner's `access` deployment (review S190). Nothing on billing, no other group
// - the what-if identity: trusted only for a job in `staging-whatif` (main only,
//   no reviewer), the plan the partner reads before approving. It reads staging's
//   group and asks Azure's what-if; it changes nothing
// - the alarm on an app changing role grants, trusts, policy rules or locks
//   across the subscription (watch.bicep, AZ5e), where the infra identity can't reach it
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

@description('The alert address the access alarm emails, as the foundation has it.')
param alertEmail string

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

module watch 'watch.bicep' = {
  scope: deployers
  params: {
    tags: tags
    short: short
    location: location
    // The foundation's workspace, by name (names.bicep's): it exists before this runs.
    workspaceId: resourceId(subscription().subscriptionId, stagingGroupName, 'Microsoft.OperationalInsights/workspaces', 'log-agentx-${short}')
    alertEmail: alertEmail
    infraPrincipalId: identities.outputs.infraPrincipalId
  }
}

// The foundation is a subscription deployment (it makes the group): Azure asks for the deployment's own rights there.
// They write nothing but the deployment's record; what it creates needs the identity's rights on the group.
resource infraSubscriptionRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(subscription().id, 'agentx-${environment}-infra-subscription')
  properties: {
    roleName: 'Agent X infra deploy (${environment}, subscription)'
    description: 'CI\'s approved infrastructure deploy (AZ5): the foundation\'s deployment record. Nothing else on the subscription.'
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
          // A what-if's answer is fetched from the subscription's async results, not the deployment's (AZ5d)
          'Microsoft.Resources/subscriptions/operationresults/read'
        ]
        notActions: []
        dataActions: []
        notDataActions: []
      }
    ]
  }
}

// What-if at the subscription, for the foundation's plan: what it reads is in the group, by Reader there.
resource whatIfRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(subscription().id, 'agentx-${environment}-whatif')
  properties: {
    roleName: 'Agent X infra what-if (${environment})'
    description: 'The plan before an approved infrastructure deploy (AZ5): Azure\'s what-if. It changes nothing.'
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
          // A what-if's answer is fetched from the subscription's async results, not the deployment's (AZ5d)
          'Microsoft.Resources/subscriptions/operationresults/read'
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
