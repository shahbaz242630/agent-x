// The two identities' rights on staging's own resource group (AZ5).
//
// - infra: Contributor, which is what the partner's deploy writes in the group;
//   a role of its own for what Contributor leaves out and the foundation writes
//   (custom roles and the policy rules' assignments); and grants, limited by an
//   Azure condition to the roles our Bicep gives (GRANTED_ROLES) and never to
//   itself: a grant of any other role, or to the infra identity, is refused by
//   Azure, so an approved deploy can't make itself an owner
// - what-if: Reader, so Azure's what-if can read what each deployment touches
targetScope = 'resourceGroup'

param environment string
@description('The infra identity\'s resource ID, which names its grants.')
param infraId string
@description('The what-if identity\'s resource ID, which names its grant.')
param whatIfId string
param infraPrincipalId string
param whatIfPrincipalId string

var contributor = 'b24988ac-6180-42a0-ab88-20f7382dd24c'
var reader = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'
var accessAdministrator = 'f58310d9-a9f6-439a-9e8d-f62e7b41a168'

// Key Vault Secrets User, as modules/secret-access.bicep gives it.
var vaultReaderRole = '4633458b-17de-408a-b874-0445c86b69e6'

// The custom roles our Bicep gives, by the word each is named from (guid(resourceGroup().id, word)): CI's and the
// job watch's (names.bicep), the evidence store's four and the activity downloads' (their modules).
// infra.test.ts holds this list equal to every role the deployments give.
var customRoleWords = [
  'release'
  'job-watch'
  'evidence-writer'
  'audit-anchors'
  'audit-anchors-reader'
  'evidence-plan-reader'
  'activity-downloads'
]
var grantedRoles = join(concat([vaultReaderRole], map(customRoleWords, word => guid(resourceGroup().id, word))), ', ')

// Azure's condition on a role assignment (version 2.0): a write only of those roles and to someone else, a removal
// only of those roles. Its syntax is Microsoft's own example, "Constrain roles and principals".
var grantsCondition = '((!(ActionMatches{\'Microsoft.Authorization/roleAssignments/write\'})) OR (@Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {${grantedRoles}} AND @Request[Microsoft.Authorization/roleAssignments:PrincipalId] ForAnyOfAnyValues:GuidNotEquals {${infraPrincipalId}})) AND ((!(ActionMatches{\'Microsoft.Authorization/roleAssignments/delete\'})) OR (@Resource[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {${grantedRoles}}))'

// What Contributor leaves out and the foundation writes: our custom roles and the guardrails' assignments.
resource infraGrantsRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(resourceGroup().id, 'agentx-${environment}-infra-group')
  properties: {
    roleName: 'Agent X infra deploy (${environment}, group)'
    description: 'CI\'s approved infrastructure deploy (AZ5): the custom roles and the policy rules\' assignments the foundation writes in this group.'
    type: 'CustomRole'
    assignableScopes: [
      resourceGroup().id
    ]
    permissions: [
      {
        actions: [
          'Microsoft.Authorization/roleDefinitions/read'
          'Microsoft.Authorization/roleDefinitions/write'
          'Microsoft.Authorization/policyAssignments/read'
          'Microsoft.Authorization/policyAssignments/write'
        ]
        notActions: []
        dataActions: []
        notDataActions: []
      }
    ]
  }
}

var infraGrantsRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', infraGrantsRole.name)

resource infraContributes 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, infraId, contributor)
  properties: {
    description: 'The approved infrastructure deploy writes the group (deploy/azure/deployers)'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', contributor)
    principalId: infraPrincipalId
    principalType: 'ServicePrincipal'
  }
}

resource infraWritesRoles 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, infraId, infraGrantsRoleId)
  properties: {
    description: 'The approved infrastructure deploy writes our custom roles and policy assignments (deploy/azure/deployers)'
    roleDefinitionId: infraGrantsRoleId
    principalId: infraPrincipalId
    principalType: 'ServicePrincipal'
  }
}

resource infraGrants 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, infraId, accessAdministrator)
  properties: {
    description: 'The approved infrastructure deploy gives our own roles, never another, never to itself (deploy/azure/deployers)'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', accessAdministrator)
    principalId: infraPrincipalId
    principalType: 'ServicePrincipal'
    conditionVersion: '2.0'
    condition: grantsCondition
  }
}

resource whatIfReads 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, whatIfId, reader)
  properties: {
    description: 'The plan before an approved infrastructure deploy reads the group (deploy/azure/deployers)'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', reader)
    principalId: whatIfPrincipalId
    principalType: 'ServicePrincipal'
  }
}
