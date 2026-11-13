// Azure's refusals (guardrails.bicep), each given on the resource group with the
// words a refused request gets back: what was refused and what to do instead.
// Enforced (`Default`): a rule only reported would refuse nothing.

@description('Each rule: its definition, the name it is given under and its words for a refusal.')
param rules array

resource assignments 'Microsoft.Authorization/policyAssignments@2025-01-01' = [
  for rule in rules: {
    name: rule.name
    properties: {
      displayName: rule.displayName
      policyDefinitionId: rule.definitionId
      enforcementMode: 'Default'
      nonComplianceMessages: [
        {
          message: rule.message
        }
      ]
    }
  }
]
