// Staging's roles, guardrails, activity log and budget (AZ5; access.bicep):
// the partner's own deployment, never CI's. The alert address comes from the
// shell that deploys, never from this repository (Rule Book §7):
// AGENTX_AZURE_ALERT_EMAIL, the foundation's.
using 'access.bicep'

param environment = 'staging'
param alertEmail = readEnvironmentVariable('AGENTX_AZURE_ALERT_EMAIL')

// About $45-50 a month while switched on (ADR-002 Amendment G1), so the 80%
// email arrives before the month's cost passes it.
param budgetAmount = 60
param budgetStartDate = '2026-09-01'
