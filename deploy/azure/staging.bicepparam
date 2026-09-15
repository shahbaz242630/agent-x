// Staging (ADR-002): synthetic data only (ADR-009), in the partner's own
// subscription until a company account exists. The alert address and the
// server admin's password come from the shell that deploys, never from this
// repository (Rule Book §7): AGENTX_AZURE_ALERT_EMAIL and
// AGENTX_AZURE_POSTGRES_ADMIN_PASSWORD.
using 'main.bicep'

param environment = 'staging'
param location = 'uaenorth'
param alertEmail = readEnvironmentVariable('AGENTX_AZURE_ALERT_EMAIL')

// Staging logs a few MB a day; 1 GB is far above that and costs at most about
// $3.29 on the day it is hit (ADR-013).
param logDailyCapGb = 1

// About $45-50 a month while switched on (ADR-002 Amendment G1), so the 80%
// email arrives before the month's cost passes it.
param budgetAmount = 60
param budgetStartDate = '2026-09-01'

param postgresAdminPassword = readEnvironmentVariable('AGENTX_AZURE_POSTGRES_ADMIN_PASSWORD')
param postgresBackupRetentionDays = 7
param postgresGeoRedundantBackup = false

// One zone is enough for synthetic data; it can't be changed later.
param appsZoneRedundant = false

// Staging runs synthetic traffic only, so any error event is worth a look.
param appErrorAlertThreshold = 0
