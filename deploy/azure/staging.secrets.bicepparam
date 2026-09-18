// Staging's secrets (0e G2c; secrets.bicep). Every value comes from the shell
// that deploys, never from this repository (Rule Book §7): the machine logins
// made for the run, the people's from the password manager (G3).
// - every variable is set on every run: an empty one leaves that secret as the
//   vault has it, and a missing one stops the run, so a misspelt name can't
//   pass for a rotation
// - Windows PowerShell 5.1 deletes a variable set to empty, so a run goes
//   through G3's tool or Git Bash, which keep it
// - Zitadel's master key takes a fresh 32 characters every run, never the real
//   one again: only the first run's is kept. So do the app's keys, as one JSON
//   value: a key the vault already holds keeps its value
using 'secrets.bicep'

param environment = 'staging'
param postgresAdminPassword = readEnvironmentVariable('AGENTX_AZURE_POSTGRES_ADMIN_PASSWORD')
param dbOwnerPassword = readEnvironmentVariable('AGENTX_AZURE_DB_OWNER_PASSWORD')
param dbAppPassword = readEnvironmentVariable('AGENTX_AZURE_DB_APP_PASSWORD')
param dbBackupPassword = readEnvironmentVariable('AGENTX_AZURE_DB_BACKUP_PASSWORD')
param dbZitadelPassword = readEnvironmentVariable('AGENTX_AZURE_DB_ZITADEL_PASSWORD')
param zitadelMasterKey = readEnvironmentVariable('AGENTX_AZURE_ZITADEL_MASTERKEY')
param zitadelAdminPassword = readEnvironmentVariable('AGENTX_AZURE_ZITADEL_ADMIN_PASSWORD')
param loginClientPrivateKey = readEnvironmentVariable('AGENTX_AZURE_LOGIN_CLIENT_PRIVATE_KEY')
param loginClientPublicKey = readEnvironmentVariable('AGENTX_AZURE_LOGIN_CLIENT_PUBLIC_KEY')
param appKeyValues = readEnvironmentVariable('AGENTX_AZURE_APP_KEYS')
