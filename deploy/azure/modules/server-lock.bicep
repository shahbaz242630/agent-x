// The live database server's delete lock (S184, S185), moved from postgres.bicep to the partner's `access`
// deployment (AZ5): CI's approved infrastructure deploy can't write a lock, so it can never lift one either. Same
// name, same scope, so Azure keeps the lock it has.
//
// Deleting a server deletes every restore point with it (S184: a restore's first steps nearly did): Azure itself
// refuses a delete while this lock stands, whoever asks and however. Changes still go through. A server of an older
// generation (AZ25) keeps its lock too, so letting it go after the partner's sign-off is a deliberate removal by an
// Owner first. Stage G's copies and the drill are restored by the CLI, not here, so they carry none and stay deletable.
// A new generation's server is locked once access runs after the foundation that made it (playbook L).
targetScope = 'resourceGroup'

@description('The live server, by the name the foundation gave it (names.bicep).')
param serverName string

resource server 'Microsoft.DBforPostgreSQL/flexibleServers@2025-08-01' existing = {
  name: serverName
}

resource keepServer 'Microsoft.Authorization/locks@2020-05-01' = {
  scope: server
  name: 'keep-live-database'
  properties: {
    level: 'CanNotDelete'
    notes: 'The live database and its restore points. Never delete before a replacement runs and is checked (Incident playbook L).'
  }
}
