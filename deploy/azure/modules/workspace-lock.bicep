// The main workspace's delete lock (AZ5e review S192), in the partner's `access` deployment, as the server's is.
// The access alarm (deployers/watch.bicep) reads the subscription's activity log from this workspace: CI's infra
// identity is Contributor on the group and could delete it to blind every log alert before acting. Contributor can't
// write or lift a lock, so Azure refuses that delete, whoever asks. Changes, the cap among them, still go through: the
// workspace-free alarm in watch.bicep tells of those.
targetScope = 'resourceGroup'

@description('The main workspace, by the name the foundation gave it (names.bicep).')
param workspaceName string

resource workspace 'Microsoft.OperationalInsights/workspaces@2025-02-01' existing = {
  name: workspaceName
}

resource keepWorkspace 'Microsoft.Authorization/locks@2020-05-01' = {
  scope: workspace
  name: 'keep-log-workspace'
  properties: {
    level: 'CanNotDelete'
    notes: 'The logs every alert reads, the access alarm among them. Never delete: an Owner lifts this first, on purpose.'
  }
}
