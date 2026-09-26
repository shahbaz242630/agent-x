// Email for the admins' notices (Phase 1 B5-2): Azure Communication Services,
// the one service that sends them (the Notifier port, B5-1b), and the email
// service with the domain it sends from.
//
// - Azure offers all three only as global resources; what they keep at rest
//   (the sender's name, the messages while they are sent) stays in their data
//   location, the UAE, which can't be changed once they exist (Microsoft).
//   The policy holds it (rule `email`)
// - Azure's own domain (`<guid>.azurecomm.net`, sender DoNotReply) on
//   staging, so no DNS records at Hostinger; our own domain with SPF, DKIM and
//   DMARC before production (partner decision S54, SEC-HA-13). Azure limits
//   its domain to 5 emails a minute and 10 an hour
// - no open or click tracking: a tracked email rewrites links and carries a
//   pixel that tells Azure when a recipient reads it
// - the API signs each send with the service's access key (B5-3), so local
//   auth stays on: a managed identity's token would need the app to fetch one
//   over plain http inside the container
// - ACS is retiring: no new customers from 23 Oct 2026, email ends 30 Sep 2028
//   (Microsoft). The long-term supplier is chosen before production
//   (Carry-Forward); the Notifier port makes the change one adapter

param emailServiceName string
param communicationName string
param tags object

// ACS's name for the United Arab Emirates as a data location.
var dataLocation = 'UAE'

resource emailService 'Microsoft.Communication/emailServices@2026-03-18' = {
  name: emailServiceName
  location: 'global'
  tags: tags
  properties: {
    dataLocation: dataLocation
  }
}

// An Azure-managed domain must be named AzureManagedDomain (Microsoft).
resource domain 'Microsoft.Communication/emailServices/domains@2026-03-18' = {
  parent: emailService
  name: 'AzureManagedDomain'
  location: 'global'
  tags: tags
  properties: {
    domainManagement: 'AzureManaged'
    userEngagementTracking: 'Disabled'
  }
}

resource communication 'Microsoft.Communication/communicationServices@2026-03-18' = {
  name: communicationName
  location: 'global'
  tags: tags
  properties: {
    dataLocation: dataLocation
    disableLocalAuth: false
    linkedDomains: [domain.id]
  }
}
