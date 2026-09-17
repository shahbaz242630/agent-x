// Staging's jobs (0e G2d; apps.bicep), deployed after the foundation and the
// secrets. What changes with every build, and the two values that name a person
// or a domain, come from the shell that deploys, never from this repository
// (Rule Book §7):
// - AGENTX_AZURE_APP_IMAGE_DIGEST and AGENTX_AZURE_RELEASE: the image CI
//   published and the commit it was built from, the pair
//   `deploy/image/verify.ts` checks a signature for before a deployment (G4)
// - AGENTX_AZURE_AUTH_HOST: the host name Zitadel is served on
// - AGENTX_AZURE_ZITADEL_ADMIN_EMAIL: the first admin's address
// and, from the tool rather than the operator, AGENTX_AZURE_APP_MIN_REPLICAS
// (below).
using 'apps.bicep'

param environment = 'staging'
param location = 'uaenorth'

// Where CI publishes our image (Product-Documentation/Container-Image.md). The
// digest is a parameter of its own, so a tag can never take its place.
param appImageRepository = 'ghcr.io/shahbaz242630/agent-x'
param appImageDigest = readEnvironmentVariable('AGENTX_AZURE_APP_IMAGE_DIGEST')
param release = readEnvironmentVariable('AGENTX_AZURE_RELEASE')

// The same image the compose stack runs, so one weekly bump moves both
// (tooling/checks/images.test.ts keeps them equal). ADR-003 moves the major
// version by hand.
param zitadelImage = 'ghcr.io/zitadel/zitadel:v4.17.3@sha256:2ec2a42551862ca59dc752c321c7041358dea8b33b63ea5e021ec499ad5e2d9f'

param authHost = readEnvironmentVariable('AGENTX_AZURE_AUTH_HOST')
param zitadelAdminEmail = readEnvironmentVariable('AGENTX_AZURE_ZITADEL_ADMIN_EMAIL')

// The login pages, the same version and the same reference the compose stack
// runs (tooling/checks/images.test.ts keeps them equal).
param zitadelLoginImage = 'ghcr.io/zitadel/zitadel-login:v4.17.3@sha256:07ae03bd1aa49dbc015617a0c1bc9e6abd956616856f0bb374269fae7da79059'

param appHost = readEnvironmentVariable('AGENTX_AZURE_APP_HOST')

// ADR-002: "Staging scales to zero when not in use". Nothing is billed while
// nothing runs; the first request after a quiet spell waits for a cold start,
// which synthetic traffic can afford. Production sets 1. The deploy tool sets
// 0, or 1 for `apps --keep-running` (AGENTX_AZURE_APP_MIN_REPLICAS), which
// keeps one replica of each app running, billed, until the next `apps`.
param appMinReplicas = int(readEnvironmentVariable('AGENTX_AZURE_APP_MIN_REPLICAS'))
