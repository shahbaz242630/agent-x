// Staging's jobs (0e G2d; apps.bicep), deployed after the foundation and the
// secrets. What changes with every build, and the two values that name a person
// or a domain, come from the shell that deploys, never from this repository
// (Rule Book §7):
// - AGENTX_AZURE_APP_IMAGE_DIGEST and AGENTX_AZURE_RELEASE: the image CI
//   published and the commit it was built from, the pair
//   `deploy/image/verify.ts` checks a signature for before a deployment (G4)
// - AGENTX_AZURE_AUTH_HOST: the host name Zitadel is served on
// - AGENTX_AZURE_ZITADEL_ADMIN_EMAIL: the first admin's address
// - AGENTX_AZURE_API_OIDC_CLIENT_ID: the API's client ID in Zitadel (B2-6)
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
param zitadelImage = 'ghcr.io/zitadel/zitadel:v4.19.5@sha256:a586456a208e0db4c633db0ba43c427c24b37846138b8b13ff16ad8e003a18d3'

param authHost = readEnvironmentVariable('AGENTX_AZURE_AUTH_HOST')
param zitadelAdminEmail = readEnvironmentVariable('AGENTX_AZURE_ZITADEL_ADMIN_EMAIL')

// The login pages, the same version and the same reference the compose stack
// runs (tooling/checks/images.test.ts keeps them equal).
param zitadelLoginImage = 'ghcr.io/zitadel/zitadel-login:v4.19.5@sha256:2f8e57672fcd4f9a285d99355fae9f85fd7495768c090c07c3bbc2d84fc06617'

param appHost = readEnvironmentVariable('AGENTX_AZURE_APP_HOST')

// ADR-014 §4: staging talks to the fake partner, which keeps its records in
// the database (Phase 1 D2-1), until the partner's sandbox adapter (Phase 5).
param partnerMode = 'fake'

// The API as Zitadel's OIDC client (B2-6): the client ID Zitadel gave when the
// API was registered with it; its secret is in the vault.
param apiOidcClientId = readEnvironmentVariable('AGENTX_AZURE_API_OIDC_CLIENT_ID')

// ADR-002: "Staging scales to zero when not in use". Nothing is billed while
// nothing runs; the first request after a quiet spell waits for a cold start,
// which synthetic traffic can afford. Production sets 1. The deploy tool sets
// 0, or 1 for `apps --keep-running` (AGENTX_AZURE_APP_MIN_REPLICAS), which
// keeps one replica of each app running, billed, until the next `apps`.
param appMinReplicas = int(readEnvironmentVariable('AGENTX_AZURE_APP_MIN_REPLICAS'))

// The load test's run (D2c, PL-38): deploy.ts always sets both, the run only
// for `apps --load-run` with the load image's verified digest; the defaults
// serve the policy tests.
param loadRun = bool(readEnvironmentVariable('AGENTX_AZURE_LOAD_RUN', 'false'))
param loadImageRepository = 'ghcr.io/shahbaz242630/agent-x-load'
param loadImageDigest = readEnvironmentVariable('AGENTX_AZURE_LOAD_IMAGE_DIGEST', '')

// Stage G's throwaway copy (4D2e), by its host: deploy.ts sets it for
// `apps --load-run --load-database <name>` alone, after checking the name, and
// empty otherwise; apps.bicep reads it only in a load run.
param loadDatabaseHost = readEnvironmentVariable('AGENTX_AZURE_LOAD_DATABASE_HOST', '')

// The anchor key's public halves (4D2e E9), as staging's API logs them at start
// (`api.starting`, keys: audit-anchor), `<version>:<key>`: public, so kept here.
// Copied from staging's `api.starting` of d46cdaea (4 Nov 2026, S173).
// Only the public key's `x` value goes here, never the private `d`: this file is
// committed, and a private key here would let anyone sign anchors.
param anchorPublicKeys = '1:YGJbtqiqwcHQT32ByJhe-28JTKwrMacr8rHCj_S91No'

// The anchors' epoch, the API's and the operator's alike: raised by one only for a
// sanctioned restore of the whole database (playbook H).
param anchorEpoch = 1

// The hand deploys' records (T1b), as JSON: deploy.ts reads them from the
// migration job before every apps run and sets them, so the deployment, which
// replaces the job's tags, keeps them; the default serves the policy tests.
param records = json(readEnvironmentVariable('AGENTX_AZURE_RECORDS', '{}'))
