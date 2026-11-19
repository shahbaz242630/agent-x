// AG10: the header Zitadel's processes ask for their machine IDs with, named alone, with no package: the API's config
// (settings.ts machineIdsConfig) and the deploy tool that writes Zitadel's config file (deploy/azure/deploy.ts, run in
// CI with no packages installed) both read it here, so what the deploy writes is exactly what the API checks.

/**
 * Zitadel's webhook can send static headers but signs nothing (`Machine.Identification.Webhook` in the pinned image's
 * defaults: Url, JPath, Headers), so a shared value is the most it can prove.
 */
export const MACHINE_ID_HEADER = 'X-Agentx-Machine-Key';
