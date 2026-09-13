/**
 * Modules product code may not import. .dependency-cruiser.js builds its
 * rules from these lists, and a gate proof checks that every entry has its own
 * broken fixture. Entries are module names, or patterns for a family of them.
 */

/** Cloud-vendor SDKs never appear in product code (ADR-010 §2). */
export const CLOUD_SDKS = [
  '@azure',
  '@azure-rest',
  '@aws-sdk',
  'aws-sdk',
  '@google-cloud',
  'googleapis',
  '@googleapis',
  'firebase-admin',
  'oci-[a-z-]+',
  'ibm-cloud-sdk-core',
  '@alicloud',
];

/**
 * SEC-WEB-05: Node's network modules, allowed only in the outbound client. The
 * names are as dependency-cruiser reports them: `node:https` is plain `https`.
 */
export const NETWORK_CORE_MODULES = [
  'http',
  'https',
  'http2',
  'net',
  'tls',
  'dgram',
  'dns',
  'dns/promises',
  // A child process could run a network tool.
  'child_process',
  // Node's old internal names for parts of http and tls.
  '_http_agent',
  '_http_client',
  '_http_common',
  '_http_incoming',
  '_http_outgoing',
  '_http_server',
  '_tls_common',
  '_tls_wrap',
];

/** SEC-WEB-05: common HTTP and WebSocket client libraries, allowed only in the outbound client. */
export const HTTP_CLIENTS = [
  'undici',
  'axios',
  'got',
  'node-fetch',
  'cross-fetch',
  'isomorphic-fetch',
  'make-fetch-happen',
  'ky',
  'ofetch',
  'superagent',
  'needle',
  'request',
  'phin',
  'wretch',
  '@hapi/wreck',
  'ws',
];
