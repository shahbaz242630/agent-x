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
 * SEC-DATA-03 (ADR-013): vendor telemetry SDKs never appear in product code,
 * not even in the observability folder. They send data out on their own
 * connections; the app's only telemetry path is its log on stdout. This list is
 * a second line: every production dependency must also be on the reviewed list
 * in tooling/allowed-dependencies.ts.
 */
export const TELEMETRY_SDKS = [
  // Error tracking
  '@sentry(?:-internal)?',
  'raven',
  '@bugsnag',
  'rollbar',
  '@rollbar',
  '@honeybadger-io',
  'raygun',
  'raygun4js',
  '@airbrake',
  '@appsignal',
  // OpenTelemetry, tracing and application performance monitoring
  '@opentelemetry',
  '@vercel/otel',
  'dd-trace',
  '@datadog',
  'newrelic',
  '@newrelic',
  'elastic-apm-node',
  '@elastic/apm-rum',
  'applicationinsights',
  '@microsoft/applicationinsights-[a-z-]+',
  '@splunk/otel',
  '@honeycombio',
  '@instana',
  '@dynatrace',
  'lightstep-tracer',
  'jaeger-client',
  'hot-shots',
  '@grafana/faro-[a-z-]+',
  // Session replay and log shipping
  '@highlight-run',
  'highlight\\.run',
  // Two entries, not one with an optional part: dependency-cruiser refuses nested repeats as unsafe.
  'logrocket',
  'logrocket-[a-z-]+',
  '@fullstory',
  '@logtail',
  '@axiomhq',
  // Product analytics
  'posthog-node',
  'posthog-js',
  '@posthog',
  '@segment',
  'analytics-node',
  'mixpanel',
  'mixpanel-browser',
  '@amplitude',
  'amplitude-js',
  '@snowplow',
  '@rudderstack',
  '@vercel/analytics',
];

/**
 * ADR-013: pino, through the redacting logger, is the only way to write logs.
 * Other logging libraries skip the redaction, and pino's add-ons (transports
 * such as pino-loki) ship logs over the network. None may be imported, not even
 * in the observability folder.
 */
export const OTHER_LOGGERS = [
  'pino-[a-z0-9-]+',
  'winston',
  'bunyan',
  'debug',
  'log4js',
  'consola',
  'loglevel',
  'signale',
  'roarr',
  'npmlog',
  'tslog',
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
