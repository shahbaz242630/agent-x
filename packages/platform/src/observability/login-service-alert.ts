// SA2: the login events copier's lines one alert counts, any one of them at
// once (deploy/azure/modules/environment.bicep, "Login service: a change made
// behind Agent X"): someone acting as another person in the login service,
// rights given or changed inside it, an access token issued for a login, and
// a full page of its events at one time that the copier had to move past.
// Our own routine tokens and grants (idp-event.ts isOurRoutineChange) are the
// info lines `idp.token_issued_by_us` and `idp.rights_changed_by_us`, left out.
// The error spike alert counts only many errors of one kind, and the daily
// email the warnings, a day late. The policy (deploy/azure/policy.ts) holds
// the rule's query to exactly this list, and the copier's tests hold its lines
// to it. Nothing here imports a package: the policy runs with Node alone.

/** The events, each as the copier logs it. */
export const LOGIN_SERVICE_ALERT_EVENTS = [
  'idp.impersonated',
  'idp.rights_changed',
  'idp.token_issued',
  'idp_events.tied_page',
] as const;
