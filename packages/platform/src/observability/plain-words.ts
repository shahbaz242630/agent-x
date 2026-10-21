// Decision 29 (partner, S127): every warning and error says in plain English
// what happened, what broke and what happens next. The logger adds these words
// to each warn and error line as `says`, and takes only the events listed here
// at those levels, so a new failure can't ship without its words, and an
// alert can show the words rather than the event code.

/** Each a short whole sentence or two, for a reader who doesn't know the code. */
export interface PlainWords {
  readonly happened: string;
  readonly broke: string;
  readonly next: string;
}

export const PLAIN_WORDS = {
  'activity.places_stale': {
    happened: 'The API started with a place file more than 45 days old.',
    broke:
      'Activity rows still get a country and city, but places from newer internet addresses may be missing or wrong.',
    next: 'Check the monthly place file refresh ran, open its branch as a pull request and merge it.',
  },
  'access_log.write_failed': {
    happened: "A request's activity-log row could not be saved.",
    broke: "That one request is missing from its organisation's activity log; the request itself went through.",
    next: 'Nothing to do if it is rare. If it repeats, the database is failing: check its health.',
  },
  'access_log_seal_check.failed': {
    happened: "An organisation's activity log seals could not be checked this run.",
    broke:
      'A change to its sealed days would not be caught until the next run, 30 minutes later; nothing else is affected.',
    next: 'Nothing to do if it is rare. If it repeats, check the database and the audit chain.',
  },
  'access_log_seal_check.run_failed': {
    happened: 'A run of the activity log seal check stopped early on an error.',
    broke: 'Sealed days are not checked until the next run, 30 minutes later.',
    next: 'Nothing to do if it is rare. If it repeats, a developer should find the cause in the log.',
  },
  'access_log_seal.failed': {
    happened: "An organisation's activity log day could not be sealed this run.",
    broke: 'That day stays unsealed for now, so a change to it would not yet be caught; nothing else is affected.',
    next: 'Nothing to do if it is rare: the next run, 15 minutes later, tries again. If it repeats, check the audit chain and the database.',
  },
  'access_log_seal.moved': {
    happened: "An organisation's activity log day changed while it was being sealed.",
    broke:
      'That day and every later one stay unsealed. A closed day never changes: a server clock is far off, or this is tampering.',
    next: "Check the servers' clocks and the database for changes made outside the app.",
  },
  'access_log_seal.run_failed': {
    happened: 'A run of the daily activity log seal stopped early on an error.',
    broke: 'Days waiting to be sealed stay unsealed until the next run, 15 minutes later.',
    next: 'Nothing to do if it is rare. If it repeats, a developer should find the cause in the log.',
  },
  'access_log.export_build_failed': {
    happened: "One month of an admin's background activity log download could not be made this time.",
    broke: 'That download is not ready yet; nothing else is affected.',
    next: 'Nothing to do: it is tried again within minutes, up to three times. If it keeps failing, check the download store.',
  },
  'access_log.export_failed': {
    happened: "An admin's background activity log download was given up after a month failed three times.",
    broke: 'That download will not be made; the admin was told by email to ask again.',
    next: 'Check the download store and the database are healthy, then let the admin ask again.',
  },
  'access_log.export_overdue': {
    happened: "An admin's background activity log download was still not made six days after it was asked.",
    broke: 'That download was given up so no file outlives its time; the admin was told by email to ask again.',
    next: 'Check the API ran its downloads (it may have been stopped or asleep), then let the admin ask again.',
  },
  'access_log.export_read_failed': {
    happened: "A part of an admin's background activity log download could not be read from the download store.",
    broke: 'That part was not sent; the admin was asked to try again. The file itself is unchanged.',
    next: 'Nothing to do if it is rare. If it repeats, check the download store is up and the API may read it.',
  },
  'access_log.export_run_failed': {
    happened: 'A run of the background activity log downloads stopped early on an error.',
    broke: 'Downloads waiting to be made are held up until the next run, a minute later.',
    next: 'Nothing to do if it is rare. If it repeats, a developer should find the cause in the log.',
  },
  'agent_key.refused': {
    happened:
      "An agent's key was turned away because the server no longer holds the security key version it was made with.",
    broke: 'That agent cannot act until this is fixed; nothing it asked for was done.',
    next: "Put the retired key version back in the app's settings, or give the agent a new key.",
  },
  'api.crashed': {
    happened: 'The API hit an error nothing caught and shut itself down.',
    broke: 'Requests in progress were cut off, and the API is down until it starts again.',
    next: 'Check the hosting platform has started it again. A developer should find the cause in the log.',
  },
  'api.database_unavailable': {
    happened: 'The API could not reach the database while starting.',
    broke: 'The API did not start, so no one can use the service through it.',
    next: 'Check the database is up and reachable, then start the API again.',
  },
  'api.listen_failed': {
    happened: 'The API could not open its network port while starting.',
    broke: 'The API did not start, so no one can use the service through it.',
    next: 'Check the port is free and the hosting settings are right, then start it again.',
  },
  'api.start_not_recorded': {
    happened: "The API could not record its own start in the platform's signed history.",
    broke: 'The API refused to start, so no one can use the service through it.',
    next: 'Check the database and the signing keys. If an integrity alarm came with it, treat it as possible tampering.',
  },
  'api.start_refused': {
    happened: 'The API refused to start because a setting, a key or the database login is wrong.',
    broke: 'The API did not start, so no one can use the service through it.',
    next: 'Fix the setting the log names, then start it again.',
  },
  'api.stop_failed': {
    happened: 'Something failed while the API was shutting down.',
    broke: 'The API stopped anyway; the last minute of security counts may not have been saved.',
    next: 'Nothing to do if it is rare. If it repeats, a developer should look at the cause.',
  },
  'api.stop_timed_out': {
    happened: 'The API took too long to shut down and was stopped by force.',
    broke: 'Requests still in progress were cut off, and recent security counts may not have been saved.',
    next: 'Nothing to do if it is rare. If it repeats, check whether the database is slow.',
  },
  'audit.anchor_check_crashed': {
    happened: 'The regular tamper check of the audit history hit an unexpected error.',
    broke: 'Some audit histories were not checked this time.',
    next: 'It runs again at the next check, a few minutes later. If it repeats, a developer should look at it.',
  },
  'audit.anchor_check_failed': {
    happened: 'The regular tamper check of the audit history could not finish, usually as the database was slow.',
    broke: 'One audit history went unchecked this time, or all of them if the list could not be read.',
    next: 'It is tried again at the next check. Three misses in a row raise the integrity alarm.',
  },
  'audit.backlog': {
    happened: 'A record had too much unchecked recent history to be verified while showing a list.',
    broke: 'That record was left off the list; the rest of the list was shown.',
    next: 'Nothing to do if it is rare. If it repeats for the same record, look into why its history is piling up.',
  },
  'audit.integrity_failed': {
    happened:
      'A tamper check found records, the audit trail or the database set-up changed, or could not check them for too long.',
    broke: 'Whatever met it was refused or stopped, and an organisation found tampered with is put on hold.',
    next: 'Treat it as a possible break-in and follow the incident runbook straight away.',
  },
  'audit.integrity_hold_set': {
    happened: 'An organisation was put on its security hold because something of its was found tampered with.',
    broke: 'Its payments are not passed to the payment partner until an admin of the organisation clears the hold.',
    next: 'Investigate the tamper alarm before it and record the findings; then an admin can clear the hold.',
  },
  'audit_log.kept_names_unreadable': {
    happened: 'Some saved names or email addresses of people in an audit or activity log could not be opened.',
    broke: 'Those people show without that saved detail on the page or download, unless the login service gave it.',
    next: 'If it repeats, check the database: a saved copy that will not open may have been altered or copied.',
  },
  'audit_log.names_unavailable': {
    happened:
      "The login service did not answer when an audit or activity log page or download asked for people's names.",
    broke: "People are named from Agent X's saved copy instead, or shown without a name where there is none.",
    next: 'Check the login service is up. The next page or download asks it again.',
  },
  'auth.login_service_sign_out_failed': {
    happened: 'A person signed out, but their session at the login service could not be ended.',
    broke: 'Their Agent X session ended anyway, but they may still be signed in at the login service.',
    next: 'Check the login service is up. If it keeps failing, see the runbook.',
  },
  'auth.sign_in_failed': {
    happened: 'A sign-in attempt was refused.',
    broke: 'That person was not signed in; the attempt was noted as a security event.',
    next: 'They can try again. Many in a row may mean someone is trying to get into an account.',
  },
  'auth.sign_in_unavailable': {
    happened: 'A sign-in could not go ahead because the login service could not be reached.',
    broke: 'The person was not signed in and was asked to try again shortly.',
    next: 'It usually clears once the login service wakes up. If it keeps happening, check the login service is up.',
  },
  'auth.step_up_failed': {
    happened: "A person's check of who they are, before a sensitive change, failed.",
    broke: 'The change was refused; they stay signed in, and it was noted as a security event.',
    next: 'They can try again. Many in a row may mean someone is misusing an account.',
  },
  'consent_lapse.failed': {
    happened: 'A bank account whose consent has run out could not have that recorded.',
    broke: "The lapse is not yet in the organisation's record.",
    next: 'It is tried again at the next run, about 5 minutes later. If it keeps failing, check the database and the integrity alarms.',
  },
  'consent_lapse.unreadable': {
    happened: "The list of an organisation's bank consents that have run out could not be read.",
    broke: 'No lapses were recorded for that organisation this run.',
    next: 'It is tried again at the next run, about 5 minutes later. If it keeps failing, check the database.',
  },
  'db.connection_lost': {
    happened: 'A connection to the database dropped.',
    broke: 'Any request using it at that moment failed; the app replaces the connection by itself.',
    next: "Nothing to do if it is rare, such as during a database restart. If it repeats, check the database's health.",
  },
  'db.migration.connection_lost': {
    happened: 'The database update job lost its connection to the database.',
    broke: 'The update in progress did not finish; any part not saved was undone.',
    next: 'Check the database is up, then run the update job again; it carries on from where it stopped.',
  },
  'db.migration.lock_wait_ran_out': {
    happened: 'A database update waited too long for a table that was in use.',
    broke: 'Nothing changed yet: that update was undone and is tried again after a short pause, up to 5 tries.',
    next: 'Nothing to do. If all 5 tries fail, the job stops: run it again at a quieter time.',
  },
  'db.migration.rollback_failed': {
    happened: 'A database update failed, and undoing it failed too.',
    broke: 'The connection is likely lost; closing it undoes the update anyway, so nothing half-done is kept.',
    next: "Look at the update's own error, fix the cause and run the update job again.",
  },
  'db.schema_unreadable': {
    happened: 'The database would not let Agent X read its own security set-up for the routine check.',
    broke:
      'The check could not vouch for the database: at start-up the app refuses to start; while running it carries on.',
    next: 'Check the database is up and its permissions are unchanged; if not, treat it as possible tampering.',
  },
  'db.tenant.leftover_discarded': {
    happened: 'A database connection still carried a setting left by an earlier request, so it was thrown away.',
    broke: 'Nothing leaked: another connection was used instead. It points to a bug or an attack.',
    next: 'Tell the developer so it can be investigated; it should never happen.',
  },
  'db.transaction_retried': {
    happened: 'Two database changes collided, so one was undone and is being tried again.',
    broke: 'Nothing is lost: it gets up to 3 tries in all, and fails only if the last one collides too.',
    next: 'Nothing to do if it is rare. A steady rise means busy records clash often: tell the developer.',
  },
  'db_setup.connection_lost': {
    happened: 'The database set-up job lost its connection to the database server.',
    broke: 'The set-up did not finish.',
    next: 'Check the database server is up, then run the set-up job again; it only creates what is missing.',
  },
  'db_setup.failed': {
    happened: 'The database set-up job failed.',
    broke:
      'The database server may not have all the logins and databases the platform needs, so the platform may not work on it.',
    next: 'Fix the problems the log lists, repairing the server by hand if it is half set up, then run the job again. It is safe to repeat.',
  },
  'db_setup.owner_rights_kept': {
    happened: 'The database set-up job could not give back extra rights it borrowed for one step.',
    broke: 'The set-up admin login still holds those rights for now; the step itself had already failed.',
    next: 'Run the set-up job again: its check reports the leftover rights and its run takes them back.',
  },
  'db_setup.rollback_failed': {
    happened: 'A database set-up step failed, and undoing it failed too.',
    broke: 'The connection is likely lost; closing it undoes the step anyway, so nothing half-done is kept.',
    next: "Look at the step's own error, fix the cause and run the set-up job again.",
  },
  'db_setup.start_refused': {
    happened: 'The database set-up job refused to start.',
    broke: "Nothing was done to the database server: the job's settings are wrong or missing.",
    next: 'Fix the settings the log lists, then run the job again.',
  },
  'factor_reset.confirmation_unreadable': {
    happened:
      "A contact's link to confirm a sign-in factor reset could not be checked: its saved secret would not open.",
    broke: 'The confirmation was refused and the reset was not moved on. The saved secret may have been altered.',
    next: 'Treat it as possible tampering with the database and follow the incident runbook.',
  },
  'factor_resets.removal_failed': {
    happened: "A due reset of a person's lost sign-in factor could not be carried out.",
    broke: 'Nothing was recorded for it and the reset stays due.',
    next: 'It is tried again at the next run, every 5 minutes. If it keeps failing, check the login service.',
  },
  'factor_resets.removed_after_cancel': {
    happened: "A person's sign-in factors were removed just as their reset was cancelled.",
    broke:
      "The reset shows as cancelled, but the factors are gone, and the person's admin or approver powers wait 7 days.",
    next: 'Ask the person to set up their sign-in factors again.',
  },
  'factor_resets.run_failed': {
    happened: 'The run that carries out due sign-in factor resets could not list the organisations.',
    broke: 'No resets were carried out this time; they stay due.',
    next: 'It is tried again at the next run, every 5 minutes. If it repeats, check the database.',
  },
  'factor_resets.unreadable': {
    happened: "An organisation's sign-in factor resets could not be read or trusted.",
    broke: 'None of its due resets were carried out this run; resets that cannot be trusted also put it on hold.',
    next: 'It is tried again at the next run, every 5 minutes. If it repeats, check the database and any tamper alarm.',
  },
  'funding_sources.currency_mismatch': {
    happened: "The bank link gave an account's limits in a different currency from the account.",
    broke: 'Nothing of it was kept: a new link was rejected, or an account already linked was paused.',
    next: 'Ask the bank to correct it, then link again, or an admin reactivates the paused account.',
  },
  'funding_sources.partner_answer_mismatch': {
    happened: 'The bank link answered about a different account or organisation than the one asked about.',
    broke: 'The answer was not believed, and the person was told the bank link is unavailable.',
    next: 'Raise it with the payment partner; if it repeats, see the runbook.',
  },
  'funding_sources.partner_page_refused': {
    happened: 'The bank link gave a web page that is not its own secure page.',
    broke: 'No account link was started, and the admin was told the bank link is unavailable.',
    next: 'Check the payment partner settings, and raise it with the partner if it repeats.',
  },
  'health.check_failed': {
    happened: "One of the API's health checks failed.",
    broke: 'The API told the uptime monitors it is unavailable.',
    next: 'Check which part the log names and whether it recovers by itself.',
  },
  'hold_history.failed': {
    happened: 'The full history check for an organisation on an integrity hold failed.',
    broke: 'The hold cannot be cleared until this check finishes.',
    next: 'It starts again from the beginning at the next run, about 30 seconds later. If it keeps failing, check the database.',
  },
  'hold_history.run_failed': {
    happened: 'The list of organisations could not be read, so the history check for held organisations was skipped.',
    broke: "No held organisation's history was checked this run.",
    next: 'It is tried again at the next run, about 30 seconds later. If it keeps failing, check the database.',
  },
  'hold_history.tampered': {
    happened: 'The full history check for an organisation on an integrity hold found records that were tampered with.',
    broke: 'The hold stays in place, and the integrity alarm was raised.',
    next: 'Find out what changed the records and put them right; the check then starts again.',
  },
  'holdings_check.failed': {
    happened: "The regular check of an organisation's spend requests against their budget holds failed.",
    broke: "Part of that organisation's requests went unchecked this run.",
    next: 'It carries on from where it stopped at the next run, about 15 minutes later. If it keeps failing, check the database.',
  },
  'holdings_check.run_failed': {
    happened: 'The list of organisations could not be read, so the budget-hold check was skipped.',
    broke: "No organisation's spend requests were checked this run.",
    next: 'It is tried again at the next run, about 15 minutes later. If it keeps failing, check the database.',
  },
  'http.framework_log': {
    happened: 'The web server reported a problem of its own while handling a request.',
    broke: 'That request may not have been answered properly.',
    next: 'Nothing to do if it is rare. If it repeats, a developer should look at the detail in the log.',
  },
  'http.request_completed': {
    happened: 'A request was handled, but its answer failed on its way back to the caller.',
    broke: 'The caller may not have received the answer, though the work was done.',
    next: 'Nothing to do if it is rare: a change sent again with its repeat key is not done twice. If it repeats, check the network.',
  },
  'http.request_failed': {
    happened: 'An unexpected error stopped a request from being handled.',
    broke: 'The caller got a general error, and that request was not completed.',
    next: 'The caller can try again. If it repeats, a developer should look at the cause.',
  },
  'http.request_rate_limited': {
    happened: 'A caller sending too many requests was refused, and that refusal failed on its way back.',
    broke: 'The caller may not have been told to slow down; nothing else was affected.',
    next: 'Nothing to do if it is rare. If it repeats, check the network.',
  },
  'idempotency.busy': {
    happened: 'A request waited too long for an earlier copy of itself that was still being handled.',
    broke: 'This copy was turned away as busy and nothing was saved from it; the earlier one carries on.',
    next: 'Nothing to do: the sender can send it again. If it happens often, the database may be slow.',
  },
  'idempotency.conflict': {
    happened: 'A request reused a retry key that was already used for a different request.',
    broke: 'It was refused and nothing was saved from it; the first request stands as it was.',
    next: 'Nothing to do on our side: the sender should use a new key for a new request.',
  },
  'idempotency.key_not_held': {
    happened:
      'A repeated request could not be checked: the security key version its first copy was saved with is no longer held.',
    broke: 'The request was refused and nothing was saved from it.',
    next: "Put the retired key version back in the app's settings until its saved requests are 30 days old.",
  },
  'idempotency.not_applied': {
    happened: "A request's saved result had already been filled in by something other than the app.",
    broke: 'The request was refused and all it did was undone. Something outside the app may be changing the database.',
    next: 'Treat it as possible tampering and follow the incident runbook.',
  },
  'idempotency.rollback_failed': {
    happened: 'A request failed, and undoing its partial work failed too.',
    broke: 'The request did not go through and none of it was kept; the database connection may have dropped.',
    next: "Nothing to do if it is rare. If it repeats, check the database's health.",
  },
  'idempotency.sweep_crashed': {
    happened: 'The hourly clean-up of old repeat-request guards hit an unexpected error.',
    broke: 'Guards past their 30 days may not have been deleted; they only take up a little room.',
    next: 'The next clean-up runs about an hour later. If it repeats, a developer should look at it.',
  },
  'idempotency.sweep_failed': {
    happened: 'The hourly clean-up of old repeat-request guards failed for one organisation or for all.',
    broke: 'Guards past their 30 days were not deleted this time; they only take up a little room.',
    next: 'The next clean-up, about an hour later, takes what was left. If it keeps failing, check the database.',
  },
  'idempotency.unreadable': {
    happened: "A request's saved retry record could not be read, or held no result.",
    broke: 'The request was refused and nothing was saved. Something outside the app may have changed the database.',
    next: 'Treat it as possible tampering: check the database and follow the incident runbook.',
  },
  'identity.contact_fill_failed': {
    happened: "The hourly job that saves people's names from the login service stopped part-way.",
    broke: 'Some people still have no saved name, so audit logs may show them without one.',
    next: 'It is tried again at the next hourly run. If it keeps failing, check the login service.',
  },
  'identity.flow_sweep_failed': {
    happened: 'The hourly clean-up of unfinished sign-ins failed.',
    broke: 'Some old unfinished sign-ins were not deleted this time.',
    next: 'The next clean-up, about an hour later, takes what was left. If it keeps failing, check the database.',
  },
  'identity.records_filling': {
    happened:
      "An organisation's stored registered contacts or sign-in factor resets passed half of what the app can read.",
    broke: 'Nothing is affected yet; if they keep growing, that list will stop working for the organisation.',
    next: 'Find out why the organisation has so many, and tell the developer before the limit is reached.',
  },
  'identity.session_sweep_failed': {
    happened: 'The hourly clean-up of ended sign-in sessions failed.',
    broke: 'Some old sign-in sessions were not deleted this time; none can be used again.',
    next: 'The next clean-up, about an hour later, takes what was left. If it keeps failing, check the database.',
  },
  'identity.step_up_challenge_sweep_failed': {
    happened: 'The hourly clean-up of expired identity re-checks failed.',
    broke: 'Some old identity re-checks were not deleted this time; none can be used again.',
    next: 'The next clean-up, about an hour later, takes what was left. If it keeps failing, check the database.',
  },
  'idp.impersonated': {
    happened: 'The login service recorded someone acting as another person, which Agent X never turns on.',
    broke: "It was copied to the audit trail. Someone may have misused the login service's admin powers.",
    next: "Treat it as a possible break-in: check the login service's admin accounts and follow the incident runbook.",
  },
  'idp.rights_changed': {
    happened: 'Someone was given, changed or removed admin rights inside the login service itself.',
    broke: "It was copied to the audit trail. Those rights can change anyone's sign-in.",
    next: 'Check the change was planned; if not, treat it as a possible break-in and follow the runbook.',
  },
  'idp.token_issued': {
    happened: 'The login service issued an access token for a login.',
    broke: 'It was copied to the audit trail. Such a token lets a program sign in without a person.',
    next: 'Check it was planned; if not, remove the token in the login service and follow the runbook.',
  },
  'idp_events.keys_unread': {
    happened: 'After a person added a security key, the login service could not say which keys they hold.',
    broke:
      'To stay safe, the new key counts as a risky change: that person goes 7 days without admin or approver powers.',
    next: 'Nothing to do if the person added the key themselves; the 7 days pass by themselves.',
  },
  'idp_events.run_failed': {
    happened: "The job that copies the login service's admin events into the audit trail failed this run.",
    broke: 'Events not yet copied are waiting; any copied before the failure are kept.',
    next: 'It carries on from where it stopped at the next run, every 5 minutes. If it repeats, check the login service.',
  },
  'idp_events.tied_page': {
    happened: 'A full page of login service events all had the same time, so the copy job moved past that moment.',
    broke: 'Any more events from that exact moment may not have been copied into the audit trail.',
    next: "Check the login service's own event history for that moment for anything missed.",
  },
  'integrity_hold.chain_still_broken': {
    happened: "An admin tried to clear the organisation's security hold, but its audit trail is still broken.",
    broke: 'The clearing was refused, so the hold stays on.',
    next: "A broken audit trail needs an operator's restore, not an admin's button: follow the incident runbook.",
  },
  'log.invalid_event': {
    happened: 'Part of the app wrote a log line with a badly formed name.',
    broke: 'The line was still kept, under a general name, so alerts that watch for its real name may miss it.',
    next: 'Tell the developer: it is a code mistake to fix.',
  },
  'log.suppressed': {
    happened: 'One kind of log line came too often in a minute, so further copies were held back and counted.',
    broke: 'The count is exact, but the details of the held-back lines are not in the log.',
    next: 'Look at the kind of line it names: a flood usually means something is failing over and over.',
  },
  'mandate_expiry.failed': {
    happened: 'A mandate past its end date could not be marked as expired.',
    broke: 'It still shows as open, but no payment can be made under it.',
    next: 'It is tried again at the next run, about 5 minutes later. If it keeps failing, check the database and the integrity alarms.',
  },
  'mandate_expiry.run_failed': {
    happened: 'The list of organisations could not be read, so the check for ended mandates was skipped.',
    broke: 'No mandate was marked as expired this run, but none can be spent past its end.',
    next: 'It is tried again at the next run, about 5 minutes later. If it keeps failing, check the database.',
  },
  'mandate_expiry.unreadable': {
    happened: "An organisation's mandates past their end date could not be looked up.",
    broke: "None of that organisation's mandates was marked as expired this run, but none can be spent past its end.",
    next: 'It is tried again at the next run, about 5 minutes later. If it keeps failing, check the database.',
  },
  'migrate.failed': {
    happened: 'The database update job failed during a release.',
    broke:
      'The new version was not put live. Earlier updates in the run stay in place; the failing one was normally undone.',
    next: 'If the database was busy, run the release again. Otherwise a developer must fix the update; one flagged part-done needs repair by hand.',
  },
  'migrate.start_refused': {
    happened: 'The database update job refused to start.',
    broke: 'No database update was made, so the release did not put the new version live.',
    next: 'Fix the settings the log lists, then run the release again.',
  },
  'notification.failed': {
    happened: 'An email notice could not be sent this time.',
    broke: 'Its recipient has not been told yet; a notice that can never be sent is given up at once.',
    next: 'It is tried again later, up to 8 tries in all. If many fail, check the email service and the login service.',
  },
  'notification.run_failed': {
    happened: 'The run that sends email notices stopped early.',
    broke: 'Notices it had not sent are waiting and are not lost.',
    next: 'A later run picks them up once their hold runs out. If it repeats, check the database.',
  },
  'notifications.notice_sweep_failed': {
    happened: 'The hourly clean-up of old notices failed.',
    broke: 'Some notices already sent or given up were kept past their time this run.',
    next: 'The next clean-up, about an hour later, takes what was left. If it keeps failing, check the database.',
  },
  'operator.database_unavailable': {
    happened: 'An operator job could not reach the database.',
    broke: 'The job stopped before doing anything, so nothing was changed.',
    next: 'Check the database is up and reachable, then run the job again.',
  },
  'operator.done_before': {
    happened: 'An operator job was asked to do something already done.',
    broke: "Nothing was changed: the organisation or its first admin's invitation already exists from an earlier run.",
    next: 'Nothing to fix. Make sure the finished request is not left on the job to run again.',
  },
  'operator.export_unwritten': {
    happened: 'An export of an audit or activity log for a case was recorded, but its file was not saved to storage.',
    broke: "It is on record and the organisation's admins are told, but there is no file yet.",
    next: "Run the job again with the same request file. If records can't be verified again, treat it as a security issue.",
  },
  'operator.failed': {
    happened: 'An operator job stopped on an unexpected error.',
    broke: 'Its work most likely did not happen, though a connection lost at the very end may have saved it.',
    next: 'Check the database, then re-run the same request file: it says if it was done. Check a new organisation was not made before typing it again.',
  },
  'operator.refused': {
    happened: 'An operator job refused the request it was given.',
    broke:
      'Nothing was changed: the request was wrong or not allowed, such as a missing organisation, too large a range, or records that could not be verified.',
    next: 'Read the problems the log lists, fix the request and run the job again.',
  },
  'operator.restore_check_failed': {
    happened: 'The backup restore drill found the restored copy does not match the live database.',
    broke: "That backup can't be trusted to bring the platform back whole. Nothing was changed on either side.",
    next: 'Read the problems the log lists and check the backups before relying on them.',
  },
  'operator.start_refused': {
    happened: 'An operator job refused to start.',
    broke: 'Nothing was done: its settings, signing keys or database login rights are wrong.',
    next: 'Fix the problems the log lists, then run the job again.',
  },
  'request_expiry.failed': {
    happened: 'A spend request left waiting for approval too long could not be expired.',
    broke: "It still holds part of the agent's budget for now.",
    next: 'It is tried again at the next run, about 5 minutes later. If it keeps failing, check the database and the integrity alarms.',
  },
  'request_expiry.run_failed': {
    happened: 'The list of organisations could not be read, so the expiry of overdue spend requests was skipped.',
    broke: 'No overdue request was expired this run; their budget holds stay for now.',
    next: 'It is tried again at the next run, about 5 minutes later. If it keeps failing, check the database.',
  },
  'request_expiry.unreadable': {
    happened: "An organisation's overdue spend requests could not be looked up.",
    broke: "None of that organisation's overdue requests was expired this run.",
    next: 'It is tried again at the next run, about 5 minutes later. If it keeps failing, check the database.',
  },
  'waiting_rejection.failed': {
    happened: 'A waiting request an admin chose to reject with a policy change could not be rejected.',
    broke: "It stays waiting, still holding part of the agent's budget; its approver can still reject it.",
    next: 'It is tried again in about 5 minutes. If it keeps failing, check the database and the integrity alarms.',
  },
  'waiting_rejection.run_failed': {
    happened:
      'The list of organisations could not be read, so rejecting the requests admins chose to reject with a policy change was skipped.',
    broke: 'Those requests stay waiting a while longer, still holding part of their budgets.',
    next: 'It is tried again in about 5 minutes. If it keeps failing, check the database connection.',
  },
  'waiting_rejection.unreadable': {
    happened: 'The policies whose changes left requests to reject could not be read for one organisation.',
    broke: "That organisation's requests stay waiting for now; nothing was rejected on what could not be read.",
    next: 'It is tried again in about 5 minutes. If it keeps failing, check the integrity alarms for that organisation.',
  },
  'request_void.failed': {
    happened:
      'A pending spend request could not be cancelled after something it uses was stopped with its requests cancelled.',
    broke: "It stays pending for now, still holding part of the agent's budget.",
    next: 'It is tried again in about 5 minutes. If it keeps failing, check the database and the integrity alarms.',
  },
  'request_void.run_failed': {
    happened:
      'The list of organisations could not be read, so the cancelling of spend requests no longer allowed was skipped.',
    broke: 'No such request was cancelled, and no ended bank consent was recorded, this run.',
    next: 'It is tried again at the next run, about 5 minutes later. If it keeps failing, check the database.',
  },
  'request_void.unreadable': {
    happened: "An organisation's spend requests that are no longer allowed could not be looked up.",
    broke: 'None of them was cancelled this run.',
    next: 'It is tried again at the next run, about 5 minutes later. If it keeps failing, check the database.',
  },
  'security.event_sweep_failed': {
    happened: 'The hourly clean-up of old security records failed.',
    broke: 'Some failed sign-in and too-many-request records were kept past their time this run.',
    next: 'The next clean-up, about an hour later, takes what was left. If it keeps failing, check the database.',
  },
  'security.events_refused': {
    happened: 'A batch of security counts was refused as badly formed.',
    broke: 'Those counts of failed sign-ins and refused requests were dropped and are lost.',
    next: 'This is a bug: a developer should look at it.',
  },
  'security.events_unaddressed': {
    happened: 'More addresses than the API can track sent failed sign-ins or too many requests in a short time.',
    broke: 'Some were counted without their address or person.',
    next: 'This may be an attack: check the security records and the traffic.',
  },
  'security.events_unwritten': {
    happened: 'The API stopped before all its security counts could be saved.',
    broke: 'Those counts of failed sign-ins and refused requests are lost.',
    next: 'Nothing to do if it is rare. If it repeats, check whether the database is slow when the API stops.',
  },
  'security.events_write_failed': {
    happened: 'Security counts could not be saved to the database.',
    broke: 'They are not in the security records yet; they were kept in memory.',
    next: 'They are tried again a minute later. If it keeps failing, check the database.',
  },
  'spend_request.agent_cancels_spent': {
    happened: 'An agent tried to cancel a spend request after using up its cancels for the last 24 hours.',
    broke: 'That cancel was refused; the request stays open.',
    next: 'An admin or approver can cancel it. Check why the agent is cancelling so many.',
  },
  'status.change_not_applied': {
    happened: "A record's status change did not stick: the record ended up in a different state from the one decided.",
    broke: 'The action was refused and undone. Something outside the app may be changing the database.',
    next: 'Treat it as possible tampering and follow the incident runbook.',
  },
  'status.unreadable': {
    happened: 'A record held a status the app does not know, or appeared twice.',
    broke: 'The action on it was refused and undone. The record may have been changed outside the app.',
    next: 'Treat it as possible tampering and follow the incident runbook.',
  },
  'suppliers.contacts_unreadable': {
    happened: "A supplier's saved contact details could not be opened.",
    broke: 'The supplier could not be shown or changed, and the person was told its record cannot be trusted.',
    next: 'Check the encryption keys and the integrity alarms; see the runbook.',
  },
  'suppliers.fingerprint_unavailable': {
    happened: 'A new payee was confirmed by the bank link, but could not be finished from this check.',
    broke: 'The payee registration stays open; nothing is lost.',
    next: 'It finishes when the request that sent the account details is sent again. Nothing to do unless it stays open.',
  },
  'suppliers.partner_answer_refused': {
    happened: "The bank link's answer about a new payee was unsafe or unusable.",
    broke: 'The payee registration was marked as failed, and nothing of the answer was kept.',
    next: 'An admin can register the payee again. If it repeats, raise it with the payment partner.',
  },
  'suppliers.partner_page_refused': {
    happened: 'The bank link gave a payee form that is not on its own secure page.',
    broke: 'The person was not sent there and was told the bank link is unavailable.',
    next: 'Check the payment partner settings, and raise it with the partner if it repeats.',
  },
  'suppliers.registration_partner_differs': {
    happened: 'A payee registration was started with a different payment partner from the one now in use.',
    broke: 'It was not checked, and the person was told the bank link is unavailable.',
    next: 'Check the payment partner settings; the payee may need registering again.',
  },
  'suppliers.version_missing': {
    happened: "Part of a supplier's saved history is missing from the database.",
    broke: 'The supplier could not be verified, and the person was told its record cannot be trusted.',
    next: 'Treat it as possible tampering: check the integrity alarms and see the runbook.',
  },
  // Keys are event names (logger.ts's EventName), written out so the logger's import isn't circular.
} as const satisfies Readonly<Record<`${string}.${string}`, PlainWords>>;

/** An event a caller may log as a warning or error. The `log.` ones are the logger's own. */
export type ProblemEvent = Exclude<keyof typeof PLAIN_WORDS, `log.${string}`>;

/** Only reachable past the type, e.g. by a cast: the line still says something useful. */
const NO_WORDS: PlainWords = {
  happened: 'Something went wrong that has no plain words yet.',
  broke: 'What it affects is not written down.',
  next: 'Look up the line in the code and add its words to the catalogue.',
};

/** The three sentences for one line, joined. */
export function saysFor(event: string): string {
  const words: PlainWords = Object.hasOwn(PLAIN_WORDS, event)
    ? PLAIN_WORDS[event as keyof typeof PLAIN_WORDS]
    : NO_WORDS;
  return `${words.happened} ${words.broke} ${words.next}`;
}
