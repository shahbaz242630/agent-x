-- The platform hand-off pause (Phase 4 B1; BR-11's operator pause; SEC-OPS-03;
-- partner decision 4, S135): one switch for the whole platform that stops
-- every hand-off of an approved payment to the bank. Requests are still
-- decided and approved; approved ones wait until it is resumed, and each is
-- checked again before it goes. Only the operator's command moves it, with a
-- reason, and each move is a signed event on the platform chain
-- (`platform.handoff_paused` / `platform.handoff_resumed`), told to every
-- organisation's admins on its own chain.
--
-- - `platform_controls.handoff_pause`: its one row (`only_row`, as the chain
--   head's), whether it is paused, and the platform event that set it
--   (`event_seq`, `event_id`). The app believes the row only when it points
--   at the newest of those events and says what it did; a row that doesn't
--   is tampering, read as paused (fails closed). Locked first by every
--   transaction that reads or moves it (ADR-006 §6 level 1), FOR SHARE by a
--   hand-off, FOR NO KEY UPDATE by the operator's change.
-- - Born paused, pointing at no event (ADR-014 §4: the first production start
--   runs with the pause ON): a new environment hands nothing off until an
--   operator resumes it, with a reason, on the record.
--
-- A global table, of no organisation: no tenant wall. Its schema is
-- append-only for the app, so it is an exception there with its reason
-- (schema-policy.ts), as the chain head is: the app reads it and moves those
-- three columns alone, never adding or deleting a row.
--
-- Notice kinds: `handoff_paused` and `handoff_resumed`, to every admin of
-- every organisation, each `aboutId` the entry on its own audit log.

-- The newest pause or resume, read with the row by every hand-off: by its
-- action, so the read stays a few index entries however long the platform
-- chain grows (a process start adds one event each).
CREATE INDEX audit_events_by_action ON platform_controls.audit_events (action, seq);

CREATE TABLE platform_controls.handoff_pause (
  only_row boolean NOT NULL PRIMARY KEY DEFAULT true CHECK (only_row),
  paused boolean NOT NULL,
  event_seq bigint CHECK (event_seq >= 1),
  event_id uuid,
  CONSTRAINT event_whole CHECK ((event_seq IS NULL) = (event_id IS NULL))
);

INSERT INTO platform_controls.handoff_pause (paused, event_seq, event_id) VALUES (true, NULL, NULL);

GRANT SELECT ON platform_controls.handoff_pause TO agentx_app;
GRANT UPDATE (paused, event_seq, event_id) ON platform_controls.handoff_pause TO agentx_app;
GRANT SELECT ON platform_controls.handoff_pause TO agentx_backup;

ALTER TABLE notifications.outbox DROP CONSTRAINT outbox_kind_check;
ALTER TABLE notifications.outbox
  ADD CONSTRAINT outbox_kind_check
    CHECK (
      kind IN (
        'role_granted',
        'member_rejoined',
        'member_removed',
        'role_removed',
        'contact_added',
        'contact_removed',
        'second_factor_removed',
        'second_factor_added',
        'password_changed',
        'sign_in_email_changed',
        'sign_in_blocked',
        'sign_in_restored',
        'factor_reset_link',
        'factor_reset_asked',
        'factor_reset_confirmed',
        'factor_reset_cancelled',
        'factor_reset_expired',
        'factor_reset_completed',
        'supplier_reactivated',
        'supplier_payee_changed',
        'supplier_details_changed',
        'supplier_verified',
        'supplier_suspended',
        'agent_handed_over',
        'agent_handed_to_you',
        'mandate_accepted',
        'mandate_suspended',
        'mandate_resumed',
        'mandate_revoked',
        'mandate_expired',
        'organization_policy_changed',
        'mandate_policy_changed',
        'spend_request_waiting',
        'organization_frozen',
        'organization_unfrozen',
        'audit_log_exported',
        'access_log_export_ready',
        'access_log_export_failed',
        'access_log_exported',
        'handoff_paused',
        'handoff_resumed'
      )
    );
