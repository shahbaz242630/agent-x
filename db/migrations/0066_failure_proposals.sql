-- A second admin's approval before an UNKNOWN payment is marked failed
-- (Phase 4 gate H10; partner decision 38 and its S145 heads-up: Agent X can't
-- check the bank's reference an admin types, so one admin proposes and
-- another confirms; ADR-007 §10; Rule Book §1.9).
--
-- transactions.failure_proposals: one admin's proposal to mark a payment
-- failed, with the bank's evidence reference they typed. An authority table
-- (ADR-012 §2): an OPEN one is what a second admin's confirm frees a
-- payment's money and its order on. At the transaction's level in the lock
-- order (ADR-006 §6: 10), after its transaction, its parent. Sealed: the
-- transaction, the reference, who proposed it, when, and its status:
--   OPEN       proposed, waiting for a second admin (or, where the
--              organisation has one admin only, that admin a day on);
--   WITHDRAWN  taken back by an admin, the proposer among them;
--   CONFIRMED  confirmed: the payment moved to FAILED in the same transaction.
-- A proposal left OPEN when the bank's answer settles the payment first ends
-- with it: its confirm is refused, and a new one can't be made (the payment
-- is no longer UNKNOWN). One OPEN proposal a payment
-- (`one_open_proposal_a_payment`); the WITHDRAWN and CONFIRMED stay, so the
-- organisation's audit log and these rows agree for good.
--
-- The app adds rows and reads them, and changes only the status and the two
-- signed-state columns, which the audit module's record writes and seals
-- together; the rest are fixed when it is made (`fixed_at_creation`). The
-- backup role reads everything.
--
-- Notice kinds, to every admin, `aboutId` the payment's transaction:
-- `payment_mark_proposed` (a second admin must confirm) and
-- `payment_mark_withdrawn`.

CREATE TABLE transactions.failure_proposals (
  org_id uuid NOT NULL,
  id uuid NOT NULL,
  transaction_id uuid NOT NULL,
  evidence_ref text NOT NULL CHECK (evidence_ref ~ '^[A-Za-z0-9][A-Za-z0-9._/-]{2,63}$'),
  proposed_by uuid NOT NULL,
  status text NOT NULL CHECK (status IN ('OPEN', 'WITHDRAWN', 'CONFIRMED')),
  created_at timestamptz NOT NULL CHECK (pg_catalog.isfinite(created_at)),
  state_version integer NOT NULL DEFAULT 1,
  state_event_id uuid,
  PRIMARY KEY (org_id, id),
  CONSTRAINT of_a_transaction FOREIGN KEY (org_id, transaction_id) REFERENCES transactions.transactions (org_id, id)
);

CREATE UNIQUE INDEX one_open_proposal_a_payment ON transactions.failure_proposals (org_id, transaction_id)
  WHERE status = 'OPEN';

ALTER TABLE transactions.failure_proposals ENABLE ROW LEVEL SECURITY;
ALTER TABLE transactions.failure_proposals FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON transactions.failure_proposals
  USING (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid)
  WITH CHECK (org_id = nullif(pg_catalog.current_setting('app.org_id', true), '')::uuid);

CREATE TRIGGER fixed_at_creation BEFORE UPDATE ON transactions.failure_proposals
  FOR EACH ROW EXECUTE FUNCTION state_rules.guard_fixed('transaction_id', 'evidence_ref', 'proposed_by', 'created_at');

CREATE TRIGGER status_guard BEFORE INSERT OR UPDATE ON transactions.failure_proposals
  FOR EACH ROW EXECUTE FUNCTION state_rules.guard_status('OPEN', 'OPEN>WITHDRAWN', 'OPEN>CONFIRMED');

GRANT SELECT, INSERT ON transactions.failure_proposals TO agentx_app;
-- Every sealed column, as the signed state writes them all with the seal when
-- it signs a row (transactions.transactions alike); `fixed_at_creation` keeps
-- the transaction, the reference, the proposer and the time as made.
GRANT UPDATE (
  transaction_id, evidence_ref, proposed_by, status, created_at, state_version, state_event_id
) ON transactions.failure_proposals TO agentx_app;
GRANT SELECT ON transactions.failure_proposals TO agentx_backup;

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
        'handoff_resumed',
        'spend_request_stopped',
        'supplier_remittance_changed',
        'payment_remittance',
        'payment_remittance_no_email',
        'payment_marked_failed',
        'payment_contradicted',
        'payment_unproven',
        'payment_still_unknown',
        'payment_mark_proposed',
        'payment_mark_withdrawn'
      )
    );
