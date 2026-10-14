-- The cascades of Phase 3 (PRD §4.2; BR-09, BR-11; ADR-006 §10; Phase 3 C1):
-- when an agent, mandate, funding source or supplier is stopped, its pending
-- spend requests (waiting for approval, approved, or ready) are denied and
-- their reservations and order claims released, a bounded batch in the
-- brake's own transaction and the rest by a follow-up job, which looks for
-- them a page at a time, by ID, in every organisation.
--
-- One index holding only the pending requests, so both looks stay a short
-- scan however many requests an organisation has made: a request leaves it
-- when it is denied, expired, cancelled or handed off. The row's columns only
-- pick the candidates; each is then read through its signed state before
-- anything moves. No table, column or grant changes.

CREATE INDEX pending_requests ON spend_requests.requests (org_id, id)
  WHERE status IN ('APPROVAL_REQUIRED', 'APPROVED', 'INSTRUCTION_READY');
