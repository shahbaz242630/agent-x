-- The expiry of requests waiting for approval (PRD §4.2; ADR-006 §10; BR-09;
-- partner decision 10; Phase 2 D7a): a spend request APPROVAL_REQUIRED for 72
-- hours is EXPIRED by the API's job, its reservation and order claim
-- released. The job looks for them a page at a time, by ID, every few
-- minutes, in every organisation.
--
-- One index holding only the requests still waiting, so that look stays a
-- short scan however many requests an organisation has made: a request
-- leaves it when it is approved, denied, expired or cancelled. The row's
-- `created_at` only picks the candidates; each is then judged by its
-- decision's sealed time (D7). No table, column or grant changes.

CREATE INDEX waiting_for_approval ON spend_requests.requests (org_id, id, created_at)
  WHERE status = 'APPROVAL_REQUIRED';
