-- Accepting an invitation (ADR-005 §6, SEC-HA-08; B4-4b): who accepted it,
-- and what became of it.
--
-- An open invitation is accepted by a signed-in person whose verified email
-- is the invited one (B4-4c). A developer or a viewer joins at once: the
-- invitation moves OPEN>ACCEPTED in the transaction that adds the
-- membership. An admin or a finance approver waits for an existing admin to
-- confirm who accepted, with step-up (B4-4d): OPEN>AWAITING_CONFIRMATION,
-- then AWAITING_CONFIRMATION>ACCEPTED with the membership, or
-- AWAITING_CONFIRMATION>DECLINED.
--
-- `accepted_by` names the person who accepted (an identity.users ID), and is
-- sealed with the rest, so an owner can't put another person in the place of
-- the one an admin is asked to confirm. It is null until accepted. The app
-- may update it as it may the other signed fields (the signing step writes
-- every one).
--
-- Adding a signed field changes what every invitation's seal covers, so an
-- invitation sealed before this reads as tampered with. None exists outside
-- tests (staging has no members, so no one there could invite), and a
-- rollback across this migration is refused anyway (Container-Image.md
-- "Known limits").

ALTER TABLE identity.invitations
  ADD COLUMN accepted_by uuid REFERENCES identity.users (id);

ALTER TABLE identity.invitations DROP CONSTRAINT invitations_status_check;
ALTER TABLE identity.invitations ADD CONSTRAINT invitations_status_check
  CHECK (status IN ('DRAFT', 'OPEN', 'AWAITING_CONFIRMATION', 'ACCEPTED', 'DECLINED'));

DROP TRIGGER status_guard ON identity.invitations;
CREATE TRIGGER status_guard BEFORE INSERT OR UPDATE ON identity.invitations
  FOR EACH ROW EXECUTE FUNCTION state_rules.guard_status(
    'DRAFT',
    'DRAFT>OPEN',
    'OPEN>ACCEPTED',
    'OPEN>AWAITING_CONFIRMATION',
    'AWAITING_CONFIRMATION>ACCEPTED',
    'AWAITING_CONFIRMATION>DECLINED'
  );

GRANT UPDATE (accepted_by) ON identity.invitations TO agentx_app;
