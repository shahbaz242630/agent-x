-- Rejoining after deactivation (ADR-005 §6, ADR-003 §8; B4-5c): a person
-- deactivated in an organisation comes back through a new invitation, to the
-- same membership, never a second one. The directory holds one entry per
-- person in an organisation and never deletes it (0015), so the membership it
-- names is the one that comes back: DEACTIVATED>ACTIVE.
--
-- It restores authority, so it goes through what a first join does: an
-- admin's step-up on the invitation (B4-3), the invited address matched at
-- acceptance (B4-4c), and, for an admin or a finance approver, an existing
-- admin's confirmation with step-up (B4-4d). The role is the invitation's,
-- and when it began is the day it came back: a member returning isn't an
-- established one (ADR-012 §1). Both are sealed with the rest, as before.

DROP TRIGGER status_guard ON identity.memberships;
CREATE TRIGGER status_guard BEFORE INSERT OR UPDATE ON identity.memberships
  FOR EACH ROW EXECUTE FUNCTION state_rules.guard_status('ACTIVE', 'ACTIVE>DEACTIVATED', 'DEACTIVATED>ACTIVE');
