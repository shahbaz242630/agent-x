-- The first admin's invitation (ADR-005 §6, ADR-011 §3; B4-6a): an
-- organisation the operator created has no members, so no admin can invite
-- its first one. The operator's command does (the one operator write to an
-- organisation's tables besides creating it, recorded on the platform chain):
-- an invitation for an admin, opened in the transaction that makes it, naming
-- no member who asked (`invited_by`) and no step-up (`step_up_challenge_id`),
-- as the command runs on the operator's job, not in a person's session.
--
-- Both are null together, and only on an admin's invitation
-- (`asked_by_a_member_or_the_operator`); a member's invitation still names
-- both, the member by the foreign key as before. Both stay sealed. Accepted
-- while the organisation has no members, it makes the first admin at once;
-- otherwise an existing admin confirms who accepted, as for any admin
-- (B4-4d).

ALTER TABLE identity.invitations ALTER COLUMN invited_by DROP NOT NULL;
ALTER TABLE identity.invitations ALTER COLUMN step_up_challenge_id DROP NOT NULL;
ALTER TABLE identity.invitations ADD CONSTRAINT asked_by_a_member_or_the_operator CHECK (
  (invited_by IS NOT NULL AND step_up_challenge_id IS NOT NULL)
  OR (invited_by IS NULL AND step_up_challenge_id IS NULL AND role = 'admin')
);
