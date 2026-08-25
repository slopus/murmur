# Group roles and asynchronous membership

## Destination

Every MLS session carries an MLS-protected role state: one owner account, a set
of admin accounts, and two policies. The owner is the account that created the
session. The owner is always an admin, cannot be demoted, and cannot be removed
from the session by anyone, including itself. Admins are granted and revoked by
the owner. When the `adminsAssignAdmins` policy is enabled, an admin may also
grant admin to another member; only the owner revokes admin. When the
`anyoneCanAddMembers` policy is enabled, any member may add a new member
account; otherwise only admins may. Removing a member account always requires
an admin, except that any member may remove its own account to leave. Policies
are chosen at creation and may later be changed only by the owner.

Role state travels inside every Commit's authenticated control and inside the
joiner bootstrap, so each member holds the identical role state for each epoch
and validates every Commit against the role state of the epoch it extends. An
unauthorized Commit is deterministically rejected by every member, so a rogue
member cannot fork the session. Device-scoped changes that follow a signed
account roster — adding a newly authorized device of an existing member account
or removing a revoked one — are authorized for the devices of that same account
and for admins, because the account-signed device credential is itself the
proof of admission.

Membership and role changes are asynchronous intents. The public API records a
durable intent and returns; Murmur converges it into a Commit during
synchronization and retries after losing a concurrent-Commit race, without any
other member being online. An add intent for an account that is already a
member completes as a no-op, so concurrent adds of the same person converge to
one member. Each add intent snapshots the session's per-account removal
generation when it is created; if that account's removal generation has
advanced by the time the intent executes, the add fails as a durable issue
instead of silently re-admitting someone who was just removed. A deliberate
re-add created after observing the removal succeeds.

This plan ships without backward compatibility. Every session is role-managed;
the single-committer flow, its committer transfer API, its proposal queue, and
the old session record and Commit wire formats are deleted, not kept beside the
new model. Sessions persisted by earlier releases are not decoded or migrated.

## How we know it is done

- A session exposes its owner, admin set, and policies, and the creator account
  is the owner.
- Owner-granted and, under `adminsAssignAdmins`, admin-granted admin
  assignments propagate through Commits and are enforced identically by every
  member.
- With `anyoneCanAddMembers` disabled, a non-admin member's add intent fails
  locally and an unauthorized membership Commit is rejected by every member.
- The owner cannot be demoted or removed; any other member can leave; removing
  someone else's account requires an admin.
- `addMember` and `removeMember` return once the intent is durable, and the
  change converges through synchronization even when every other member is
  offline.
- Two members concurrently adding the same account converge to exactly one
  membership without an error.
- An add intent created before observing that account's removal fails with a
  durable issue; one created afterwards succeeds.
- Losing a concurrent-Commit race cancels the staged Commit, preserves and
  re-encrypts its dependent application sends, and retries the intent, and a
  joiner Welcomed by the losing Commit is re-Welcomed and joins.
- No single-committer code path, committer transfer API, proposal queue, or
  legacy session decode remains in the package.
