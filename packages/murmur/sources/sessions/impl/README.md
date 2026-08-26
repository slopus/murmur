# Session implementation

The engine encodes authenticated bootstrap, Commit, proposal, role-control, and
application frames. Session records contain MLS and application-routing state;
active and staged epochs are stored separately.

KeyPackage bundles are one-use by default. Explicit internal reusable bundles
support account convergence and the directory's last-resort admission. A
reusable bundle may decrypt several independently created Welcomes until
rotation; one-use directory bundles are deleted after successful Welcome
processing or explicit rotation.

Directory spent notifications are ordinary signed inbox frames. They mark a
claimed public reference and schedule replenishment without deleting the
private bundle still needed by a later Welcome.
