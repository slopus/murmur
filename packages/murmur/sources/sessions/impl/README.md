# Session implementation

The engine encodes authenticated bootstrap, Commit, proposal, role-control, and
application frames. Session records contain MLS and application-routing state;
active and staged epochs are stored separately.

KeyPackage bundles are one-use by default. Explicit internal reusable bundles
are reserved for account convergence across known sessions.
