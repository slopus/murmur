# Account implementation

`deviceRosterCodec.ts` owns strict current-roster and roster-mutation encoding.
The mutation is carried by an account-identity-signed ordinary delivery; the
relay authenticates it and atomically stores the resulting roster and inbox
notification.

`accountRecords.ts` prepares only account-device lifecycle events and durable
roster convergence jobs.

`directoryCodec.ts` owns strict directory upload and spent-notification
plaintext. `directoryRecords.ts` stores non-secret reference metadata for the
current last-resort package, one-use pool, pending replenishment, and spent
markers. Matching private KeyPackage bundles remain in the session engine's
durable KeyPackage storage.

Device authority is exactly the relay's current account-signed roster. Murmur
does not add secondary device credentials or an approval ceremony.
