# Relay protocol

Canonical codecs cover sender-signed deliveries, recipient-signed queue reads,
recipient-signed acknowledgements, account-signed terminal operations and
directory uploads, exact directory claims, and their JSON wire forms.

Every signature uses a distinct domain. Delivery signatures bind operation ID,
sender, owning sender account, direct recipients or relay-visible session
control, session ownership metadata, creation and expiry times, and ciphertext.
Session controls cover epoch, encrypted-content class, device coverage, and the
post-Commit membership and role summary. Read and acknowledgement signatures
bind recipient identity, cursor, limits, time, and operation-specific fields.

Each directory device publishes sorted, unique one-use package references and
exactly one last-resort reference. Every one-use item embeds its own
device-signed ordinary-inbox spent notification.
