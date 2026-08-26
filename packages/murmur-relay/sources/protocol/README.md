# Relay protocol

Canonical codecs cover sender-signed deliveries, recipient-signed queue reads,
recipient-signed acknowledgements, and their JSON wire forms.

Every signature uses a distinct domain. Delivery signatures bind operation ID,
sender, exact recipients, creation and expiry times, and ciphertext. Read and
acknowledgement signatures bind recipient identity, cursor, limits, time, and
operation-specific fields.
