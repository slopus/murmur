# Relay HTTP boundary

The Fetch-compatible handler exposes health, signed publication, bounded queue
read, ordered SSE, signed acknowledgement, current device rosters, directory
uploads, exact ticketed directory claims, and account-signed terminal session
and account deletion. JSON parsing rejects duplicate keys and unknown fields
before protocol validation.

CORS origins are exact, request sizes are bounded, and POST rate limiting uses
a trusted remote address. A trusted ingress principal separately bounds
outstanding multicast references.

Directory upload and claim routes bypass the generic remote-address requirement
and request limiter because directory admission belongs at ticket issuance.
Claim-time spent notifications remain subject to ordinary queue quotas.
