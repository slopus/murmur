# Relay HTTP boundary

The Fetch-compatible handler exposes health, signed publication, bounded queue
read, ordered SSE, and signed acknowledgement routes. JSON parsing rejects
duplicate keys and unknown fields before protocol validation.

CORS origins are exact, request sizes are bounded, and POST rate limiting uses
a trusted remote address. A trusted ingress principal separately bounds
outstanding multicast references.
