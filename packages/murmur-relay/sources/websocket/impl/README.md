# WebSocket implementation

The session engine accepts exactly one queue operation per socket, verifies that
the signed operation matches the ticket device, and streams exact delivery
objects plus heartbeats when requested.
