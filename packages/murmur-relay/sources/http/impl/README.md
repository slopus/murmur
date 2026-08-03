# HTTP implementation

Mechanical bounded stream reading used before JSON parsing and trusted-proxy
client-address resolution. A
declared oversized `Content-Length` is rejected immediately; chunked bodies are
cancelled as soon as their cumulative size crosses the configured limit.

`streamResponse.ts` builds the `GET .../stream` SSE body. It is strictly
pull-driven so runtime backpressure is honoured: each `pull` drains the
subscriber's bounded queue into named events (`ready` first, then `frame`,
`wake`, `drop`) and parks with a keepalive timeout between batches, emitting a
`: keepalive` comment when idle. The only unread bytes ever buffered are the
chunk enqueued per pull; everything else stays in the drop-oldest subscriber
queue. Request abort or a closed subscription ends the stream and detaches the
abort listener.
