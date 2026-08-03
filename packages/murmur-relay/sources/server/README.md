# Node server

This module adapts Node `IncomingMessage`/`ServerResponse` to the package's Fetch
handler. Protocol behavior remains testable without a socket; this layer owns
URL/header/body adaptation and listening. Premature request, response, or socket
closure aborts the Fetch request so long-poll waiters are released immediately;
all lifecycle listeners are removed after response completion. The adapter
passes the socket's direct peer address as trusted request metadata and pipes
Fetch response bodies with Node stream backpressure rather than buffering them.

Long-lived SSE responses (`GET .../stream`) work unchanged: piping applies socket
backpressure so a slow client throttles the source instead of growing memory, and
Node exempts a fully received request (a bodyless `GET`) from `requestTimeout`,
`headersTimeout`, and `keepAliveTimeout`, so a minutes-long response is not
aborted. Streaming response headers are flushed before the first chunk so the
client observes `ready` without buffering delay.
