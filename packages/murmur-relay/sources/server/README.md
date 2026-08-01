# Node server

This module adapts Node `IncomingMessage`/`ServerResponse` to the package's Fetch
handler. Protocol behavior remains testable without a socket; this layer owns
URL/header/body adaptation and listening. Premature request, response, or socket
closure aborts the Fetch request so long-poll waiters are released immediately;
all lifecycle listeners are removed after response completion. The adapter
passes the socket's direct peer address as trusted request metadata and pipes
Fetch response bodies with Node stream backpressure rather than buffering them.
