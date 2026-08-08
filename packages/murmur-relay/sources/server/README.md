# Node server

Adapts Node `IncomingMessage` and `ServerResponse` to the relay's Fetch handler.
It streams request and response bodies with backpressure, propagates disconnect
abort signals into long polls, and bounds graceful shutdown.
