# WebSocket relay transport

This additive boundary maps temporary device-bound tickets and strict JSON
WebSocket frames onto the existing relay service. HTTP/SSE routes remain
unchanged.

Queue pages and acknowledgements carry the same sequence and generation fields
as HTTP. A stream emits one continuity control frame before delivery frames, so
the client proves the chain before processing ciphertext.
