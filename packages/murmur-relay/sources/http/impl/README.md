# HTTP implementation

Mechanical bounded stream reading used before JSON parsing or blob hashing. A
declared oversized `Content-Length` is rejected immediately; chunked bodies are
cancelled as soon as their cumulative size crosses the configured limit.
