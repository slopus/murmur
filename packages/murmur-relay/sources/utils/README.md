# Utilities

Strict, self-contained byte and JSON codecs shared by the protocol and stores
live here. They reject ambiguous encodings at the boundary so higher layers
only handle normalized values.

The standalone runtime also uses the Pino-backed logger in this directory. It
renders only time, fixed-width module, and a self-contained message; interactive
terminals color modules deterministically while redirected and container output
remains plain text.
