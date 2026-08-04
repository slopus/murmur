# Transport implementation

Strict JSON codecs and the browser-safe Fetch transport. HTTP response bodies
are consumed incrementally under hard bounds; protected reads acquire and sign
one-use challenges automatically.
