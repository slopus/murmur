# Utility tests

Canonical JSON and boundary codecs are tested independently because signature
compatibility and ambiguous-input rejection depend on their exact bytes. Logger
tests pin the visible three-field format, confine ANSI color to interactive
module labels, and verify credential-safe error summaries.
