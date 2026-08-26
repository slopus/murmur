# MLS KeyPackages

A KeyPackage binds one HPKE init key, one leaf encryption key, the Ed25519
signature key, credential bytes, and a bounded lifetime. Canonical codecs and
reference hashing are local to this module.

`createMlsKeyPackage` returns public material plus one-use private HPKE keys.
The stateful facade persists the serialized private bundle before releasing the
public admission material. Successful Welcome processing consumes and destroys
the bundle.
