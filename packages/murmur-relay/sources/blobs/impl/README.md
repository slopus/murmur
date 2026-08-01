# Blob backend implementation

This directory contains the filesystem streaming mechanics and AWS SigV4
canonicalization used by the public blob backends.

```text
local: body stream -> size/hash transform -> temporary file -> atomic install
s3:    canonical request -> signing key ladder -> presigned URL
```
