# Blob backends

Blob storage is independent of relay topic state. The HTTP layer asks a backend
for a short-lived transfer link and clients move ciphertext through that link.

```text
client -> POST link request -> BlobBackend -> signed PUT/GET URL
client -------------------------------> local filesystem or S3
```

`LocalBlobBackend` stores sharded content-addressed files and authenticates
relay-local transfer URLs with HMAC-SHA256. `S3BlobBackend` constructs AWS SigV4
presigned URLs without an SDK and uses a signed checksum header for uploads.
