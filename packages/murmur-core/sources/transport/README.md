# Transport

The relay contract carries signed opaque events, subscriptions, per-recipient
deliveries, acknowledgements, and ciphertext blobs. It has no chat, document, or
MLS knowledge.

```text
publisher -- signed event --> topic
                               |
                         recipient queues
                               |
subscriber <-- delivery / ack -'
```
