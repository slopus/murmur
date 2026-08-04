# Group creation tests

Exercises the RFC epoch-zero state and its first full Add Commit into epoch one.

```text
create(A) -> epoch 0 tree [A] -> Add(B) Commit -> epoch 1 tree [A,B]
                                      |
                                  Welcome(B)
```

The test connects initialization to the normal membership machinery instead of
testing an isolated constructor shape.
