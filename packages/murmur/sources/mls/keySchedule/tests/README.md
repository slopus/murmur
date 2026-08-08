# Key-schedule tests

Length, determinism, context binding, and label-separation tests.

```text
same inputs/context -> same epoch outputs
changed GroupContext -> different outputs
same secret + different label -> separated keys
all outputs ------------------> suite-sized bytes
```

The tests make accidental label reuse or missing context binding visible before
it can split member epochs.
