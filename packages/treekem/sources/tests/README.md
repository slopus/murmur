# Public API tests

These tests exercise only the byte-oriented package surface.

```text
create Alice
    |
    `-- update Add(Bob, Carol, Dave)
            |       |       |
           join    join    join
            \       |       /
             same fresh secret
```

The suite then updates from different branches, removes a member, and proves
that the removed state cannot apply the next packet. Separate cases cover
tampering, stale updates, wrong Welcome keys, and immutable inputs.
