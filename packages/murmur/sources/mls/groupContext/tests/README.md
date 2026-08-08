# Group context tests

Coverage for RFC wire encoding, transcript transitions, and confirmation tags.

```text
encoded context -> decode/encode equality
prior transcript + Commit -> next confirmed hash
confirmation key + hash --> expected tag -> next interim hash
```

The vectors ensure every member feeds byte-identical context into the epoch key
schedule.
