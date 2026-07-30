# CLI sources

The executable starts in `main.ts`; `index.ts` exposes the programmatic Node
runtime. Domain modules keep durable storage, user-facing command parsing, and
encrypted messaging behavior separate.

```text
main.ts -> cli -> runtime -> @slopus/murmur + private MLS workspace
                    |
                 storage -> SQLite
```

The historical `src` tree is not part of the new build. It remains temporarily
for migration reference while the master-plan CLI surface is rebuilt here.
