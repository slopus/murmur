# Code organization

Taken from Rig's code organization plan; the same rules apply here.

## Big picture

An ideal project makes it obvious where to go when reading or changing a
particular piece of behavior. Its source code lives in `sources`. An executable
starts from `sources/main.ts`; a package that is exported starts from
`sources/index.ts`.

Murmur does not use top-level await. An executable will therefore usually define
an asynchronous `main` function and invoke it immediately.

## Domain modules

Code is organized into modules by domain. The boundary is practical rather than
rigid: everything concerned with keys, ratchets, and encryption belongs in
`crypto`; reaching a peer over a wire belongs in `transport`; the relay's own
behavior belongs in `relay`; profiles and contacts belong in `identity`. The goal
is that someone working on a domain knows which module to open and finds all of
that domain's behavior there.

Modules may call one another. Their dependencies should preferably form a rough
tree, with higher-level modules calling lower-level ones, but this is not a folder
hierarchy to model or enforce. Keep the domain modules where they naturally
belong.

## Utilities

The `utils` directory holds self-contained, non-domain-specific functions that
need no surrounding infrastructure. They do not have to be trivial. A base64
codec that fits coherently in one file, or a function that computes a hash,
belongs in `utils`: either can be used anywhere and does not constitute a domain
of its own.

When such functionality grows into a subsystem with several related operations or
its own infrastructure, it becomes a module. Hashing may remain a utility, while a
growing collection of cryptographic behavior belongs in a `crypto` module.

## Module shape

A module will commonly have an `index.ts` and a `types.ts`. Its top level holds
the important functions, classes, and entry points that it exports or that a
reader needs in order to understand what the module does. This does not require
inventing a facade: a `transport` or `relay` module may simply expose useful
operations, while a `session` module may expose several classes and functions.

Everything below that level belongs in an `impl` directory. `impl` holds
secondary work and small mechanical helpers that are not important when first
reading the program. It does not need an elaborate internal hierarchy or a strict
file order, but its files must be named predictably. Prefer the entity first and
the operation second, as in `topicCreateDescriptor.ts`, following the same naming
style as persistence operations so related files sort together.

## Tests

Tests stay close to the implementation they cover, but they are not colocated
with source files. They live in a `tests` subdirectory at the corresponding
level. A module's top-level behavior is tested in its `tests` directory, and code
inside `impl` is tested in `impl/tests`.

## Documentation

Every directory has a `README.md` that explains what the directory contains and
how it works. It includes ASCII diagrams and any other context needed to
understand the structure and behavior.

## Change discipline

Before every commit, the model runs the formatter and includes every resulting
formatting change in the commit. This applies to every file, including files in
`master-plans`; formatting changes are not left out because they fall outside the
main code change.

Do not refactor or reorganize existing code unless the user asks for it. The
distinction between modules and `utils` guides where new code goes; it is not a
reason to move existing code between them opportunistically.

## What done looks like

- Source code lives in `sources`, with `main.ts` as an executable entry point or
  `index.ts` as an exported package entry point.
- Executables avoid top-level await and normally invoke an asynchronous `main`
  function immediately.
- Each domain has an obvious module containing all of its related behavior.
- Self-contained, non-domain-specific functions live in `utils`, and move into a
  domain module only when they grow into a subsystem.
- A module's top level reveals its important public shape, while secondary
  implementation details live in `impl`.
- Files in `impl` have predictable entity-then-operation names without an
  artificial folder hierarchy.
- Tests live in nearby `tests` subdirectories rather than beside source files,
  including a separate `impl/tests` for implementation details.
- Module dependencies remain as tree-like as practical without turning that
  dependency structure into nested directories.
- Every directory has a `README.md` that explains how it works, with ASCII
  diagrams and supporting context.
- Every commit includes all formatter output, while refactoring happens only when
  the user requests it.
