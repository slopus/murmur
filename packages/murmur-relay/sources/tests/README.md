# Package API tests

These tests protect the deliberately small root module surface. Domain tests use
deep internal imports so implementation helpers do not become public merely for
test convenience.

```text
domain modules -> sources/index.ts -> embedders and custom stores
```
