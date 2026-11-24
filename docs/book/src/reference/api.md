# API reference (rustdoc)

The Rust API documentation is generated with `cargo doc` and published next to this book:

- [`catbird_mls`](../api/catbird_mls/index.html)

Start with `client::CatbirdMlsClient`, `client::traits` and `error::MLSError`. Swift and Kotlin names follow from the Rust names (camelCase in Swift).

The pages are built with the default features. The legacy engine (`orchestrator`, `engine`) is not public in that build.

Locally:

```bash
cargo doc --no-deps --open
```
