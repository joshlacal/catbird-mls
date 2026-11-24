# The Swift package

Catbird's Apple apps use [`CatbirdMLSCore`](https://github.com/joshlacal/CatbirdMLSCore), a Swift package (Swift tools 6.0; iOS 18 and macOS 15) with three layers:

| Target | Contents |
|---|---|
| `CatbirdMLSFFI` | A binary target: the `CatbirdMLSFFI.xcframework` built from this crate, downloaded from the package's GitHub release and pinned by checksum in `Package.swift` |
| `CatbirdMLS` | The UniFFI-generated Swift bindings (`CatbirdMLS.swift`). Generated, never edited by hand. Compiled in Swift 5 language mode for UniFFI 0.28. |
| `CatbirdMLSCore` | Swift wrappers: `MLSClientCoordinator` (an observable wrapper that owns the client on a dedicated queue), `KeychainPlatformKeyStore`, `PetrelPlatformTransport` (built on the Petrel AT Protocol client), and the push-extension helpers |

## Using a local build

`Package.swift` uses a local XCFramework instead of the release if one is present in `Sources/` and carries a matching build manifest, or if `CATBIRD_MLS_FFI_PATH` points at one. `CATBIRD_MLS_LOCAL_INTEGRATION=1` also switches Petrel to sibling checkouts. `Scripts/rebuild-ffi.sh` rebuilds the framework from sibling repositories.

## Releases

A release of the binary is cut by three manually run workflows in `CatbirdMLSCore`:

1. **Build and Release FFI** (`build-ffi.yml`) checks out exact commits of every source repository, builds the XCFramework on macOS and verifies it.
2. **Inspect completed FFI artifact** (`ffi-artifact-handoff.yml`) re-checks that build and records its release metadata.
3. After `Package.swift` and `Scripts/ffi-release-inputs.json` are updated and tagged, **Publish verified FFI for existing final tag** (`publish-verified-ffi.yml`) publishes the same verified archive as the release. It never creates or moves the tag.

`Package.swift` refuses to resolve if its release tag or checksum disagree with `ffi-release-inputs.json`.
