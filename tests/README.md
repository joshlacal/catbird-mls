# MLS FFI Test Suite

This directory contains comprehensive tests for the MLS FFI layer to isolate and diagnose issues.

## Test Files

### `two_user_messaging_test.rs`

Tests the two-user rapid messaging scenario to isolate whether SecretReuseError is an OpenMLS bug or an FFI bug.

**Status**: ✅ All tests PASS - OpenMLS 0.7.1 works correctly

**Tests included**:
1. `test_two_user_rapid_messaging` - Core scenario reproducing production bug flow
2. `test_two_user_multiple_messages` - 5 rounds of rapid message exchange
3. `test_two_user_out_of_order_messages` - Out-of-order message delivery handling

**Configuration**:
- Ciphersuite: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`
- Provider: `OpenMlsRustCrypto` (in-memory storage)
- Credentials: Basic credentials

**Run all tests**:
```bash
cargo test --test two_user_messaging_test -- --nocapture
```

**Run specific test**:
```bash
cargo test --test two_user_messaging_test test_two_user_rapid_messaging -- --nocapture
```

**Run in quiet mode**:
```bash
cargo test --test two_user_messaging_test --quiet
```

**Run with single thread** (for deterministic output):
```bash
cargo test --test two_user_messaging_test -- --nocapture --test-threads=1
```

### `persistence_repro.rs`

Tests persistence and deserialization scenarios to verify group state is correctly preserved across restarts.

**Status**: ✅ All tests PASS

**Tests included**:
1. `test_creator_can_decrypt_after_restart` - Verify group creator can decrypt after restart
2. `test_both_sides_can_decrypt_after_restart` - Both users can decrypt after restart
3. `test_serialize_at_different_stages` - Serialization at various lifecycle stages

**Run all tests**:
```bash
cargo test --test persistence_repro -- --nocapture
```

## Test Results Summary

### Two-User Messaging Tests

```
running 3 tests
test test_two_user_rapid_messaging ... ok
test test_two_user_multiple_messages ... ok
test test_two_user_out_of_order_messages ... ok

test result: ok. 3 passed; 0 failed; 0 ignored
```

**Key Finding**: OpenMLS 0.7.1 correctly handles concurrent messaging without SecretReuseError. The bug is in the FFI layer, not OpenMLS.

## Debugging Tips

### Enable Logging

Tests use `env_logger`. Set `RUST_LOG` environment variable for detailed logging:

```bash
RUST_LOG=debug cargo test --test two_user_messaging_test -- --nocapture
```

Log levels:
- `error` - Only errors
- `warn` - Warnings and errors
- `info` - Info, warnings, and errors
- `debug` - Debug info and above
- `trace` - All logging (very verbose)

### Filter Specific Tests

```bash
# Run only rapid messaging test
cargo test --test two_user_messaging_test rapid_messaging -- --nocapture

# Run all tests with "two_user" in the name
cargo test two_user -- --nocapture
```

### Generate Test Coverage

```bash
# Install cargo-tarpaulin if not already installed
cargo install cargo-tarpaulin

# Generate coverage report
cargo tarpaulin --test two_user_messaging_test --out Html
```

## Understanding Test Output

### Epoch Tracking

Tests display epoch numbers at each step:
```
✅ Step 1: Alice created group at epoch 0
✅ Step 3: Alice merged pending commit
   Alice now at epoch 1
```

### Sender Chain Information

Tests log sender chain generation numbers:
```
✅ Step 4: Alice created application message
   Alice sender chain generation: (should be 0 for first message)
```

### Message Content

Successful message decryption shows the content:
```
✅ Step 6: Bob successfully decrypted Alice's message
   Message content: "Hello Bob from Alice!"
```

## CI/CD Integration

### GitHub Actions Example

```yaml
- name: Run MLS Tests
  run: |
    cd Catbird/MLS/mls-ffi
    cargo test --test two_user_messaging_test -- --nocapture
    cargo test --test persistence_repro -- --nocapture
```

### Local Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit
cd Catbird/MLS/mls-ffi
cargo test --test two_user_messaging_test --quiet || exit 1
cargo test --test persistence_repro --quiet || exit 1
```

## Further Reading

- **Test Results**: `docs/TWO_USER_MESSAGING_TEST_RESULTS.md` - Detailed analysis of test findings
- **OpenMLS Docs**: https://openmls.tech/ - Official OpenMLS documentation
- **RFC 9420**: https://datatracker.ietf.org/doc/rfc9420/ - MLS Protocol specification

## Troubleshooting

### Test Compilation Errors

If you see compilation errors, ensure you have the correct Rust toolchain:

```bash
rustc --version  # Should be 1.70+
cargo --version
```

### Test Failures

If tests fail:

1. Check OpenMLS version in `Cargo.toml` (should be 0.7.1)
2. Clean and rebuild: `cargo clean && cargo test`
3. Check for environment issues: `cargo test -- --nocapture` for full output
4. Review test logs for specific error messages

### Performance Issues

Tests should complete in under 1 second. If slower:

1. Ensure running in release mode: `cargo test --release`
2. Check system resources: `top` or Activity Monitor
3. Reduce test parallelism: `-- --test-threads=1`

## Contributing

When adding new tests:

1. Follow existing test patterns and naming conventions
2. Include detailed logging with `println!` statements
3. Use descriptive test names: `test_scenario_expected_outcome`
4. Document test purpose and expected behavior
5. Update this README with new test information

## License

Part of the Catbird MLS FFI project. See main project LICENSE.
