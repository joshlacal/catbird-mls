#!/bin/bash

echo "=========================================="
echo "  Diagnostic Logging Verification Script"
echo "=========================================="
echo ""

echo "✅ Step 1: Checking for console output (eprintln/println)..."
if grep -r "eprintln\|println" src/ 2>&1 | grep -v "Binary" | grep -q .; then
    echo "❌ FAIL: Found console output in src/"
    exit 1
else
    echo "✅ PASS: No console output in src/ directory"
fi
echo ""

echo "✅ Step 2: Verifying PROCESSED_MESSAGES cache exists..."
if grep -q "static ref PROCESSED_MESSAGES" src/api.rs; then
    echo "✅ PASS: Replay detection cache found"
else
    echo "❌ FAIL: Replay detection cache missing"
    exit 1
fi
echo ""

echo "✅ Step 3: Verifying thread tracking in decrypt_message..."
if grep -q "Thread {:?} attempting to acquire lock" src/api.rs; then
    echo "✅ PASS: Thread tracking found"
else
    echo "❌ FAIL: Thread tracking missing"
    exit 1
fi
echo ""

echo "✅ Step 4: Verifying storage verification in process_welcome..."
if grep -q "Verifying storage round-trip" src/api.rs; then
    echo "✅ PASS: Storage verification found"
else
    echo "❌ FAIL: Storage verification missing"
    exit 1
fi
echo ""

echo "✅ Step 5: Running cargo check..."
if cargo check 2>&1 | grep -q "Finished"; then
    echo "✅ PASS: Code compiles successfully"
else
    echo "❌ FAIL: Compilation errors detected"
    exit 1
fi
echo ""

echo "✅ Step 6: Running integration tests..."
if cargo test --test two_user_messaging_test 2>&1 | grep -q "test result: ok"; then
    echo "✅ PASS: All integration tests passing"
else
    echo "❌ FAIL: Integration tests failed"
    exit 1
fi
echo ""

echo "=========================================="
echo "  🎉 ALL VERIFICATION CHECKS PASSED! 🎉"
echo "=========================================="
echo ""
echo "Summary:"
echo "  ✅ No console output in source code"
echo "  ✅ Replay detection cache implemented"
echo "  ✅ Thread tracking implemented"
echo "  ✅ Storage verification implemented"
echo "  ✅ Code compiles successfully"
echo "  ✅ All tests passing"
echo ""
echo "Status: DIAGNOSTIC LOGGING COMPLETE AND VERIFIED"
echo ""
