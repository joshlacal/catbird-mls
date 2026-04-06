#!/usr/bin/env python3
"""Smoke test for catbird-mls Python bindings."""
import sys
import os

# Add build output to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'build', 'python'))

def test_import():
    """Verify the bindings can be imported."""
    try:
        import catbird_mls
        print("✅ catbird_mls module imported successfully")
        return True
    except ImportError as e:
        print(f"❌ Failed to import catbird_mls: {e}")
        return False

def test_types_available():
    """Verify key types are available."""
    import catbird_mls

    expected_types = [
        'CatbirdMls',
        'Conversation',
        'ChatMessage',
        'FfiOrchestratorConfig',
    ]

    missing = []
    for t in expected_types:
        if not hasattr(catbird_mls, t):
            missing.append(t)

    if missing:
        print(f"⚠️  Missing types: {missing}")
        return False

    print(f"✅ All {len(expected_types)} expected types found")
    return True

if __name__ == '__main__':
    results = [test_import()]
    if results[0]:
        results.append(test_types_available())

    if all(results):
        print("\n✅ All smoke tests passed!")
        sys.exit(0)
    else:
        print("\n❌ Some smoke tests failed")
        sys.exit(1)
