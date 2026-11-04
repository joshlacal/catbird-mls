#!/usr/bin/env python3
"""Receipt integrity tests with disposable byte fixtures; no native-build claim."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("manifest", Path(__file__).with_name("native-artifact-manifest.py"))
manifest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manifest)


class ReceiptIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.inputs = {"features": "labyrinth", "native_source_revision": "a" * 40, "extra_pipeline_inputs": {"wrapper.sh": "fixture-hash"}}
        self.receipt = {"schema": 1, "build_id": "test-only", "inputs": self.inputs,
                        "inputs_sha256": manifest.digest_json(self.inputs), "kind": "android"}
        self.path = self.root / "receipt.json"
        self.make_files(sorted(manifest.ANDROID_ABIS))

    def make_files(self, abis):
        paths = ["src/main/kotlin/blue/catbird/mls/catbird_mls.kt"]
        paths += [f"src/main/jniLibs/{abi}/libcatbird_mls.so" for abi in abis]
        for relative in paths:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f"Disposable integrity fixture: {relative}".encode())
        self.receipt["abis"] = abis
        self.receipt["artifacts"] = manifest.android_files(self.root, abis)
        self.save()

    def save(self):
        manifest.write_json(self.path, self.receipt)

    def verify(self):
        args = ["manifest", "verify-android", "--manifest", str(self.path), "--root", str(self.root), "--require-complete"]
        with patch.object(sys, "argv", args), patch.object(manifest, "capture_inputs", return_value=self.inputs):
            manifest.main()

    def test_complete_matching_receipt_passes(self):
        self.verify()

    def test_partial_bundle_cannot_be_stamped_complete(self):
        self.make_files(["arm64-v8a"])
        with self.assertRaisesRegex(ValueError, "all four ABIs"):
            self.verify()

    def test_modified_native_output_rejected(self):
        path = self.root / "src/main/jniLibs/x86/libcatbird_mls.so"
        path.write_bytes(b"Modified disposable bytes")
        with self.assertRaisesRegex(ValueError, "packaged files"):
            self.verify()

    def test_modified_kotlin_rejected(self):
        path = self.root / "src/main/kotlin/blue/catbird/mls/catbird_mls.kt"
        path.write_bytes(b"Modified disposable binding bytes")
        with self.assertRaisesRegex(ValueError, "packaged files"):
            self.verify()

    def test_source_or_pipeline_drift_rejected(self):
        changed = copy.deepcopy(self.inputs)
        changed["extra_pipeline_inputs"]["wrapper.sh"] = "changed-fixture-hash"
        with patch.object(manifest, "capture_inputs", return_value=changed):
            with self.assertRaisesRegex(ValueError, "inputs changed"):
                manifest.verify_inputs(self.receipt)

    def test_tampered_input_record_rejected(self):
        changed = copy.deepcopy(self.receipt)
        changed["inputs"]["features"] = "different"
        with self.assertRaisesRegex(ValueError, "modified native input receipt"):
            manifest.verify_inputs(changed)

    def test_unknown_source_revision_rejected(self):
        self.receipt["inputs"]["native_source_revision"] = "unknown"
        self.receipt["inputs_sha256"] = manifest.digest_json(self.inputs)
        with self.assertRaisesRegex(ValueError, "exact source revision"):
            manifest.verify_inputs(self.receipt)

    def test_duplicate_or_unknown_abi_rejected(self):
        for abis in [[], ["arm64-v8a", "arm64-v8a"], ["../other"]]:
            with self.assertRaisesRegex(ValueError, "nonempty, unique, and supported"):
                manifest.android_files(self.root, abis)

    def test_postprocessing_retains_parent_and_tool_identity(self):
        parent_hash = manifest.digest_file(self.path)
        tool = self.root / "strip-fixture"
        tool.write_bytes(b"Disposable tool fixture")
        output = self.root / "packaged.json"
        args = ["manifest", "record-android-postprocess", "--manifest", str(self.path), "--root", str(self.root), "--tool", str(tool), "--output", str(output)]
        with patch.object(sys, "argv", args), patch.object(manifest, "capture_inputs", return_value=self.inputs):
            manifest.main()
        receipt = json.loads(output.read_text())
        self.assertEqual(receipt["postprocessing"]["parent_manifest_sha256"], parent_hash)
        self.assertEqual(receipt["postprocessing"]["tool_sha256"], manifest.digest_file(tool))
        self.assertEqual(receipt["inputs_sha256"], self.receipt["inputs_sha256"])


if __name__ == "__main__":
    unittest.main()
