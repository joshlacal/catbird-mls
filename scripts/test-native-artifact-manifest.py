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
        self.wrapper = self.root / "wrapper.sh"
        self.wrapper.write_bytes(b"Disposable pipeline wrapper")
        self.inputs = {
            "features": "labyrinth",
            "native_source_revision": "a" * 40,
            "native_source_tree": "b" * 40,
            "extra_pipeline_inputs": {"wrapper.sh": manifest.digest_file(self.wrapper)},
        }
        self.receipt = {
            "schema": 2,
            "build_id": "test-only",
            "inputs": self.inputs,
            "inputs_sha256": manifest.digest_json(self.inputs),
            "kind": "android",
            "diagnostics": {"extra_pipeline_inputs": {"wrapper.sh": str(self.wrapper)}},
        }
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
        changed["native_source_tree"] = "c" * 40
        with patch.object(manifest, "capture_inputs", return_value=changed):
            with self.assertRaisesRegex(ValueError, "inputs changed"):
                manifest.verify_inputs(self.receipt)

    def test_extra_pipeline_input_drift_rejected(self):
        self.wrapper.write_bytes(b"Changed pipeline wrapper")
        changed = copy.deepcopy(self.inputs)
        changed["extra_pipeline_inputs"]["wrapper.sh"] = manifest.digest_file(self.wrapper)
        with patch.object(manifest, "capture_inputs", return_value=changed) as capture:
            with self.assertRaisesRegex(ValueError, "inputs changed"):
                manifest.verify_inputs(self.receipt)
        self.assertEqual(
            capture.call_args.args[1], [f"wrapper.sh={self.wrapper.resolve()}"]
        )

    def test_android_module_input_uses_relocated_root(self):
        relocated = self.root / "relocated"
        relocated.mkdir()
        current = relocated / "regenerate.sh"
        current.write_bytes(b"Current wrapper")
        self.inputs["extra_pipeline_inputs"] = {
            "android-module/regenerate.sh": manifest.digest_file(current)
        }
        self.receipt["inputs_sha256"] = manifest.digest_json(self.inputs)
        self.receipt["diagnostics"]["extra_pipeline_inputs"] = {
            "android-module/regenerate.sh": "/old/checkout/regenerate.sh"
        }
        with patch.object(manifest, "capture_inputs", return_value=self.inputs) as capture:
            manifest.verify_inputs(self.receipt, root=relocated)
        self.assertEqual(
            capture.call_args.args[1],
            [f"android-module/regenerate.sh={current.resolve()}"],
        )

    def test_tampered_input_record_rejected(self):
        changed = copy.deepcopy(self.receipt)
        changed["inputs"]["features"] = "different"
        with self.assertRaisesRegex(ValueError, "modified native input receipt"):
            manifest.verify_inputs(changed)

    def test_unknown_source_revision_rejected(self):
        self.receipt["inputs"]["native_source_revision"] = "unknown"
        self.receipt["inputs_sha256"] = manifest.digest_json(self.inputs)
        with self.assertRaisesRegex(ValueError, "exact source"):
            manifest.verify_inputs(self.receipt)

    def test_duplicate_or_unknown_abi_rejected(self):
        for abis in [[], ["arm64-v8a", "arm64-v8a"], ["../other"]]:
            with self.assertRaisesRegex(ValueError, "nonempty, unique, and supported"):
                manifest.android_files(self.root, abis)

    def test_postprocessing_retains_parent_and_tool_identity(self):
        parent_hash = manifest.digest_json({
            key: value for key, value in self.receipt.items()
            if key not in {"diagnostics", "postprocessing"}
        })
        tool = self.root / "strip-fixture"
        tool.write_bytes(b"Disposable tool fixture")
        output = self.root / "packaged.json"
        args = ["manifest", "record-android-postprocess", "--manifest", str(self.path),
                "--root", str(self.root), "--tool", str(tool), "--output", str(output)]
        with patch.object(sys, "argv", args), \
                patch.object(manifest, "capture_inputs", return_value=self.inputs):
            manifest.main()
        receipt = json.loads(output.read_text())
        self.assertEqual(receipt["postprocessing"]["parent_content_sha256"], parent_hash)
        self.assertEqual(receipt["postprocessing"]["tool_sha256"], manifest.digest_file(tool))
        self.assertNotIn("tool", receipt["postprocessing"])
        self.assertEqual(receipt["diagnostics"]["postprocess_tool"], str(tool.resolve()))
        self.assertEqual(receipt["inputs_sha256"], self.receipt["inputs_sha256"])

    def test_content_identity_survives_checkout_relocation(self):
        def checkout(name):
            root = self.root / name
            (root / ".jj").mkdir(parents=True)
            crate = root / "crate"
            (crate / "src").mkdir(parents=True)
            (root / "scripts").mkdir()
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["crate"]\nresolver = "2"\n'
            )
            (root / "Cargo.lock").write_text(
                'version = 3\n\n[[package]]\nname = "uniffi"\nversion = "0.29.4"\n'
            )
            (root / "uniffi.toml").write_text("[bindings.kotlin]\n")
            (root / "build-android.sh").write_text("fixture build\n")
            (root / "create-xcframework.sh").write_text("fixture xcframework\n")
            (root / "scripts/native-artifact-manifest.py").write_text("fixture receipt\n")
            (root / "wrapper").write_text("fixture wrapper\n")
            (crate / "Cargo.toml").write_text(
                '[package]\nname = "fixture"\nversion = "0.1.0"\n'
            )
            (crate / "src/lib.rs").write_text("pub fn fixture() {}\n")
            package_id = f"path+file://{crate}#fixture@0.1.0"
            metadata = {
                "packages": [{
                    "id": package_id,
                    "name": "fixture",
                    "version": "0.1.0",
                    "source": None,
                    "manifest_path": str(crate / "Cargo.toml"),
                }],
                "resolve": {"nodes": [{"id": package_id, "features": ["default"]}]},
            }
            return root, metadata

        def capture(root, metadata):
            def fake_run(*args, **_kwargs):
                if args[:2] == ("cargo", "metadata"):
                    return json.dumps(metadata)
                if args[:2] == ("jj", "log"):
                    return "a" * 40
                if args[:3] == ("jj", "git", "root"):
                    return str(root / ".git")
                if args[:2] == ("git", "--git-dir"):
                    return "a" * 40 if args[-1].endswith("^{commit}") else "b" * 40
                if args[0].endswith("rustc"):
                    return "rustc fixture"
                if args[:2] == ("cargo", "--version"):
                    return "cargo fixture"
                raise AssertionError(args)

            diagnostics = {}
            with patch.object(manifest, "ROOT", root), \
                    patch.object(manifest, "run", side_effect=fake_run), \
                    patch.object(manifest.shutil, "which", return_value="/fixture/jj"):
                inputs = manifest.capture_inputs(
                    "labyrinth", [f"wrapper={root / 'wrapper'}"], diagnostics
                )
            return inputs, diagnostics

        left_root, left_metadata = checkout("left")
        right_root, right_metadata = checkout("right")
        left, left_diagnostics = capture(left_root, left_metadata)
        right, right_diagnostics = capture(right_root, right_metadata)

        self.assertEqual(left, right)
        self.assertEqual(manifest.digest_json(left), manifest.digest_json(right))
        self.assertNotIn(str(left_root), json.dumps(left))
        self.assertNotIn(str(right_root), json.dumps(right))
        self.assertNotEqual(
            left_diagnostics["native_source_root"], right_diagnostics["native_source_root"]
        )
        self.assertNotEqual(
            left_diagnostics["extra_pipeline_inputs"]["wrapper"],
            right_diagnostics["extra_pipeline_inputs"]["wrapper"],
        )
        self.assertNotEqual(
            left_diagnostics["path_package_manifests"]["path#fixture@0.1.0"],
            right_diagnostics["path_package_manifests"]["path#fixture@0.1.0"],
        )

    def test_jj_only_checkout_uses_backend_git_commit_and_tree(self):
        root = self.root / "jj-only"
        (root / ".jj").mkdir(parents=True)
        backend = self.root / "backend.git"
        calls = []

        def fake_run(*args, **_kwargs):
            calls.append(args)
            if args[:2] == ("jj", "log"):
                return "a" * 40
            if args[:3] == ("jj", "git", "root"):
                return str(backend)
            if args[:3] == ("git", "--git-dir", str(backend)):
                return "a" * 40 if args[-1].endswith("^{commit}") else "b" * 40
            raise AssertionError(args)

        diagnostics = {}
        with patch.object(manifest, "ROOT", root), \
                patch.object(manifest, "run", side_effect=fake_run), \
                patch.object(manifest.shutil, "which", return_value="/fixture/jj"):
            revision, tree = manifest.exact_source_identity(diagnostics)
        self.assertEqual((revision, tree), ("a" * 40, "b" * 40))
        self.assertEqual(diagnostics["vcs"], "jj")
        self.assertIn(
            ("git", "--git-dir", str(backend), "rev-parse", f'{"a" * 40}^{{tree}}'),
            calls,
        )

    def test_jj_identity_failure_does_not_fall_back_to_git(self):
        root = self.root / "broken-jj"
        (root / ".jj").mkdir(parents=True)
        calls = []

        def fake_run(*args, **_kwargs):
            calls.append(args)
            raise OSError("unavailable Jujutsu store")

        with patch.object(manifest, "ROOT", root), \
                patch.object(manifest, "run", side_effect=fake_run), \
                patch.object(manifest.shutil, "which", return_value="/fixture/jj"):
            with self.assertRaisesRegex(ValueError, "exact Jujutsu commit and Git tree"):
                manifest.exact_source_identity({})
        self.assertFalse(any(args[0] == "git" for args in calls))

    def test_clean_git_only_checkout_has_exact_commit_and_tree(self):
        def fake_run(*args, **_kwargs):
            if args[:2] == ("git", "status"):
                return ""
            if args[:2] == ("git", "rev-parse"):
                return "c" * 40 if args[-1] == "HEAD^{commit}" else "d" * 40
            raise AssertionError(args)

        diagnostics = {}
        with patch.object(manifest, "ROOT", self.root), \
                patch.object(manifest.shutil, "which", return_value=None), \
                patch.object(manifest, "run", side_effect=fake_run):
            revision, tree = manifest.exact_source_identity(diagnostics)
        self.assertEqual(revision, "c" * 40)
        self.assertEqual(tree, "d" * 40)
        self.assertEqual(diagnostics["vcs"], "git")


if __name__ == "__main__":
    unittest.main()
