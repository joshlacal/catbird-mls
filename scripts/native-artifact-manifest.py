#!/usr/bin/env python3
"""Bind native outputs to the exact locked source inputs of one build.

Schema 2 hashes checkout-independent content identity; local paths are retained
only under ``diagnostics``. This is a reproducibility receipt, not a signature
or a claim of runtime safety. Partial Android builds remain partial: their ABI
set is explicit and consumers requiring the complete bundle must reject them.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tomllib
import uuid


ROOT = Path(__file__).resolve().parents[1]
ANDROID_ABIS = {"arm64-v8a", "armeabi-v7a", "x86", "x86_64"}


def digest_bytes(value):
    return hashlib.sha256(value).hexdigest()


def digest_file(path):
    return digest_bytes(Path(path).read_bytes())


def digest_json(value):
    return digest_bytes(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def run(*args, cwd=ROOT):
    return subprocess.check_output(args, cwd=cwd, text=True).strip()


def inherited_workspace_files(directory):
    for parent in directory.parents:
        manifest = parent / "Cargo.toml"
        if manifest.is_file() and "workspace" in tomllib.loads(manifest.read_text()):
            return {parent / name for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml")
                    if (parent / name).is_file()}
    return set()


def external_build_options():
    names = {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CFLAGS", "CXXFLAGS", "CPPFLAGS",
             "LDFLAGS", "CC", "CXX", "AR", "RANLIB", "CMAKE_POLICY_VERSION_MINIMUM",
             "OPENSSL_DIR", "OPENSSL_LIB_DIR", "OPENSSL_INCLUDE_DIR", "OPENSSL_STATIC"}
    prefixes = ("CFLAGS_", "CXXFLAGS_", "CPPFLAGS_", "CC_", "CXX_", "AR_", "RANLIB_")
    return {name: value for name, value in sorted(os.environ.items())
            if name in names or name.startswith(prefixes)
            or (name.startswith("CARGO_TARGET_") and name.endswith(("_LINKER", "_RUSTFLAGS")))}


def exact_source_identity(diagnostics):
    revision_pattern = r"(?:[a-f0-9]{40}|[a-f0-9]{64})"
    if shutil.which("jj"):
        try:
            revision = run(
                "jj", "log", "--no-graph", "-r", "latest(::@ & ~empty())", "-T", "commit_id"
            )
            commit = run("git", "rev-parse", f"{revision}^{{commit}}")
            tree = run("git", "rev-parse", f"{revision}^{{tree}}")
            if re.fullmatch(revision_pattern, revision) and commit == revision \
                    and re.fullmatch(revision_pattern, tree):
                diagnostics["vcs"] = "jj"
                return revision, tree
        except (OSError, subprocess.CalledProcessError):
            pass
    if run("git", "status", "--porcelain=v1", "--untracked-files=all",
           "--ignore-submodules=none"):
        raise ValueError("ordinary Git checkout must be clean")
    revision = run("git", "rev-parse", "HEAD^{commit}")
    tree = run("git", "rev-parse", "HEAD^{tree}")
    if re.fullmatch(revision_pattern, revision) is None \
            or re.fullmatch(revision_pattern, tree) is None:
        raise ValueError("native source must have an exact Git commit and tree")
    diagnostics["vcs"] = "git"
    return revision, tree


def parse_extra_inputs(specs):
    result = {}
    for spec in specs:
        if "=" not in spec:
            raise ValueError("--extra-input must be a stable label followed by '=PATH'")
        label, raw_path = spec.split("=", 1)
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", label) is None \
                or label.startswith("/") or ".." in label.split("/"):
            raise ValueError(f"invalid extra-input label: {label!r}")
        if label in result:
            raise ValueError(f"duplicate extra-input label: {label}")
        result[label] = Path(raw_path).resolve()
    return result


def package_identity(package):
    source = package["source"] or "path"
    return f"{source}#{package['name']}@{package['version']}"


def capture_inputs(features, extra_inputs=(), diagnostics=None):
    diagnostics = {} if diagnostics is None else diagnostics
    command = ["cargo", "metadata", "--format-version", "1", "--locked"]
    if features:
        command += ["--features", features]
    metadata = json.loads(run(*command))
    packages = []
    package_ids = {}
    package_paths = {}
    for package in metadata["packages"]:
        stable_id = package_identity(package)
        if stable_id in package_ids.values():
            raise ValueError(f"ambiguous package identity: {stable_id}")
        package_ids[package["id"]] = stable_id
        if package["source"] is not None:
            continue
        manifest = Path(package["manifest_path"])
        directory = manifest.parent
        files = {manifest} | inherited_workspace_files(directory)
        for name in ("build.rs", "uniffi.toml", "rust-toolchain.toml", "Cargo.lock"):
            if (directory / name).is_file():
                files.add(directory / name)
        for name in ("src", ".cargo", "opus"):
            if (directory / name).exists():
                files.update(p for p in (directory / name).rglob("*") if p.is_file())
        packages.append({
            "name": package["name"],
            "version": package["version"],
            "files": {os.path.relpath(p, directory): digest_file(p) for p in sorted(files)},
        })
        package_paths[stable_id] = str(manifest)
    revision, tree = exact_source_identity(diagnostics)
    lock = ROOT / "Cargo.lock"
    versions = {p["version"] for p in tomllib.loads(lock.read_text())["package"]
                if p["name"] == "uniffi"}
    if len(versions) != 1:
        raise ValueError("expected one coherent UniFFI version")
    labeled_extras = parse_extra_inputs(extra_inputs)
    diagnostics.update({
        "native_source_root": str(ROOT),
        "path_package_manifests": package_paths,
        "extra_pipeline_inputs": {label: str(path) for label, path in labeled_extras.items()},
    })
    return {
        "native_source_revision": revision,
        "native_source_tree": tree,
        "features": features,
        "uniffi_version": versions.pop(),
        "rustc": run(os.environ.get("RUSTC", "rustc"), "--version", "--verbose"),
        "cargo": run("cargo", "--version"),
        "external_build_options": external_build_options(),
        "cargo_lock_sha256": digest_file(lock),
        "binding_config_sha256": digest_file(ROOT / "uniffi.toml"),
        "extra_pipeline_inputs": {
            label: digest_file(path) for label, path in sorted(labeled_extras.items())
        },
        "pipeline_inputs": {str(p.relative_to(ROOT)): digest_file(p) for p in sorted([
            ROOT / "build-android.sh", ROOT / "create-xcframework.sh",
            ROOT / "scripts/native-artifact-manifest.py",
        ])},
        "path_packages": sorted(packages, key=lambda p: (p["name"], p["version"])),
        "resolved_features": {
            package_ids[node["id"]]: node["features"] for node in metadata["resolve"]["nodes"]
        },
    }


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def current_extra_inputs(receipt, root, overrides=()):
    expected = set(receipt.get("inputs", {}).get("extra_pipeline_inputs", {}))
    explicit = parse_extra_inputs(overrides)
    if explicit:
        if set(explicit) != expected:
            raise ValueError("current extra pipeline inputs do not match the receipt labels")
        return [f"{label}={path}" for label, path in sorted(explicit.items())]

    recorded = receipt.get("diagnostics", {}).get("extra_pipeline_inputs", {})
    resolved = {}
    for label in expected:
        if label.startswith("android-module/") and root is not None:
            path = Path(root) / label.removeprefix("android-module/")
        else:
            raw_path = recorded.get(label)
            if raw_path is None:
                raise ValueError(f"current path required for extra pipeline input: {label}")
            path = Path(raw_path)
        resolved[label] = path.resolve()
    return [f"{label}={path}" for label, path in sorted(resolved.items())]


def verify_inputs(receipt, extra_inputs=(), root=None):
    inputs = receipt.get("inputs", {})
    if receipt.get("schema") != 2 or digest_json(inputs) != receipt.get("inputs_sha256"):
        raise ValueError("invalid or modified native input receipt")
    revision_pattern = r"(?:[a-f0-9]{40}|[a-f0-9]{64})"
    if re.fullmatch(revision_pattern, inputs.get("native_source_revision", "")) is None \
            or re.fullmatch(revision_pattern, inputs.get("native_source_tree", "")) is None:
        raise ValueError("native input receipt lacks an exact source commit and tree")
    current = capture_inputs(
        inputs["features"], current_extra_inputs(receipt, root, extra_inputs)
    )
    if digest_json(current) != receipt["inputs_sha256"]:
        raise ValueError("native build inputs changed after capture; rebuild before stamping outputs")


def android_files(root, abis):
    if not abis or len(set(abis)) != len(abis) or not set(abis) <= ANDROID_ABIS:
        raise ValueError("Android ABI list must be nonempty, unique, and supported")
    paths = [Path("src/main/kotlin/blue/catbird/mls/catbird_mls.kt")]
    paths += [Path(f"src/main/jniLibs/{abi}/libcatbird_mls.so") for abi in abis]
    result = {}
    for relative in paths:
        path = root / relative
        if not path.is_file():
            raise ValueError(f"missing build output: {path}")
        result[str(relative)] = {"sha256": digest_file(path), "bytes": path.stat().st_size}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    capture = sub.add_parser("capture")
    capture.add_argument("--features", default="")
    capture.add_argument("--output", required=True)
    capture.add_argument("--extra-input", action="append", default=[])
    finish = sub.add_parser("finish-android")
    finish.add_argument("--inputs", required=True)
    finish.add_argument("--root", required=True)
    finish.add_argument("--abis", nargs="+", required=True)
    finish.add_argument("--extra-input", action="append", default=[])
    finish.add_argument("--output", required=True)
    verify = sub.add_parser("verify-android")
    verify.add_argument("--manifest", required=True)
    verify.add_argument("--root", required=True)
    verify.add_argument("--require-complete", action="store_true")
    verify.add_argument("--extra-input", action="append", default=[])
    postprocess = sub.add_parser("record-android-postprocess")
    postprocess.add_argument("--manifest", required=True)
    postprocess.add_argument("--root", required=True)
    postprocess.add_argument("--tool", required=True)
    postprocess.add_argument("--extra-input", action="append", default=[])
    postprocess.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.command == "capture":
        diagnostics = {}
        inputs = capture_inputs(args.features, args.extra_input, diagnostics)
        write_json(args.output, {
            "schema": 2,
            "build_id": str(uuid.uuid4()),
            "inputs": inputs,
            "inputs_sha256": digest_json(inputs),
            "diagnostics": diagnostics,
        })
        return
    if args.command == "finish-android":
        receipt = json.loads(Path(args.inputs).read_text())
        verify_inputs(receipt, args.extra_input)
        receipt.update(kind="android", abis=sorted(args.abis), artifacts=android_files(Path(args.root), args.abis))
        write_json(args.output, receipt)
        return
    receipt = json.loads(Path(args.manifest).read_text())
    if receipt.get("kind") != "android":
        raise ValueError("not an Android build receipt")
    verify_inputs(receipt, args.extra_input, args.root)
    if args.command == "verify-android":
        if args.require_complete and set(receipt["abis"]) != ANDROID_ABIS:
            raise ValueError("complete Android bundle requires all four ABIs from this build")
        if android_files(Path(args.root), receipt["abis"]) != receipt["artifacts"]:
            raise ValueError("packaged files do not match this build receipt")
        return
    parent = {key: value for key, value in receipt.items()
              if key not in {"diagnostics", "postprocessing"}}
    receipt["postprocessing"] = {
        "parent_content_sha256": digest_json(parent),
        "tool_sha256": digest_file(args.tool),
    }
    receipt.setdefault("diagnostics", {})["postprocess_tool"] = str(Path(args.tool).resolve())
    receipt["artifacts"] = android_files(Path(args.root), receipt["abis"])
    write_json(args.output, receipt)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"native-artifact-manifest: {error}", file=sys.stderr)
        raise SystemExit(1) from error
