#!/usr/bin/env python3
"""Bind native outputs to the exact locked source inputs of one build.

This is a reproducibility receipt, not a signature or a claim of runtime safety.
Partial Android builds remain partial: their ABI set is explicit and consumers
requiring the complete bundle must reject them.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
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


def capture_inputs(features, extra_inputs=()):
    command = ["cargo", "metadata", "--format-version", "1", "--locked"]
    if features:
        command += ["--features", features]
    metadata = json.loads(run(*command))
    packages = []
    for package in metadata["packages"]:
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
            "name": package["name"], "version": package["version"],
            "manifest": str(manifest),
            "files": {os.path.relpath(p, directory): digest_file(p) for p in sorted(files)},
        })
    revision = run("jj", "log", "--no-graph", "-r", "latest(::@ & ~empty())", "-T", "commit_id")
    if re.fullmatch(r"[a-f0-9]{40}", revision) is None:
        raise ValueError("native source must have an exact jj revision")
    lock = ROOT / "Cargo.lock"
    versions = {p["version"] for p in tomllib.loads(lock.read_text())["package"] if p["name"] == "uniffi"}
    if len(versions) != 1:
        raise ValueError("expected one coherent UniFFI version")
    return {
        "native_source_revision": revision,
        "native_source_root": str(ROOT),
        "features": features,
        "uniffi_version": versions.pop(),
        "rustc": run(os.environ.get("RUSTC", "rustc"), "--version", "--verbose"),
        "cargo": run("cargo", "--version"),
        "external_build_options": external_build_options(),
        "cargo_lock_sha256": digest_file(lock),
        "binding_config_sha256": digest_file(ROOT / "uniffi.toml"),
        "extra_pipeline_inputs": {str(Path(p).resolve()): digest_file(p) for p in sorted(extra_inputs)},
        "pipeline_inputs": {str(p.relative_to(ROOT)): digest_file(p) for p in sorted([
            ROOT / "build-android.sh", ROOT / "create-xcframework.sh",
            ROOT / "scripts/native-artifact-manifest.py",
        ])},
        "path_packages": sorted(packages, key=lambda p: p["manifest"]),
        "resolved_features": {n["id"]: n["features"] for n in metadata["resolve"]["nodes"]},
    }


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def verify_inputs(receipt):
    if receipt.get("schema") != 1 or digest_json(receipt["inputs"]) != receipt["inputs_sha256"]:
        raise ValueError("invalid or modified native input receipt")
    if re.fullmatch(r"[a-f0-9]{40}", receipt["inputs"]["native_source_revision"]) is None:
        raise ValueError("native input receipt lacks an exact source revision")
    current = capture_inputs(receipt["inputs"]["features"], receipt["inputs"].get("extra_pipeline_inputs", {}))
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
    finish.add_argument("--output", required=True)
    verify = sub.add_parser("verify-android")
    verify.add_argument("--manifest", required=True)
    verify.add_argument("--root", required=True)
    verify.add_argument("--require-complete", action="store_true")
    postprocess = sub.add_parser("record-android-postprocess")
    postprocess.add_argument("--manifest", required=True)
    postprocess.add_argument("--root", required=True)
    postprocess.add_argument("--tool", required=True)
    postprocess.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.command == "capture":
        inputs = capture_inputs(args.features, args.extra_input)
        write_json(args.output, {"schema": 1, "build_id": str(uuid.uuid4()), "inputs": inputs, "inputs_sha256": digest_json(inputs)})
        return
    if args.command == "finish-android":
        receipt = json.loads(Path(args.inputs).read_text())
        verify_inputs(receipt)
        receipt.update(kind="android", abis=sorted(args.abis), artifacts=android_files(Path(args.root), args.abis))
        write_json(args.output, receipt)
        return
    receipt = json.loads(Path(args.manifest).read_text())
    if receipt.get("kind") != "android":
        raise ValueError("not an Android build receipt")
    verify_inputs(receipt)
    if args.command == "verify-android":
        if args.require_complete and set(receipt["abis"]) != ANDROID_ABIS:
            raise ValueError("complete Android bundle requires all four ABIs from this build")
        if android_files(Path(args.root), receipt["abis"]) != receipt["artifacts"]:
            raise ValueError("packaged files do not match this build receipt")
        return
    receipt["postprocessing"] = {"parent_manifest_sha256": digest_file(args.manifest), "tool": args.tool, "tool_sha256": digest_file(args.tool)}
    receipt["artifacts"] = android_files(Path(args.root), receipt["abis"])
    write_json(args.output, receipt)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"native-artifact-manifest: {error}", file=sys.stderr)
        raise SystemExit(1) from error
