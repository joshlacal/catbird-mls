#!/usr/bin/env python3
"""Generate and verify self-contained clean-chat contract artifacts.

The runtime crate deliberately consumes only the checked-in artifacts. This
script is the reproducible bridge from the canonical PetrelCatbird lexicon
and strict-server fixture sources; it records each source path, exact source
SHA-256, and generator revision in the artifact so a schema/vector drift
cannot be hidden by copied JSON files. The separate ``--check-mirror`` gate
proves that the mls-ds lexicon mirror is byte-identical after server regen.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


SOURCE_RELATIVE = Path(
    "PetrelCatbird/lexicons/blue/catbird/chat/blue.catbird.chat.defs.json"
)
MIRROR_RELATIVE = Path(
    "mls-ds/lexicon/blue/catbird/chat/blue.catbird.chat.defs.json"
)
FIXTURE_SOURCES = (
    (
        Path("mls-ds/server/tests/fixtures/mls_chat_control_fingerprint_source.json"),
        Path("src/orchestrator/generated/mls_chat_control_fingerprint_source.json"),
        13,
        "f33406a5d99dba3b604da108c4df2e53d70531b9fa0be14b21e2db94ba07b311",
    ),
    (
        Path("mls-ds/server/tests/fixtures/mls_chat_contract_vectors.json"),
        Path("src/orchestrator/generated/mls_chat_contract_vectors.json"),
        14,
        "96044be0c06e3dd43cbe77b7ac29c1ecfcee1922782b1c5e74258768b1aa3c6d",
    ),
    (
        Path("mls-ds/server/tests/fixtures/mls_chat_signing_domain_vectors.json"),
        Path("src/orchestrator/generated/mls_chat_signing_domain_vectors.json"),
        11,
        "40bd067558c98648a565cbd58a3e17cd4756da6df5428bd71dfce948182f0226",
    ),
)
ARTIFACT_RELATIVE = Path("src/orchestrator/generated/blue.catbird.chat.defs.json")
GENERATOR_NAME = "scripts/generate_chat_schema.py"
GENERATOR_VERSION = 7
PROVENANCE_KEY = "_catbird_mls_provenance"
CANONICAL_SOURCE_REVISION = "954d7ab20f362b731ee13f87eea89ae83558c624"
CANONICAL_SOURCE_TREE = "6779729a15bec425fa520b9197bf60bebdb9e32b"
CANONICAL_SOURCE_SHA256 = "88fb17ca9ca2bcc605c22123ba3ae801b2baf1f725afe85934680b5cd2f66c7a"
SERVER_SOURCE_REVISION = "1336d821566aacb93c3a580091518a6eb68ed63c"
SERVER_SOURCE_TREE = "5796505b80b76490f5ada54febe2d8439e1b00eb"
SERVER_VECTOR_SET = "signed-mutation"
SERVER_VECTOR_SET_COUNT = 25


def repository_root() -> Path:
    for parent in Path(__file__).resolve().parents:
        if (parent / "PetrelCatbird").is_dir() and (parent / "mls-ds").is_dir():
            return parent
    return Path(__file__).resolve().parents[2]


def source_path(value: str | Path | None) -> Path:
    return (repository_root() / (value or SOURCE_RELATIVE)).resolve()


def artifact_path(value: str | None) -> Path:
    return (Path(__file__).resolve().parents[1] / (value or ARTIFACT_RELATIVE)).resolve()


def load_source(path: Path, *, require_defs: bool = False) -> tuple[dict, str]:
    raw = path.read_bytes()
    source = json.loads(raw)
    if not isinstance(source, dict):
        raise ValueError(f"{path} is not a JSON object")
    if require_defs and not isinstance(source.get("defs"), dict):
        raise ValueError(f"{path} is not a defs lexicon object")
    digest = hashlib.sha256(raw).hexdigest()
    return source, digest


def read_vcs_revision(
    repository: Path,
    description: str,
    expected_revision: str,
    expected_tree: str,
) -> tuple[str, str]:
    try:
        revision = subprocess.run(
            ["git", "-C", str(repository), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        tree = subprocess.run(
            ["git", "-C", str(repository), "rev-parse", "HEAD^{tree}"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as error:
        raise ValueError(f"unable to inspect pinned {description} revision: {error}") from error
    if (revision, tree) != (expected_revision, expected_tree):
        raise ValueError(
            f"{description} revision is not the pinned source "
            f"(expected {expected_revision}/{expected_tree}, "
            f"found {revision}/{tree})"
        )
    return revision, tree


def canonical_revision() -> tuple[str, str]:
    return read_vcs_revision(
        repository_root() / "PetrelCatbird",
        "canonical PetrelCatbird",
        CANONICAL_SOURCE_REVISION,
        CANONICAL_SOURCE_TREE,
    )


def server_revision() -> tuple[str, str]:
    return read_vcs_revision(
        repository_root() / "mls-ds",
        "Sol-approved mls-ds",
        SERVER_SOURCE_REVISION,
        SERVER_SOURCE_TREE,
    )


def validate_canonical_source(path: Path) -> tuple[dict, str, str, str]:
    revision, tree = canonical_revision()
    source, digest = load_source(path, require_defs=True)
    if digest != CANONICAL_SOURCE_SHA256:
        raise ValueError(
            "canonical PetrelCatbird source SHA-256 does not match the pinned source "
            f"(expected {CANONICAL_SOURCE_SHA256}, found {digest})"
        )
    return source, digest, revision, tree


def fixture_case_count(source: dict, source_relative: Path) -> int:
    if source_relative.name == "mls_chat_contract_vectors.json":
        controls = source.get("controlEntryFingerprints", {}).get("cases")
        signed_mutator = source.get("signedMutator")
        if not isinstance(controls, list) or not isinstance(signed_mutator, dict):
            raise ValueError(f"{source_relative} does not contain the strict contract corpus")
        return len(controls) + 1
    cases = source.get("cases")
    if not isinstance(cases, list):
        raise ValueError(f"{source_relative} does not contain a vector cases array")
    return len(cases)


def expected_artifact(
    source: dict,
    digest: str,
    source_relative: Path,
    vector_case_count: int | None = None,
    source_revision: str | None = None,
    source_tree: str | None = None,
) -> bytes:
    artifact = dict(source)
    artifact[PROVENANCE_KEY] = {
        "sourcePath": source_relative.as_posix(),
        "sourceSha256": digest,
        "generator": GENERATOR_NAME,
        "generatorVersion": GENERATOR_VERSION,
    }
    if source_relative == SOURCE_RELATIVE:
        artifact[PROVENANCE_KEY].update(
            {
                "sourceRevision": source_revision or CANONICAL_SOURCE_REVISION,
                "sourceTree": source_tree or CANONICAL_SOURCE_TREE,
            }
        )
    if vector_case_count is not None:
        artifact[PROVENANCE_KEY].update(
            {
                "vectorCaseCount": vector_case_count,
                "sourceRevision": source_revision,
                "sourceTree": source_tree,
                "vectorSet": SERVER_VECTOR_SET,
                "vectorSetCount": SERVER_VECTOR_SET_COUNT,
            }
        )
    return (json.dumps(artifact, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )


def check_artifact(
    path: Path,
    expected: bytes,
    digest: str,
    source_relative: Path,
    vector_case_count: int | None = None,
    source_revision: str | None = None,
    source_tree: str | None = None,
) -> None:
    actual = path.read_bytes()
    if actual != expected:
        raise ValueError(
            f"{path} is stale; run {GENERATOR_NAME} --source <canonical lexicon>"
        )
    artifact = json.loads(actual)
    provenance = artifact.get(PROVENANCE_KEY)
    expected_provenance = {
        "sourcePath": source_relative.as_posix(),
        "sourceSha256": digest,
        "generator": GENERATOR_NAME,
        "generatorVersion": GENERATOR_VERSION,
    }
    if source_relative == SOURCE_RELATIVE:
        expected_provenance.update(
            {
                "sourceRevision": source_revision or CANONICAL_SOURCE_REVISION,
                "sourceTree": source_tree or CANONICAL_SOURCE_TREE,
            }
        )
    if vector_case_count is not None:
        expected_provenance.update(
            {
                "vectorCaseCount": vector_case_count,
                "sourceRevision": source_revision,
                "sourceTree": source_tree,
                "vectorSet": SERVER_VECTOR_SET,
                "vectorSetCount": SERVER_VECTOR_SET_COUNT,
            }
        )
    if provenance != expected_provenance:
        raise ValueError(f"{path} has invalid schema provenance: {provenance!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", help="canonical lexicon path, relative to the monorepo")
    parser.add_argument("--artifact", help="artifact path, relative to catbird-mls")
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the checked-in artifact instead of writing it",
    )
    parser.add_argument(
        "--check-mirror",
        action="store_true",
        help="verify the mls-ds lexicon is an exact byte mirror of PetrelCatbird",
    )
    parser.add_argument(
        "--validate-source",
        help="validate a canonical PetrelCatbird source file and its pinned VCS evidence",
    )
    args = parser.parse_args()

    if args.validate_source:
        _, digest, revision, tree = validate_canonical_source(
            Path(args.validate_source).resolve()
        )
        print(
            f"{args.validate_source}: verified canonical PetrelCatbird "
            f"revision {revision}, tree {tree}, SHA-256 {digest}"
        )
        return 0

    if args.check_mirror:
        server_revision()
        _, digest, _, _ = validate_canonical_source(source_path(SOURCE_RELATIVE))
        canonical = source_path(SOURCE_RELATIVE).read_bytes()
        mirror = source_path(MIRROR_RELATIVE).read_bytes()
        if canonical != mirror:
            canonical_digest = hashlib.sha256(canonical).hexdigest()
            mirror_digest = hashlib.sha256(mirror).hexdigest()
            raise ValueError(
                "mls-ds lexicon mirror differs from PetrelCatbird canonical source "
                f"(canonical {canonical_digest}, mirror {mirror_digest})"
            )
        print(
            f"{MIRROR_RELATIVE}: verified exact mirror of {SOURCE_RELATIVE} "
            f"(canonical SHA-256 {digest})"
        )
        return 0

    pinned_canonical_revision, pinned_canonical_tree = canonical_revision()
    pinned_server_revision, pinned_server_tree = server_revision()
    artifacts = (
        (
            SOURCE_RELATIVE,
            artifact_path(args.artifact),
            source_path(args.source),
            True,
            None,
            CANONICAL_SOURCE_SHA256,
        ),
        *(
            (
                source_relative,
                artifact_path(artifact_relative),
                source_path(source_relative),
                False,
                vector_case_count,
                source_sha256,
            )
            for source_relative, artifact_relative, vector_case_count, source_sha256 in FIXTURE_SOURCES
        ),
    )
    for (
        source_relative,
        destination,
        source,
        require_defs,
        vector_case_count,
        expected_source_sha256,
    ) in artifacts:
        loaded, digest = load_source(source, require_defs=require_defs)
        if expected_source_sha256 is not None and digest != expected_source_sha256:
            raise ValueError(
                f"{source} has SHA-256 {digest}, expected the approved corpus "
                f"{expected_source_sha256}"
            )
        if vector_case_count is not None and fixture_case_count(loaded, source_relative) != vector_case_count:
            raise ValueError(
                f"{source} has the wrong corpus count; expected {vector_case_count}"
            )
        expected = expected_artifact(
            loaded,
            digest,
            source_relative,
            vector_case_count=vector_case_count,
            source_revision=(
                pinned_server_revision
                if vector_case_count is not None
                else pinned_canonical_revision
            ),
            source_tree=(
                pinned_server_tree if vector_case_count is not None else pinned_canonical_tree
            ),
        )
        if args.check:
            check_artifact(
                destination,
                expected,
                digest,
                source_relative,
                vector_case_count=vector_case_count,
                source_revision=(
                    pinned_server_revision
                    if vector_case_count is not None
                    else pinned_canonical_revision
                ),
                source_tree=(
                    pinned_server_tree
                    if vector_case_count is not None
                    else pinned_canonical_tree
                ),
            )
            print(f"{destination}: verified source SHA-256 {digest}")
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(expected)
            print(f"{destination}: generated from source SHA-256 {digest}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"generate_chat_schema.py: {error}", file=sys.stderr)
        raise SystemExit(1)
