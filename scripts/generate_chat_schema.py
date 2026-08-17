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
    ),
    (
        Path("mls-ds/server/tests/fixtures/mls_chat_contract_vectors.json"),
        Path("src/orchestrator/generated/mls_chat_contract_vectors.json"),
        14,
    ),
)
ARTIFACT_RELATIVE = Path("src/orchestrator/generated/blue.catbird.chat.defs.json")
GENERATOR_NAME = "scripts/generate_chat_schema.py"
GENERATOR_VERSION = 5
PROVENANCE_KEY = "_catbird_mls_provenance"
CANONICAL_SOURCE_REVISION = "954d7ab20f362b731ee13f87eea89ae83558c624"
CANONICAL_SOURCE_TREE = "6779729a15bec425fa520b9197bf60bebdb9e32b"


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


def expected_artifact(
    source: dict,
    digest: str,
    source_relative: Path,
    vector_case_count: int | None = None,
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
                "sourceRevision": CANONICAL_SOURCE_REVISION,
                "sourceTree": CANONICAL_SOURCE_TREE,
            }
        )
    if vector_case_count is not None:
        artifact[PROVENANCE_KEY].update(
            {
                "vectorCaseCount": vector_case_count,
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
                "sourceRevision": CANONICAL_SOURCE_REVISION,
                "sourceTree": CANONICAL_SOURCE_TREE,
            }
        )
    if vector_case_count is not None:
        expected_provenance.update(
            {
                "vectorCaseCount": vector_case_count,
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
    args = parser.parse_args()

    if args.check_mirror:
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
            f"{MIRROR_RELATIVE}: verified exact mirror of {SOURCE_RELATIVE}"
        )
        return 0

    artifacts = (
        (
            SOURCE_RELATIVE,
            artifact_path(args.artifact),
            source_path(args.source),
            True,
            None,
        ),
        *(
            (
                source_relative,
                artifact_path(artifact_relative),
                source_path(source_relative),
                False,
                vector_case_count,
            )
            for source_relative, artifact_relative, vector_case_count in FIXTURE_SOURCES
        ),
    )
    for source_relative, destination, source, require_defs, vector_case_count in artifacts:
        loaded, digest = load_source(source, require_defs=require_defs)
        expected = expected_artifact(
            loaded, digest, source_relative, vector_case_count=vector_case_count
        )
        if args.check:
            check_artifact(
                destination,
                expected,
                digest,
                source_relative,
                vector_case_count=vector_case_count,
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
