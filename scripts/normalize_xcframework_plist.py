#!/usr/bin/env python3

import argparse
import os
import plistlib
import tempfile
from pathlib import Path


def normalize(plist_path: Path) -> None:
    with plist_path.open("rb") as stream:
        plist = plistlib.load(stream)

    libraries = plist.get("AvailableLibraries")
    if not isinstance(libraries, list):
        raise ValueError("AvailableLibraries must be an array")

    for library in libraries:
        if not isinstance(library, dict) or not isinstance(
            library.get("LibraryIdentifier"), str
        ):
            raise ValueError("each library must have a string LibraryIdentifier")

    plist["AvailableLibraries"] = sorted(
        libraries, key=lambda library: library["LibraryIdentifier"]
    )

    with tempfile.NamedTemporaryFile(
        mode="wb", dir=plist_path.parent, delete=False
    ) as stream:
        temporary_path = Path(stream.name)
        plistlib.dump(plist, stream, fmt=plistlib.FMT_XML, sort_keys=True)

    os.replace(temporary_path, plist_path)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Normalize XCFramework Info.plist ordering deterministically"
    )
    parser.add_argument("plist", type=Path)
    arguments = parser.parse_args()
    normalize(arguments.plist)


if __name__ == "__main__":
    main()
