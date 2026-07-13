import plistlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "normalize_xcframework_plist.py"


def library(identifier: str) -> dict[str, object]:
    return {
        "SupportedPlatform": "ios",
        "LibraryIdentifier": identifier,
        "LibraryPath": "libCatbirdMLSFFI.a",
        "SupportedArchitectures": ["arm64"],
    }


class NormalizeXCFrameworkPlistTests(unittest.TestCase):
    def normalize(self, identifiers: list[str]) -> tuple[list[str], bytes, bytes]:
        with tempfile.TemporaryDirectory() as directory:
            plist_path = Path(directory) / "Info.plist"
            with plist_path.open("wb") as stream:
                plistlib.dump(
                    {
                        "AvailableLibraries": [library(value) for value in identifiers],
                        "XCFrameworkFormatVersion": "1.0",
                        "CFBundlePackageType": "XFWK",
                    },
                    stream,
                    fmt=plistlib.FMT_XML,
                    sort_keys=False,
                )

            first = subprocess.run(
                [sys.executable, str(SCRIPT), str(plist_path)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            first_bytes = plist_path.read_bytes()

            second = subprocess.run(
                [sys.executable, str(SCRIPT), str(plist_path)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(second.returncode, 0, second.stderr)
            second_bytes = plist_path.read_bytes()

            with plist_path.open("rb") as stream:
                normalized = plistlib.load(stream)

            normalized_identifiers = [
                entry["LibraryIdentifier"]
                for entry in normalized["AvailableLibraries"]
            ]
            return normalized_identifiers, first_bytes, second_bytes

    def test_sorts_unsorted_available_libraries_and_is_idempotent(self) -> None:
        identifiers, first_bytes, second_bytes = self.normalize(
            ["macos-arm64_x86_64", "ios-arm64", "ios-arm64_x86_64-simulator"]
        )

        self.assertEqual(
            identifiers,
            ["ios-arm64", "ios-arm64_x86_64-simulator", "macos-arm64_x86_64"],
        )
        self.assertEqual(first_bytes, second_bytes)

    def test_preserves_sorted_available_libraries_and_is_idempotent(self) -> None:
        expected = [
            "ios-arm64",
            "ios-arm64_x86_64-maccatalyst",
            "macos-arm64_x86_64",
        ]

        identifiers, first_bytes, second_bytes = self.normalize(expected)

        self.assertEqual(identifiers, expected)
        self.assertEqual(first_bytes, second_bytes)


if __name__ == "__main__":
    unittest.main()
