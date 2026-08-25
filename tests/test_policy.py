from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from csp_mcp.config import load_settings
from csp_mcp.errors import BridgeError
from csp_mcp.policy import PathPolicy


class PathPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.settings = load_settings()
        cls.policy = PathPolicy(cls.settings)
        cls.working = cls.settings.root("working").path
        cls.working.mkdir(parents=True, exist_ok=True)

    def test_allows_new_output_inside_writable_root(self) -> None:
        with tempfile.TemporaryDirectory(dir=self.working) as directory:
            target = Path(directory) / "new-output.png"
            validated = self.policy.validate(str(target), "output_new")
            self.assertEqual(validated.root.id, "working")
            self.assertFalse(validated.path.exists())

    def test_denies_path_outside_roots(self) -> None:
        with self.assertRaises(BridgeError) as raised:
            self.policy.validate(r"C:\Windows\Temp\csp.png", "output_new")
        self.assertEqual(raised.exception.code, "E_PATH_OUTSIDE_ALLOWLIST")

    def test_denies_unc_and_device_paths(self) -> None:
        for candidate in (r"\\server\share\a.png", r"\\?\C:\CSP-MCP-Assets\Exports\a.png"):
            with self.subTest(candidate=candidate), self.assertRaises(BridgeError):
                self.policy.validate(candidate, "output_new")

    def test_denies_ads_wildcards_and_reserved_names(self) -> None:
        candidates = [
            str(self.working / "image.png:payload"),
            str(self.working / "*.png"),
            str(self.working / "CON.png"),
            str(self.working / "trailing.png") + " ",
        ]
        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(BridgeError):
                self.policy.validate(candidate, "output_new")

    def test_denies_unapproved_extension(self) -> None:
        with self.assertRaises(BridgeError) as raised:
            self.policy.validate(str(self.working / "payload.exe"), "output_new")
        self.assertEqual(raised.exception.code, "E_FORMAT_DENIED")

    def test_denies_implicit_overwrite(self) -> None:
        with tempfile.TemporaryDirectory(dir=self.working) as directory:
            target = Path(directory) / "exists.png"
            target.write_bytes(b"not-an-executable")
            with self.assertRaises(BridgeError) as raised:
                self.policy.validate(str(target), "output_new")
            self.assertEqual(raised.exception.code, "E_TARGET_EXISTS")

    def test_denies_hard_linked_input_file(self) -> None:
        with tempfile.TemporaryDirectory(dir=self.working) as directory:
            target = Path(directory) / "source.png"
            alias = Path(directory) / "alias.png"
            target.write_bytes(b"hard-link-fixture")
            os.link(target, alias)

            with self.assertRaises(BridgeError) as raised:
                self.policy.validate(str(target), "input")

            self.assertEqual(raised.exception.code, "E_HARDLINK_DENIED")

    def test_denies_reparse_point_above_configured_root(self) -> None:
        ancestor = self.working.parents[1]

        def mocked_reparse(path: Path) -> bool:
            return os.path.normcase(str(path)) == os.path.normcase(str(ancestor))

        with patch.object(PathPolicy, "_has_reparse_point", side_effect=mocked_reparse):
            with self.assertRaises(BridgeError) as raised:
                self.policy.validate(str(self.working / "new-output.png"), "output_new")

        self.assertEqual(raised.exception.code, "E_PATH_REPARSE_ESCAPE")
        payload = json.loads(str(raised.exception))
        self.assertEqual(payload["error"]["details"]["component"], str(ancestor))


if __name__ == "__main__":
    unittest.main()
