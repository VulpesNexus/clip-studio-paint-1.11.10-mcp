from __future__ import annotations

import copy
import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from csp_mcp import config as config_module
from csp_mcp.config import load_auto_actions, load_commands, load_settings
from csp_mcp.controller import validate_registry_entry
from csp_mcp.win32_backend import validate_keys


class ConfigurationTests(unittest.TestCase):
    @staticmethod
    def _write_config(path: Path, data: dict) -> None:
        path.write_text(json.dumps(data), encoding="utf-8")

    def test_profile_is_pinned_to_current_production_binary(self) -> None:
        # The tracked template, not whichever local profile this machine configured.
        tracked = config_module.CONFIG_DIR / config_module.TRACKED_CONFIG_NAME
        with patch.dict(os.environ, {config_module.CONFIG_ENV: str(tracked)}, clear=False):
            settings = load_settings()
        self.assertEqual(settings.profile_id, "csp-1.11.10-dpi96-v1")
        self.assertEqual(settings.allowed_file_versions, ("1.11.10.0",))
        self.assertEqual(settings.expected_dpi, 96)
        self.assertEqual(settings.expected_locale, "*")
        self.assertEqual(len(settings.allowed_sha256), 1)
        self.assertEqual(len(settings.allowed_sha256[0]), 64)

    def test_local_config_precedes_tracked_config_then_falls_back(self) -> None:
        baseline = config_module._read_json(config_module.CONFIG_DIR / "config.json")
        with tempfile.TemporaryDirectory() as temporary:
            config_dir = Path(temporary)
            tracked = copy.deepcopy(baseline)
            tracked["profile_id"] = "tracked-profile"
            local = copy.deepcopy(baseline)
            local["profile_id"] = "local-profile"
            self._write_config(config_dir / "config.json", tracked)
            self._write_config(config_dir / "config.local.json", local)
            with patch.object(config_module, "CONFIG_DIR", config_dir), patch.dict(os.environ, {}, clear=False):
                os.environ.pop(config_module.CONFIG_ENV, None)
                self.assertEqual(load_settings().profile_id, "local-profile")
                (config_dir / "config.local.json").unlink()
                self.assertEqual(load_settings().profile_id, "tracked-profile")

    def test_json_loader_rejects_duplicate_keys_and_nonfinite_numbers(self) -> None:
        candidates = (
            '{"schema_version": 1, "schema_version": 2}',
            '{"value": NaN}',
            '{"value": Infinity}',
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "candidate.json"
            for candidate in candidates:
                with self.subTest(candidate=candidate):
                    path.write_text(candidate, encoding="utf-8")
                    with self.assertRaises(RuntimeError):
                        config_module._read_json(path)

    def test_explicit_config_override_has_priority_and_expands_percent_env(self) -> None:
        baseline = config_module._read_json(config_module.CONFIG_DIR / "config.json")
        with tempfile.TemporaryDirectory() as temporary:
            config_dir = Path(temporary)
            local = copy.deepcopy(baseline)
            local["profile_id"] = "local-profile"
            override = copy.deepcopy(baseline)
            override["profile_id"] = "override-profile"
            self._write_config(config_dir / "config.local.json", local)
            self._write_config(config_dir / "override.json", override)
            environment = {
                config_module.CONFIG_ENV: r"%CSP_MCP_TEST_CONFIG_DIR%\override.json",
                "CSP_MCP_TEST_CONFIG_DIR": str(config_dir),
            }
            with patch.object(config_module, "CONFIG_DIR", config_dir), patch.dict(os.environ, environment, clear=False):
                self.assertEqual(load_settings().profile_id, "override-profile")

    def test_config_paths_fail_closed_for_unknown_malformed_and_nested_env(self) -> None:
        baseline = config_module._read_json(config_module.CONFIG_DIR / "config.json")
        candidates = (
            (r"%CSP_MCP_VARIABLE_THAT_DOES_NOT_EXIST%\paint.exe", {}),
            (r"%BROKEN\paint.exe", {}),
            (r"%CSP_MCP_NESTED%\paint.exe", {"CSP_MCP_NESTED": r"%USERPROFILE%\nested"}),
        )
        with tempfile.TemporaryDirectory() as temporary:
            config_path = Path(temporary) / "candidate.json"
            for executable, extra_environment in candidates:
                with self.subTest(executable=executable):
                    candidate = copy.deepcopy(baseline)
                    candidate["csp_executable"] = executable
                    self._write_config(config_path, candidate)
                    environment = {config_module.CONFIG_ENV: str(config_path), **extra_environment}
                    with patch.dict(os.environ, environment, clear=False):
                        os.environ.pop("CSP_MCP_VARIABLE_THAT_DOES_NOT_EXIST", None)
                        with self.assertRaises(RuntimeError):
                            load_settings()

    def test_public_reference_config_contains_no_machine_specific_paths(self) -> None:
        reference = (config_module.CONFIG_DIR / "config.json").read_text(encoding="utf-8")
        self.assertIn("%ProgramFiles%", reference)
        self.assertIn("%USERPROFILE%", reference)
        raw = json.loads(reference)
        configured_paths = [raw["csp_executable"]]
        configured_paths.extend(item["path"] for item in raw["shortcut_profile_files"])
        configured_paths.extend(item["path"] for item in raw["path_roots"])
        self.assertTrue(
            all(path.startswith(("%ProgramFiles%\\", "%USERPROFILE%\\")) for path in configured_paths),
            "The tracked configuration must use portable environment-rooted paths",
        )
        self.assertTrue(
            all(item["sha256"] == "0" * 64 for item in raw["shortcut_profile_files"]),
            "The tracked shortcut pins must require local configuration instead of trusting a sample profile",
        )
        ignored = (config_module.PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        self.assertIn("config/config.local.json", ignored)
        self.assertIn("config/auto_actions.local.json", ignored)

    def test_production_identity_pins_fail_closed_when_empty_or_malformed(self) -> None:
        baseline = config_module._read_json(config_module.CONFIG_DIR / "config.json")
        mutations = (
            ("expected_company_contains", ""),
            ("allowed_file_versions", []),
            ("allowed_sha256", []),
            ("allowed_sha256", ["not-a-sha256"]),
            ("profile_id", "   "),
            ("expected_locale", ""),
            ("schema_version", 2),
            ("strict_profile_for_input", False),
            ("quiet_period_ms", False),
        )
        for key, value in mutations:
            with self.subTest(key=key, value=value):
                candidate = copy.deepcopy(baseline)
                candidate[key] = value
                with patch("csp_mcp.config._read_json", return_value=candidate):
                    with self.assertRaises(RuntimeError):
                        load_settings()

    def test_capture_overlay_allowlist_is_optional_exact_and_fail_closed(self) -> None:
        baseline = config_module._read_json(config_module.CONFIG_DIR / "config.json")
        self.assertNotIn("capture_ignored_overlays", baseline)
        with patch("csp_mcp.config._read_json", return_value=copy.deepcopy(baseline)):
            self.assertEqual(load_settings().capture_ignored_overlays, ())
        entry = {"process": "Discord.exe", "class_name": "Chrome_WidgetWin_1", "title": "Discord Overlay"}
        candidate = copy.deepcopy(baseline)
        candidate["capture_ignored_overlays"] = [entry]
        with patch("csp_mcp.config._read_json", return_value=candidate):
            (overlay,) = load_settings().capture_ignored_overlays
        self.assertEqual(
            (overlay.process, overlay.class_name, overlay.title),
            ("Discord.exe", "Chrome_WidgetWin_1", "Discord Overlay"),
        )
        malformed = (
            {},
            ["Discord.exe"],
            [{"process": "Discord.exe"}],
            [dict(entry, title="  ")],
            [dict(entry, extra=True)],
            [entry, dict(entry)],
        )
        for value in malformed:
            with self.subTest(value=value):
                candidate = copy.deepcopy(baseline)
                candidate["capture_ignored_overlays"] = value
                with patch("csp_mcp.config._read_json", return_value=candidate):
                    with self.assertRaises(RuntimeError):
                        load_settings()

    def test_path_roots_reject_overlap(self) -> None:
        candidate = copy.deepcopy(config_module._read_json(config_module.CONFIG_DIR / "config.json"))
        candidate["path_roots"][1]["path"] = candidate["path_roots"][0]["path"] + r"\nested"
        with patch("csp_mcp.config._read_json", return_value=candidate):
            with self.assertRaises(RuntimeError):
                load_settings()

    def test_only_exact_workspace_cst_copy_root_is_optional(self) -> None:
        baseline = config_module._read_json(config_module.CONFIG_DIR / "config.json")
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            project = parent / "MCP"
            project.mkdir()
            copy_root = parent / ".workspace" / "csps-cst-working-2026-10-14"
            copy_root.mkdir(parents=True)
            entry = {"id": "cst_copy", "path": str(copy_root), "read": True, "write": True}
            valid = copy.deepcopy(baseline)
            valid["path_roots"].append(entry)
            with (
                patch.object(config_module, "PROJECT_ROOT", project),
                patch("csp_mcp.config._read_json", return_value=valid),
            ):
                self.assertEqual(load_settings().root("cst_copy").path, copy_root)

            other = parent / "other"
            other.mkdir()
            invalid_entries = (
                {**entry, "path": str(other)},
                {**entry, "read": False},
                {**entry, "write": False},
                {**entry, "id": "arbitrary"},
            )
            for invalid in invalid_entries:
                candidate = copy.deepcopy(baseline)
                candidate["path_roots"].append(invalid)
                with (
                    self.subTest(invalid=invalid),
                    patch.object(config_module, "PROJECT_ROOT", project),
                    patch("csp_mcp.config._read_json", return_value=candidate),
                ):
                    with self.assertRaises(RuntimeError):
                        load_settings()

    def test_ascii_cst_root_requires_exact_temp_copy_and_workspace_copy(self) -> None:
        baseline = config_module._read_json(config_module.CONFIG_DIR / "config.json")
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            project = parent / "MCP"
            project.mkdir()
            workspace_copy = parent / ".workspace" / "csps-cst-working-2026-10-14"
            workspace_copy.mkdir(parents=True)
            ascii_copy = parent / "csps-cst-ascii-20261014"
            ascii_copy.mkdir()
            candidate = copy.deepcopy(baseline)
            candidate["path_roots"].extend([
                {"id": "cst_copy", "path": str(workspace_copy), "read": True, "write": True},
                {"id": "cst_ascii_copy", "path": str(ascii_copy), "read": True, "write": True},
            ])
            with (
                patch.object(config_module, "PROJECT_ROOT", project),
                patch.object(config_module.tempfile, "gettempdir", return_value=str(parent)),
                patch("csp_mcp.config._read_json", return_value=candidate),
            ):
                self.assertEqual(load_settings().root("cst_ascii_copy").path, ascii_copy)
            other = parent / "other"
            other.mkdir()
            for bad in (
                {**candidate["path_roots"][-1], "path": str(other)},
                {**candidate["path_roots"][-1], "read": False},
                {**candidate["path_roots"][-1], "write": False},
            ):
                invalid = copy.deepcopy(candidate)
                invalid["path_roots"][-1] = bad
                with (
                    self.subTest(bad=bad),
                    patch.object(config_module, "PROJECT_ROOT", project),
                    patch.object(config_module.tempfile, "gettempdir", return_value=str(parent)),
                    patch("csp_mcp.config._read_json", return_value=invalid),
                ):
                    with self.assertRaises(RuntimeError):
                        load_settings()

    def test_registered_commands_are_valid_and_no_raw_code_exists(self) -> None:
        commands = load_commands()
        self.assertEqual(len(commands), 9)
        for command_id, command in commands.items():
            self.assertEqual(command_id, command["id"])
            validate_keys(command["keys"])
            validate_registry_entry(command, kind="command")
            serialized = str(command).casefold()
            for forbidden in ("powershell", "cmd.exe", "shell=true", "subprocess"):
                self.assertNotIn(forbidden, serialized)

    def test_registry_contains_no_unbounded_filesystem_shortcut(self) -> None:
        commands = load_commands()
        self.assertNotIn("document.save_current", commands)
        self.assertTrue(all(item.get("effect") != "filesystem" for item in commands.values()))
        with self.assertRaises(RuntimeError):
            validate_registry_entry(
                {
                    "id": "bad.save",
                    "keys": ["CTRL", "S"],
                    "risk": "destructive",
                    "effect": "filesystem",
                    "requires_confirmation": True,
                },
                kind="command",
            )

    def test_destructive_commands_require_confirmation(self) -> None:
        commands = load_commands()
        destructive = [item for item in commands.values() if item.get("risk") == "destructive"]
        self.assertTrue(destructive)
        self.assertTrue(all(item.get("requires_confirmation") for item in destructive))

    def test_auto_actions_start_empty_instead_of_inventing_user_actions(self) -> None:
        self.assertEqual(load_auto_actions(), {})

    def test_local_auto_actions_precede_the_tracked_empty_template(self) -> None:
        baseline_config = config_module._read_json(config_module.CONFIG_DIR / "config.json")
        tracked_actions = config_module._read_json(config_module.CONFIG_DIR / "auto_actions.json")
        local_actions = copy.deepcopy(tracked_actions)
        local_actions["actions"] = [
            {
                "id": "test.safe_action",
                "title": "Test action",
                "description": "Test-only local registry entry",
                "effect": "document",
                "risk": "modify",
                "keys": ["CTRL", "ALT", "F9"],
                "requires_confirmation": True,
                "attested_no_file_io": True,
                "enabled": True,
            }
        ]
        with tempfile.TemporaryDirectory() as temporary:
            config_dir = Path(temporary)
            self._write_config(config_dir / "config.json", baseline_config)
            self._write_config(config_dir / "auto_actions.json", tracked_actions)
            self._write_config(config_dir / "auto_actions.local.json", local_actions)
            with patch.object(config_module, "CONFIG_DIR", config_dir), patch.dict(os.environ, {}, clear=False):
                os.environ.pop(config_module.CONFIG_ENV, None)
                self.assertEqual(set(load_auto_actions()), {"test.safe_action"})
                (config_dir / "auto_actions.local.json").unlink()
                self.assertEqual(load_auto_actions(), {})

    def test_auto_action_registry_denies_system_shortcuts_and_unconfirmed_writes(self) -> None:
        with self.assertRaises(RuntimeError):
            validate_registry_entry(
                {
                    "id": "bad.system",
                    "keys": ["WIN", "R"],
                    "risk": "low",
                    "effect": "ui",
                    "requires_confirmation": False,
                },
                kind="auto_action",
            )
        with self.assertRaises(RuntimeError):
            validate_registry_entry(
                {
                    "id": "bad.write",
                    "keys": ["CTRL", "ALT", "F9"],
                    "risk": "modify",
                    "effect": "document",
                    "requires_confirmation": False,
                    "attested_no_file_io": True,
                },
                kind="auto_action",
            )
        validate_registry_entry(
            {
                "id": "good.document_action",
                "keys": ["CTRL", "ALT", "F9"],
                "risk": "modify",
                "effect": "document",
                "requires_confirmation": True,
                "attested_no_file_io": True,
                "enabled": True,
            },
            kind="auto_action",
        )
        with self.assertRaises(RuntimeError):
            validate_registry_entry(
                {
                    "id": "bad.disguised_save",
                    "keys": ["CTRL", "S"],
                    "risk": "low",
                    "effect": "ui",
                    "requires_confirmation": False,
                    "attested_no_file_io": True,
                },
                kind="auto_action",
            )
        with self.assertRaises(RuntimeError):
            validate_registry_entry(
                {
                    "id": "bad.unattested",
                    "keys": ["CTRL", "ALT", "F9"],
                    "risk": "low",
                    "effect": "ui",
                    "requires_confirmation": False,
                },
                kind="auto_action",
            )

    def test_registry_profile_metadata_must_match(self) -> None:
        original = config_module._read_json

        def mismatched(path):
            data = original(path)
            if path.name == "commands.json":
                data.pop("profile_ids", None)
                data["profile_id"] = "wrong-profile"
            return data

        with patch("csp_mcp.config._read_json", side_effect=mismatched):
            with self.assertRaises(RuntimeError):
                load_commands()

    def test_registry_profile_lists_match_one_profile_and_fail_closed(self) -> None:
        original = config_module._read_json
        active = load_settings().profile_id

        def with_commands(mutate):
            def read(path):
                data = original(path)
                if path.name == "commands.json":
                    data.pop("profile_id", None)
                    data.pop("profile_ids", None)
                    mutate(data)
                return data
            return read

        def listed(data):
            data["profile_ids"] = ["another-profile", active]

        with patch("csp_mcp.config._read_json", side_effect=with_commands(listed)):
            self.assertEqual(len(load_commands()), 9)

        def both(data):
            data["profile_id"] = active
            data["profile_ids"] = [active]

        def unlisted(data):
            data["profile_ids"] = ["another-profile"]

        def empty(data):
            data["profile_ids"] = []

        def duplicated(data):
            data["profile_ids"] = [active, active]

        def undeclared(data):
            pass

        for mutate in (both, unlisted, empty, duplicated, undeclared):
            with self.subTest(case=mutate.__name__):
                with patch("csp_mcp.config._read_json", side_effect=with_commands(mutate)):
                    with self.assertRaises(RuntimeError):
                        load_commands()

    def test_tracked_registries_list_exactly_the_configurable_profiles(self) -> None:
        script = (config_module.PROJECT_ROOT / "scripts" / "configure.ps1").read_text(encoding="utf-8")
        configurable = set(re.findall(r"ProfileId = '([^']+)'", script))
        self.assertEqual(configurable, {"csp-1.11.10-dpi96-v1"})
        for name in ("commands.json", "auto_actions.json"):
            with self.subTest(registry=name):
                raw = config_module._read_json(config_module.CONFIG_DIR / name)
                self.assertEqual(set(raw["profile_ids"]), configurable)

    def test_registry_rejects_string_booleans(self) -> None:
        with self.assertRaises(RuntimeError):
            validate_registry_entry(
                {
                    "id": "bad.boolean",
                    "keys": ["CTRL", "ALT", "F9"],
                    "risk": "low",
                    "effect": "ui",
                    "requires_confirmation": "false",
                    "enabled": True,
                    "attested_no_file_io": True,
                },
                kind="auto_action",
            )


if __name__ == "__main__":
    unittest.main()
