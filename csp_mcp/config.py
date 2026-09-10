from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import BridgeError


PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = PROJECT_ROOT / "config"
CONFIG_ENV = "CSP_MCP_CONFIG"
LOCAL_CONFIG_NAME = "config.local.json"
TRACKED_CONFIG_NAME = "config.json"
LOCAL_AUTO_ACTIONS_NAME = "auto_actions.local.json"
TRACKED_AUTO_ACTIONS_NAME = "auto_actions.json"
_ENV_PLACEHOLDER = re.compile(r"%([A-Za-z_][A-Za-z0-9_]*)%")


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _reject_nonfinite_json(value: str) -> Any:
    raise ValueError(f"Non-finite JSON number is not allowed: {value}")


def _expand_env_path(value: str, *, field: str) -> Path:
    """Expand only explicit ``%NAME%`` tokens without invoking a shell.

    ``os.path.expandvars`` leaves unknown variables untouched and may also
    expand shell-style syntax.  Configuration paths are security boundaries,
    so unknown, empty, malformed, or nested placeholders fail closed instead.
    """

    source = value.strip()
    if not source or "\x00" in source:
        raise RuntimeError(f"Configuration path {field!r} must be a non-empty string without NUL bytes")

    placeholders = list(_ENV_PLACEHOLDER.finditer(source))
    literal_portions = _ENV_PLACEHOLDER.sub("", source)
    if "%" in literal_portions:
        raise RuntimeError(f"Configuration path {field!r} contains a malformed environment placeholder")

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        expanded = os.environ.get(name)
        if expanded is None or not expanded.strip() or "\x00" in expanded:
            raise RuntimeError(f"Configuration path {field!r} references an unavailable environment variable: {name}")
        if _ENV_PLACEHOLDER.search(expanded) or "%" in expanded:
            raise RuntimeError(f"Environment variable {name!r} contains a nested or malformed placeholder")
        return expanded

    expanded = _ENV_PLACEHOLDER.sub(replace, source) if placeholders else source
    return Path(expanded)


def _settings_path() -> Path:
    override = os.environ.get(CONFIG_ENV)
    if override is not None:
        path = _expand_env_path(override, field=CONFIG_ENV)
        if not path.is_absolute():
            raise RuntimeError(f"{CONFIG_ENV} must resolve to an absolute file path")
        return path

    local = CONFIG_DIR / LOCAL_CONFIG_NAME
    if local.exists():
        if not local.is_file():
            raise RuntimeError(f"Local configuration is not a regular file: {local}")
        return local
    return CONFIG_DIR / TRACKED_CONFIG_NAME


def _read_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(
                handle,
                object_pairs_hook=_strict_json_object,
                parse_constant=_reject_nonfinite_json,
            )
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"Cannot load configuration {path.name}: {exc}") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"Configuration {path.name} must be a JSON object")
    return data


def _bool_field(mapping: dict[str, Any], key: str, default: bool | None = None) -> bool:
    value = mapping.get(key, default)
    if type(value) is not bool:
        raise RuntimeError(f"Configuration field {key!r} must be a JSON boolean")
    return value


def _int_in_range(mapping: dict[str, Any], key: str, minimum: int, maximum: int) -> int:
    value = mapping.get(key)
    if type(value) is not int or not minimum <= value <= maximum:
        raise RuntimeError(f"Configuration field {key!r} must be an integer in {minimum}..{maximum}")
    return value


def _number_in_range(mapping: dict[str, Any], key: str, minimum: float, maximum: float) -> float:
    value = mapping.get(key)
    if type(value) not in {int, float} or not minimum <= float(value) <= maximum:
        raise RuntimeError(f"Configuration field {key!r} must be a number in {minimum}..{maximum}")
    return float(value)


def _registry_profile_ids(raw: dict[str, Any], name: str) -> frozenset[str]:
    """The profiles a registry declares itself valid for.

    A registry names one profile with ``profile_id`` or several with ``profile_ids``,
    never both.  Registered keys are CSP default bindings, so one list can serve every
    validated build whose defaults agree; an ambiguous or malformed declaration fails
    closed instead of matching nothing silently.
    """
    single = raw.get("profile_id")
    listed = raw.get("profile_ids")
    if single is not None and listed is not None:
        raise RuntimeError(f"{name} must declare profile_id or profile_ids, not both")
    if listed is not None:
        if (
            not isinstance(listed, list)
            or not listed
            or any(not isinstance(item, str) or not item.strip() for item in listed)
            or len({item.strip() for item in listed}) != len(listed)
        ):
            raise RuntimeError(f"{name} profile_ids must be a non-empty list of unique profile ids")
        return frozenset(item.strip() for item in listed)
    if not isinstance(single, str) or not single.strip():
        raise RuntimeError(f"{name} must declare profile_id or profile_ids")
    return frozenset({single.strip()})


@dataclass(frozen=True)
class PathRoot:
    id: str
    path: Path
    read: bool
    write: bool


@dataclass(frozen=True)
class PinnedFile:
    path: Path
    sha256: str


@dataclass(frozen=True)
class Settings:
    schema_version: int
    profile_id: str
    csp_executable: Path
    expected_company_contains: str
    allowed_file_versions: tuple[str, ...]
    allowed_sha256: tuple[str, ...]
    expected_dpi: int
    expected_locale: str
    strict_profile_for_input: bool
    shortcut_profile_files: tuple[PinnedFile, ...]
    quiet_period_ms: int
    quiet_wait_timeout_ms: int
    capture_ttl_seconds: int
    confirmation_ttl_seconds: int
    max_capture_width: int
    max_text_chars: int
    max_macro_steps: int
    max_drag_seconds: float
    path_roots: tuple[PathRoot, ...]
    input_extensions: frozenset[str]
    output_extensions: frozenset[str]

    def locale_matches(self, actual: str) -> bool:
        """Windows culture does not determine CSP UI language or shortcut bindings.

        '*' permits any culture; explicit legacy pins remain supported.
        Native file dialogs validate their own labels independently.
        """
        return self.expected_locale == "*" or actual.casefold() == self.expected_locale.casefold()

    def root(self, root_id: str) -> PathRoot:
        for entry in self.path_roots:
            if entry.id == root_id:
                return entry
        raise BridgeError(
            "E_PATH_OUTSIDE_ALLOWLIST",
            f"Unknown path root: {root_id}",
            stage="validation",
        )


def load_settings() -> Settings:
    raw = _read_json(_settings_path())
    if type(raw.get("schema_version")) is not int or raw["schema_version"] != 1:
        raise RuntimeError("Only config schema_version 1 is supported")
    profile_value = raw.get("profile_id")
    company_value = raw.get("expected_company_contains")
    locale_value = raw.get("expected_locale")
    if not all(isinstance(item, str) and item.strip() for item in (profile_value, company_value, locale_value)):
        raise RuntimeError("Production profile_id, expected company, and locale must be non-empty")
    profile_id = profile_value.strip()
    expected_company = company_value.strip()
    expected_locale = locale_value.strip()
    versions_raw = raw.get("allowed_file_versions")
    hashes_raw = raw.get("allowed_sha256")
    if not isinstance(versions_raw, list) or not isinstance(hashes_raw, list):
        raise RuntimeError("Production version and SHA allowlists must be JSON arrays")
    versions = tuple(str(item).strip() for item in versions_raw)
    hashes = tuple(str(item).strip().upper() for item in hashes_raw)
    if (
        not versions
        or any(not isinstance(item, str) or not item.strip() for item in versions_raw)
        or len(set(versions)) != len(versions)
    ):
        raise RuntimeError("Production allowed_file_versions must be a non-empty unique list")
    if (
        not hashes
        or any(not isinstance(item, str) for item in hashes_raw)
        or len(set(hashes)) != len(hashes)
        or any(re.fullmatch(r"[0-9A-F]{64}", item) is None for item in hashes)
    ):
        raise RuntimeError("Production allowed_sha256 must contain unique 64-character hexadecimal hashes")
    executable_value = raw.get("csp_executable")
    if not isinstance(executable_value, str) or not executable_value.strip():
        raise RuntimeError("csp_executable must be a non-empty absolute path")
    csp_executable = _expand_env_path(executable_value, field="csp_executable")
    if not csp_executable.is_absolute():
        raise RuntimeError("csp_executable must be absolute")
    if _bool_field(raw, "strict_profile_for_input", True) is not True:
        raise RuntimeError("Production profile requires strict_profile_for_input=true")
    shortcut_files_raw = raw.get("shortcut_profile_files")
    if (
        not isinstance(shortcut_files_raw, list)
        or not shortcut_files_raw
        or any(not isinstance(item, dict) for item in shortcut_files_raw)
    ):
        raise RuntimeError("shortcut_profile_files must be a non-empty JSON array")
    shortcut_profile_files: list[PinnedFile] = []
    for item in shortcut_files_raw:
        path_value = item.get("path")
        sha_value = item.get("sha256")
        if (
            not isinstance(path_value, str)
            or not isinstance(sha_value, str)
            or re.fullmatch(r"[0-9A-Fa-f]{64}", sha_value) is None
        ):
            raise RuntimeError("Every shortcut profile file needs an absolute path and SHA-256")
        expanded_path = _expand_env_path(path_value, field="shortcut_profile_files.path")
        if not expanded_path.is_absolute():
            raise RuntimeError("Every shortcut profile file needs an absolute path and SHA-256")
        shortcut_profile_files.append(PinnedFile(expanded_path, sha_value.upper()))
    if len({os.path.normcase(str(item.path)) for item in shortcut_profile_files}) != len(shortcut_profile_files):
        raise RuntimeError("shortcut_profile_files paths must be unique")

    roots_raw = raw.get("path_roots")
    if not isinstance(roots_raw, list) or not roots_raw or any(not isinstance(item, dict) for item in roots_raw):
        raise RuntimeError("config.json must define path_roots as a non-empty JSON array")
    roots: tuple[PathRoot, ...] = tuple(
        PathRoot(
            id=str(item.get("id", "")).strip(),
            path=_expand_env_path(item.get("path"), field=f"path_roots[{index}].path")
            if isinstance(item.get("path"), str)
            else Path(""),
            read=_bool_field(item, "read", False),
            write=_bool_field(item, "write", False),
        )
        for index, item in enumerate(roots_raw)
    )
    root_ids = [item.id for item in roots]
    if set(root_ids) != {"input", "working", "exports"} or len(root_ids) != 3:
        raise RuntimeError("path_roots must define input, working, and exports exactly once")
    if any(not item.path.is_absolute() or not item.read for item in roots):
        raise RuntimeError("Every path root must be absolute and readable")
    if next(item for item in roots if item.id == "input").write:
        raise RuntimeError("The input root must remain read-only")
    if any(not next(item for item in roots if item.id == root_id).write for root_id in ("working", "exports")):
        raise RuntimeError("The working and exports roots must remain writable")
    normalized_roots = [os.path.normcase(os.path.abspath(str(item.path))) for item in roots]
    for index, left in enumerate(normalized_roots):
        for right in normalized_roots[index + 1:]:
            try:
                common = os.path.normcase(os.path.commonpath([left, right]))
            except ValueError:
                continue
            if common in {left, right}:
                raise RuntimeError("Path roots must not duplicate or contain one another")

    input_extensions_raw = raw.get("input_extensions")
    output_extensions_raw = raw.get("output_extensions")
    if not isinstance(input_extensions_raw, list) or not isinstance(output_extensions_raw, list):
        raise RuntimeError("Input and output extensions must be JSON arrays")
    input_extensions = tuple(str(item).lower() for item in input_extensions_raw)
    output_extensions = tuple(str(item).lower() for item in output_extensions_raw)
    for label, source, normalized in (
        ("input", input_extensions_raw, input_extensions),
        ("output", output_extensions_raw, output_extensions),
    ):
        if (
            not normalized
            or any(not isinstance(item, str) or re.fullmatch(r"\.[a-z0-9]+", item.lower()) is None for item in source)
            or len(set(normalized)) != len(normalized)
        ):
            raise RuntimeError(f"{label}_extensions must be a non-empty unique extension list")

    return Settings(
        schema_version=raw["schema_version"],
        profile_id=profile_id,
        csp_executable=csp_executable,
        expected_company_contains=expected_company,
        allowed_file_versions=versions,
        allowed_sha256=hashes,
        expected_dpi=_int_in_range(raw, "expected_dpi", 96, 480),
        expected_locale=expected_locale,
        strict_profile_for_input=True,
        shortcut_profile_files=tuple(shortcut_profile_files),
        quiet_period_ms=_int_in_range(raw, "quiet_period_ms", 250, 10000),
        quiet_wait_timeout_ms=_int_in_range(raw, "quiet_wait_timeout_ms", 500, 30000),
        capture_ttl_seconds=_int_in_range(raw, "capture_ttl_seconds", 5, 300),
        confirmation_ttl_seconds=_int_in_range(raw, "confirmation_ttl_seconds", 5, 300),
        max_capture_width=_int_in_range(raw, "max_capture_width", 320, 4096),
        max_text_chars=_int_in_range(raw, "max_text_chars", 1, 16384),
        max_macro_steps=_int_in_range(raw, "max_macro_steps", 1, 50),
        max_drag_seconds=_number_in_range(raw, "max_drag_seconds", 0.05, 10.0),
        path_roots=roots,
        input_extensions=frozenset(input_extensions),
        output_extensions=frozenset(output_extensions),
    )


def load_commands() -> dict[str, dict[str, Any]]:
    raw = _read_json(CONFIG_DIR / "commands.json")
    settings = load_settings()
    if int(raw.get("schema_version", -1)) != settings.schema_version:
        raise RuntimeError("commands.json schema_version does not match config.json")
    if settings.profile_id not in _registry_profile_ids(raw, "commands.json"):
        raise RuntimeError("commands.json profile_id does not match the production profile")
    commands: dict[str, dict[str, Any]] = {}
    for item in raw.get("commands", []):
        command = dict(item)
        command_id = str(command.get("id", ""))
        if not command_id or command_id in commands:
            raise RuntimeError(f"Invalid or duplicate command id: {command_id!r}")
        commands[command_id] = command
    return commands


def load_auto_actions() -> dict[str, dict[str, Any]]:
    local = CONFIG_DIR / LOCAL_AUTO_ACTIONS_NAME
    if local.exists() and not local.is_file():
        raise RuntimeError(f"Local Auto Action registry is not a regular file: {local}")
    registry_path = local if local.is_file() else CONFIG_DIR / TRACKED_AUTO_ACTIONS_NAME
    raw = _read_json(registry_path)
    settings = load_settings()
    if int(raw.get("schema_version", -1)) != settings.schema_version:
        raise RuntimeError(f"{registry_path.name} schema_version does not match the active configuration")
    if settings.profile_id not in _registry_profile_ids(raw, registry_path.name):
        raise RuntimeError(f"{registry_path.name} profile_id does not match the production profile")
    actions: dict[str, dict[str, Any]] = {}
    for item in raw.get("actions", []):
        action = dict(item)
        action_id = str(action.get("id", ""))
        if not action_id or action_id in actions:
            raise RuntimeError(f"Invalid or duplicate Auto Action id: {action_id!r}")
        actions[action_id] = action
    return actions
