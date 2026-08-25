from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import hashlib
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Literal

from .config import PathRoot, Settings
from .errors import BridgeError


PathIntent = Literal["input", "output_new", "output_replace"]
_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}
_WILDCARD_RE = re.compile(r"[\x00-\x1f*?\"<>|]")
_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002
_FILE_SHARE_DELETE = 0x00000004
_OPEN_EXISTING = 3
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_kernel32.CreateFileW.restype = wt.HANDLE
_kernel32.CreateFileW.argtypes = [
    wt.LPCWSTR,
    wt.DWORD,
    wt.DWORD,
    ctypes.c_void_p,
    wt.DWORD,
    wt.DWORD,
    wt.HANDLE,
]
_kernel32.GetFinalPathNameByHandleW.restype = wt.DWORD
_kernel32.GetFinalPathNameByHandleW.argtypes = [wt.HANDLE, wt.LPWSTR, wt.DWORD, wt.DWORD]
_kernel32.CloseHandle.restype = wt.BOOL
_kernel32.CloseHandle.argtypes = [wt.HANDLE]


@dataclass(frozen=True)
class ValidatedPath:
    path: Path
    root: PathRoot
    intent: PathIntent

    def public(self) -> dict[str, object]:
        return {
            "canonicalPath": str(self.path),
            "rootId": self.root.id,
            "intent": self.intent,
            "extension": self.path.suffix.lower(),
            "exists": self.path.exists(),
        }


class PathPolicy:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    @staticmethod
    def _has_reparse_point(path: Path) -> bool:
        try:
            attrs = os.stat(path, follow_symlinks=False).st_file_attributes
        except (AttributeError, FileNotFoundError, OSError):
            return path.is_symlink()
        return bool(attrs & _FILE_ATTRIBUTE_REPARSE_POINT)

    @staticmethod
    def _under(path: Path, root: Path) -> bool:
        try:
            return os.path.commonpath((str(path), str(root))).casefold() == str(root).casefold()
        except ValueError:
            return False

    @staticmethod
    def _assert_single_link(path: Path) -> os.stat_result:
        try:
            stat = path.stat(follow_symlinks=False)
        except OSError as exc:
            raise BridgeError("E_PATH_NOT_FOUND", "Existing file could not be inspected", stage="validation") from exc
        if stat.st_nlink != 1:
            raise BridgeError(
                "E_HARDLINK_DENIED",
                "Hard-linked files are denied at the CSP asset boundary",
                stage="validation",
                details={"linkCount": stat.st_nlink},
            )
        return stat

    @staticmethod
    def _final_path_from_handle(path: Path) -> Path:
        """Resolve an existing file/directory using a Windows kernel handle."""
        handle = _kernel32.CreateFileW(
            str(path),
            0,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
            None,
            _OPEN_EXISTING,
            _FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        if not handle or int(handle) == _INVALID_HANDLE_VALUE:
            raise BridgeError(
                "E_PATH_NOT_FOUND",
                "Existing path could not be opened for final-path verification",
                stage="validation",
                details={"win32Error": ctypes.get_last_error()},
            )
        try:
            buffer = ctypes.create_unicode_buffer(32768)
            length = _kernel32.GetFinalPathNameByHandleW(handle, buffer, len(buffer), 0)
            if not length or length >= len(buffer):
                raise BridgeError(
                    "E_PATH_REPARSE_ESCAPE",
                    "Windows could not return a bounded final path",
                    stage="validation",
                    details={"win32Error": ctypes.get_last_error()},
                )
            final = buffer.value
        finally:
            _kernel32.CloseHandle(handle)
        if final.startswith("\\\\?\\UNC\\") or not final.startswith("\\\\?\\"):
            raise BridgeError(
                "E_PATH_REPARSE_ESCAPE",
                "Final path is not a local DOS drive path",
                stage="validation",
            )
        return Path(final[4:])

    @classmethod
    def _assert_no_reparse_ancestors(cls, path: Path) -> None:
        """Reject a reparse point anywhere from the volume root to *path*.

        Checking only the configured root is insufficient: an attacker could
        replace an ancestor such as CSP-Assets with a junction, making both the
        candidate and root resolve to the same out-of-bound location.
        """
        absolute = Path(os.path.abspath(str(path)))
        current = Path(absolute.anchor)
        if not current.exists():
            raise BridgeError("E_PATH_NOT_FOUND", "Configured volume root does not exist", stage="validation")
        if cls._has_reparse_point(current):
            raise BridgeError(
                "E_PATH_REPARSE_ESCAPE",
                "A configured root ancestor is a reparse point, junction, or symlink",
                stage="validation",
                details={"component": str(current)},
            )
        for part in absolute.parts[1:]:
            current = current / part
            if not current.exists():
                raise BridgeError(
                    "E_PATH_NOT_FOUND",
                    "A configured root ancestor does not exist",
                    stage="validation",
                    details={"component": str(current)},
                )
            if cls._has_reparse_point(current):
                raise BridgeError(
                    "E_PATH_REPARSE_ESCAPE",
                    "A configured root ancestor is a reparse point, junction, or symlink",
                    stage="validation",
                    details={"component": str(current)},
                )

    def validate(self, raw_path: str, intent: PathIntent) -> ValidatedPath:
        if intent not in {"input", "output_new", "output_replace"}:
            raise BridgeError("E_POLICY_DENIED", "Unsupported path intent", stage="validation")
        if not isinstance(raw_path, str) or not raw_path or raw_path != raw_path.strip():
            raise BridgeError("E_PATH_OUTSIDE_ALLOWLIST", "Path must be a trimmed absolute path", stage="validation")
        if raw_path.startswith(("\\\\", "//", "\\\\?\\", "\\\\.\\")):
            raise BridgeError("E_PATH_OUTSIDE_ALLOWLIST", "UNC and device paths are denied", stage="validation")
        if _WILDCARD_RE.search(raw_path):
            raise BridgeError("E_PATH_OUTSIDE_ALLOWLIST", "Wildcards and control characters are denied", stage="validation")
        if len(raw_path) < 3 or raw_path[1:3] != ":\\" or ":" in raw_path[2:]:
            raise BridgeError("E_PATH_OUTSIDE_ALLOWLIST", "A local absolute drive path is required; ADS is denied", stage="validation")

        lexical = Path(os.path.abspath(raw_path))
        for part in lexical.parts[1:]:
            leaf = part.rstrip(" .")
            if leaf != part or leaf.split(".", 1)[0].upper() in _RESERVED_NAMES:
                raise BridgeError("E_PATH_OUTSIDE_ALLOWLIST", "Reserved or ambiguous path component", stage="validation")

        selected: PathRoot | None = None
        selected_root: Path | None = None
        for root in self.settings.path_roots:
            candidate_root = Path(os.path.abspath(str(root.path)))
            if self._under(lexical, candidate_root):
                selected = root
                selected_root = candidate_root
                break
        if selected is None or selected_root is None:
            raise BridgeError(
                "E_PATH_OUTSIDE_ALLOWLIST",
                "Path is outside configured CSP asset roots",
                stage="validation",
            )

        if not selected_root.is_dir():
            raise BridgeError("E_PATH_NOT_FOUND", "Configured CSP asset root does not exist", stage="validation")
        self._assert_no_reparse_ancestors(selected_root)

        if intent == "input" and not selected.read:
            raise BridgeError("E_POLICY_DENIED", "Selected root is not readable", stage="validation")
        if intent != "input" and not selected.write:
            raise BridgeError("E_POLICY_DENIED", "Selected root is not writable", stage="validation")

        current = selected_root
        relative_parts = lexical.relative_to(selected_root).parts
        for part in relative_parts:
            current = current / part
            if current.exists() and self._has_reparse_point(current):
                raise BridgeError(
                    "E_PATH_REPARSE_ESCAPE",
                    "Reparse points, junctions, and symlinks are denied",
                    stage="validation",
                )

        canonical = lexical.resolve(strict=False)
        canonical_root = selected_root.resolve(strict=True)
        handle_root = self._final_path_from_handle(selected_root)
        if os.path.normcase(str(handle_root)) != os.path.normcase(str(canonical_root)):
            raise BridgeError(
                "E_PATH_REPARSE_ESCAPE",
                "Configured root handle resolves differently from its canonical path",
                stage="validation",
            )
        if not self._under(canonical, handle_root):
            raise BridgeError("E_PATH_REPARSE_ESCAPE", "Canonical path escapes its root", stage="validation")

        extension = canonical.suffix.lower()
        allowed = self.settings.input_extensions if intent == "input" else self.settings.output_extensions
        if extension not in allowed:
            raise BridgeError("E_FORMAT_DENIED", f"File extension is not allowed for {intent}", stage="validation")

        if intent == "input":
            if not canonical.is_file():
                raise BridgeError("E_PATH_NOT_FOUND", "Input file does not exist", stage="validation")
            self._assert_single_link(canonical)
            handle_candidate = self._final_path_from_handle(canonical)
        else:
            if not canonical.parent.is_dir():
                raise BridgeError("E_PATH_NOT_FOUND", "Output parent directory does not exist", stage="validation")
            handle_parent = self._final_path_from_handle(canonical.parent)
            handle_candidate = handle_parent / canonical.name
            if intent == "output_new" and canonical.exists():
                raise BridgeError("E_TARGET_EXISTS", "Output already exists; overwrite is denied", stage="validation")
            if intent == "output_replace" and not canonical.is_file():
                raise BridgeError("E_PATH_NOT_FOUND", "Replace target does not exist", stage="validation")
            if intent == "output_replace":
                self._assert_single_link(canonical)
                handle_candidate = self._final_path_from_handle(canonical)

        if not self._under(handle_candidate, handle_root):
            raise BridgeError(
                "E_PATH_REPARSE_ESCAPE",
                "Handle-resolved path escapes its configured root",
                stage="validation",
            )
        if os.path.normcase(str(handle_candidate)) != os.path.normcase(str(canonical)):
            raise BridgeError(
                "E_PATH_REPARSE_ESCAPE",
                "Handle-resolved path differs from its canonical path",
                stage="validation",
            )

        return ValidatedPath(canonical, selected, intent)

    def root_path(self, root_id: str, *, require_read: bool = True) -> Path:
        root = self.settings.root(root_id)
        if require_read and not root.read:
            raise BridgeError("E_POLICY_DENIED", "Root is not readable", stage="validation")
        lexical = Path(os.path.abspath(str(root.path)))
        self._assert_no_reparse_ancestors(lexical)
        canonical = lexical.resolve(strict=True)
        final = self._final_path_from_handle(lexical)
        if os.path.normcase(str(final)) != os.path.normcase(str(canonical)):
            raise BridgeError("E_PATH_REPARSE_ESCAPE", "Root handle and canonical path differ", stage="validation")
        return final

    def iter_files(self, root_id: str, *, recursive: bool) -> tuple[Path, Iterable[Path]]:
        root = self.root_path(root_id)

        def candidates() -> Iterable[Path]:
            if not recursive:
                for candidate in root.iterdir():
                    if candidate.is_file() and not self._has_reparse_point(candidate):
                        try:
                            self._assert_single_link(candidate)
                        except BridgeError:
                            continue
                        yield candidate
                return
            for current_raw, directories, names in os.walk(root, topdown=True, followlinks=False):
                current = Path(current_raw)
                safe_directories: list[str] = []
                for name in directories:
                    candidate = current / name
                    if not self._has_reparse_point(candidate):
                        safe_directories.append(name)
                directories[:] = safe_directories
                for name in names:
                    candidate = current / name
                    if candidate.is_file() and not self._has_reparse_point(candidate):
                        try:
                            self._assert_single_link(candidate)
                        except BridgeError:
                            continue
                        yield candidate

        return root, candidates()


def file_sha256(
    path: Path,
    *,
    deadline: float | None = None,
    cancel_check: Callable[[], None] | None = None,
    max_bytes: int | None = None,
) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        before = os.fstat(handle.fileno())
        if before.st_nlink != 1:
            raise BridgeError(
                "E_HARDLINK_DENIED",
                "Hard-linked files cannot be hashed across the CSP asset boundary",
                stage="validation",
                details={"linkCount": before.st_nlink},
            )
        if max_bytes is not None and before.st_size > max_bytes:
            raise BridgeError(
                "E_FILE_TOO_LARGE",
                "File exceeds the bounded SHA-256 policy",
                stage="validation",
                details={"size": before.st_size, "maxBytes": max_bytes},
            )
        while True:
            if cancel_check is not None:
                cancel_check()
            if deadline is not None and time.monotonic() >= deadline:
                raise BridgeError(
                    "E_UI_TIMEOUT",
                    "SHA-256 computation exceeded the operation deadline",
                    retryable=True,
                )
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(handle.fileno())
        if (
            before.st_dev,
            before.st_ino,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise BridgeError("E_FILE_CHANGED", "File changed while SHA-256 was computed", retryable=True)
    return digest.hexdigest().upper()
