from __future__ import annotations

import hashlib
import json
import math
import os
import secrets
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

from .config import Settings, load_auto_actions, load_commands, load_settings
from .errors import BridgeError, ok_result
from .policy import PathIntent, PathPolicy, file_sha256
from . import win32_backend as win


_PRODUCTION_COMMANDS: dict[str, tuple[tuple[str, ...], str, str, bool]] = {
    "ui.cancel": (("ESCAPE",), "ui", "low", False),
    "document.new_dialog": (("CTRL", "N"), "ui", "low", False),
    "document.open_dialog": (("CTRL", "O"), "ui", "low", False),
    "edit.undo": (("CTRL", "Z"), "document", "modify", False),
    "edit.redo": (("CTRL", "Y"), "document", "modify", False),
    "selection.all": (("CTRL", "A"), "document", "modify", False),
    "selection.deselect": (("CTRL", "D"), "document", "modify", False),
    "document.save_as_dialog": (("CTRL", "SHIFT", "S"), "ui", "low", False),
    "document.close": (("CTRL", "W"), "document", "destructive", True),
}
_SEQUENCE_SAFE_COMMANDS = {"edit.undo", "edit.redo", "selection.all", "selection.deselect"}
_MAX_HASH_BYTES = 8 * 1024 * 1024 * 1024
_HASH_TIMEOUT_SECONDS = 30.0


@dataclass
class CaptureEntry:
    capture_id: str
    created_monotonic: float
    created_at: str
    hwnd: int
    pid: int
    foreground_hwnd: int
    last_input_tick: int
    control_generation: int
    window_fingerprint: str
    region: tuple[float, float, float, float] | None
    capture_max_width: int
    data: win.CaptureData
    authorizable: bool = True
    authorization_denial_reason: str | None = None


@dataclass
class ConfirmationEntry:
    token: str
    created_monotonic: float
    expires_monotonic: float
    operation: str
    identifier: str
    capture_id: str
    path: str
    file_fingerprint: str
    control_generation: int
    main_hwnd: int
    dialog_hwnd: int
    main_fingerprint: str
    dialog_fingerprint: str
    last_input_tick: int
    parameters_json: str = ""
    used: bool = False


class ControlLease:
    def __init__(self, local_lock: threading.Lock, cross_process: win.CrossProcessMutexLease) -> None:
        self.local_lock = local_lock
        self.cross_process = cross_process
        self._released = False

    def release(self) -> None:
        if self._released:
            return
        try:
            self.cross_process.release()
        finally:
            self.local_lock.release()
            self._released = True


def validate_registry_entry(entry: dict[str, Any], *, kind: str) -> None:
    identifier = str(entry.get("id", ""))
    if not identifier or kind not in {"command", "auto_action"}:
        raise RuntimeError(f"Invalid {kind} registry entry")
    if type(entry.get("enabled")) is not bool or type(entry.get("requires_confirmation")) is not bool:
        raise RuntimeError(f"{identifier}: enabled and requires_confirmation must be JSON booleans")
    keys = win.validate_keys(entry.get("keys", []))
    key_set = set(keys)
    if "WIN" in key_set:
        raise RuntimeError(f"{identifier}: Windows-key shortcuts are denied")
    denied_combinations = [
        {"ALT", "F4"},
        {"ALT", "TAB"},
        {"ALT", "ESCAPE"},
        {"CTRL", "ESCAPE"},
        {"CTRL", "ALT", "DELETE"},
    ]
    if any(combination <= key_set for combination in denied_combinations):
        raise RuntimeError(f"{identifier}: system shortcut is denied")
    if key_set <= {"CTRL", "SHIFT", "ALT", "WIN"}:
        raise RuntimeError(f"{identifier}: shortcut must contain a non-modifier key")
    risk = str(entry.get("risk", ""))
    effect = str(entry.get("effect", ""))
    if risk not in {"low", "modify", "destructive"}:
        raise RuntimeError(f"{identifier}: unsupported risk classification")
    if effect not in {"ui", "document", "filesystem"}:
        raise RuntimeError(f"{identifier}: unsupported effect classification")
    if risk == "destructive" and not entry.get("requires_confirmation", False):
        raise RuntimeError(f"{identifier}: destructive binding requires confirmation")
    # A shortcut has no path argument, so the server cannot prove that a file
    # write remains inside PathPolicy. File writes must go through the native
    # dialog tools, which validate the exact path immediately before input.
    if effect == "filesystem":
        raise RuntimeError(f"{identifier}: unbounded filesystem shortcut is denied")
    if kind == "command":
        expected = _PRODUCTION_COMMANDS.get(identifier)
        actual = (tuple(keys), effect, risk, entry["requires_confirmation"])
        if expected is None or actual != expected:
            raise RuntimeError(f"{identifier}: command does not match the pinned production binding")
    if kind == "auto_action":
        modifiers = key_set & {"CTRL", "SHIFT", "ALT", "WIN"}
        non_modifiers = [key for key in keys if key not in {"CTRL", "SHIFT", "ALT", "WIN"}]
        safe_function_keys = {f"F{index}" for index in range(1, 13)}
        if (
            len(non_modifiers) != 1
            or non_modifiers[0] not in safe_function_keys
            or modifiers not in ({"CTRL", "ALT"}, {"CTRL", "ALT", "SHIFT"})
        ):
            raise RuntimeError(
                f"{identifier}: Auto Action shortcut must be Ctrl+Alt+[Shift]+F1..F12"
            )
        if entry.get("attested_no_file_io") is not True:
            raise RuntimeError(f"{identifier}: Auto Action must attest that it contains no file I/O")
        if effect != "ui" or risk != "low":
            if not entry.get("requires_confirmation", False):
                raise RuntimeError(f"{identifier}: modifying Auto Action requires confirmation")


class CspController:
    def __init__(self) -> None:
        self.settings: Settings = load_settings()
        self.commands = load_commands()
        self.auto_actions = load_auto_actions()
        for entry in self.commands.values():
            validate_registry_entry(entry, kind="command")
        for entry in self.auto_actions.values():
            validate_registry_entry(entry, kind="auto_action")
        self.path_policy = PathPolicy(self.settings)
        self._control_lock = threading.Lock()
        self._control_generation = win.ControlGeneration("Local\\CspLocalMcp.Generation.v1")
        self._cache_lock = threading.RLock()
        self._captures: dict[str, CaptureEntry] = {}
        self._confirmations: dict[str, ConfirmationEntry] = {}
        self._owned_input_tick: int | None = None
        self._state_counter = 0
        self._cancel_local = threading.local()

    def invoke_with_cancellation(
        self,
        operation: Callable[..., Any],
        cancel_event: threading.Event,
        *args: Any,
    ) -> Any:
        """Run one tool operation with a thread-local cooperative cancellation token."""
        self._cancel_local.event = cancel_event
        try:
            self._check_cancelled()
            return operation(*args)
        finally:
            try:
                del self._cancel_local.event
            except AttributeError:
                pass

    def _current_cancel_event(self) -> threading.Event | None:
        event = getattr(self._cancel_local, "event", None)
        return event if isinstance(event, threading.Event) else None

    def _check_cancelled(self, *, state_change: str = "none") -> None:
        event = self._current_cancel_event()
        if event is not None and event.is_set():
            raise BridgeError(
                "E_CANCELLED",
                "The MCP client cancelled this operation",
                retryable=True,
                state_change=state_change,
                recovery=["Call csp_get_state and csp_capture before retrying"],
            )

    def _hash_file(self, path: Path, *, deadline: float | None = None) -> str:
        return file_sha256(
            path,
            deadline=deadline if deadline is not None else time.monotonic() + _HASH_TIMEOUT_SECONDS,
            cancel_check=self._check_cancelled,
            max_bytes=_MAX_HASH_BYTES,
        )

    def _identity(self) -> dict[str, Any]:
        path = self.settings.csp_executable
        # The executable is only ~95 MB on the pinned profile. Recompute the
        # signature and hash on every call rather than trusting mutable stat
        # metadata as a cache key.
        identity = win.binary_identity(path)
        identity["pathMatches"] = (
            os.path.normcase(os.path.abspath(identity.get("path", "")))
            == os.path.normcase(os.path.abspath(str(path)))
        )
        company = str(identity.get("company", ""))
        identity["companyMatches"] = self.settings.expected_company_contains.casefold() in company.casefold()
        identity["versionAllowed"] = identity.get("fileVersion") in self.settings.allowed_file_versions
        identity["sha256Allowed"] = str(identity.get("sha256", "")).upper() in self.settings.allowed_sha256
        identity["supported"] = all(
            [
                identity.get("exists"), identity.get("signatureValid"), identity["pathMatches"],
                identity["companyMatches"], identity["versionAllowed"], identity["sha256Allowed"],
            ]
        )
        return identity

    def _assert_binary(self) -> dict[str, Any]:
        identity = self._identity()
        if not identity.get("exists"):
            raise BridgeError("E_CSP_NOT_RUNNING", "Configured CSP executable is missing")
        if not identity.get("signatureValid") or not identity.get("companyMatches"):
            raise BridgeError("E_SIGNATURE_INVALID", "CSP signature or signed publisher does not match policy")
        if not identity.get("versionAllowed") or not identity.get("sha256Allowed"):
            raise BridgeError(
                "E_VERSION_UNSUPPORTED",
                "Installed CSP binary differs from the validated production profile",
                details={"fileVersion": identity.get("fileVersion"), "profileId": self.settings.profile_id},
            )
        return identity

    def _shortcut_profile_status(self) -> dict[str, Any]:
        files: list[dict[str, Any]] = []
        supported = True
        for pinned in self.settings.shortcut_profile_files:
            exists = pinned.path.is_file()
            error = ""
            try:
                actual = self._hash_file(pinned.path) if exists else ""
            except (BridgeError, OSError) as exc:
                actual = ""
                error = exc.code if isinstance(exc, BridgeError) else type(exc).__name__
            matches = exists and actual.upper() == pinned.sha256
            supported = supported and matches
            files.append(
                {
                    "path": str(pinned.path),
                    "exists": exists,
                    "sha256Matches": matches,
                    "expectedSha256": pinned.sha256,
                    "actualSha256": actual.upper(),
                    "error": error,
                }
            )
        return {
            "supported": supported,
            "files": files,
            "boundary": "Pinned CSP shortcut artifacts; CELSYS exposes no public shortcut-query API",
        }

    def _assert_shortcut_profile(self) -> dict[str, Any]:
        status = self._shortcut_profile_status()
        if not status["supported"]:
            raise BridgeError(
                "E_SHORTCUT_PROFILE_MISMATCH",
                "CSP shortcut settings differ from the attested production profile",
                retryable=True,
                details=status,
                recovery=[
                    "Do not run semantic shortcut commands",
                    "Review CSP shortcut settings and update the pinned profile deliberately",
                ],
            )
        return status

    def _target(self, hwnd: int = 0, *, for_input: bool = False) -> win.WindowRecord:
        self._assert_binary()
        record = win.choose_csp_window(self.settings.csp_executable, hwnd or None)
        if for_input and self.settings.strict_profile_for_input:
            if record.dpi != self.settings.expected_dpi:
                raise BridgeError(
                    "E_DPI_PROFILE_MISMATCH",
                    "Window DPI differs from the validated profile",
                    details={"expected": self.settings.expected_dpi, "actual": record.dpi},
                )
            actual_locale = win.current_locale_name()
            if not self.settings.locale_matches(actual_locale):
                raise BridgeError(
                    "E_LOCALE_UNSUPPORTED",
                    "Windows locale differs from the validated profile",
                    details={"expected": self.settings.expected_locale, "actual": actual_locale},
                )
        return record

    def _visible_standard_dialogs(self, record: win.WindowRecord) -> list[win.WindowRecord]:
        return [
            item
            for item in win.list_process_dialogs(
                self.settings.csp_executable,
                record.pid,
                main_hwnd=record.hwnd,
            )
            if item.visible and item.class_name == "#32770"
        ]

    def _revision(self, record: win.WindowRecord, generation: int | None = None) -> str:
        generation = self._control_generation.current() if generation is None else generation
        return f"rev-{generation}-{record.fingerprint[:12]}"

    def _purge_expired(self) -> None:
        now = time.monotonic()
        with self._cache_lock:
            self._captures = {
                key: value for key, value in self._captures.items()
                if now - value.created_monotonic <= self.settings.capture_ttl_seconds
            }
            self._confirmations = {
                key: value for key, value in self._confirmations.items()
                if now <= value.expires_monotonic and not value.used
            }

    def _capture_record(
        self,
        record: win.WindowRecord,
        *,
        region: Sequence[float] | None = None,
        max_width: int | None = None,
        authorizable: bool = True,
        store: bool = True,
    ) -> CaptureEntry:
        width = max_width or self.settings.max_capture_width
        if width < 320 or width > self.settings.max_capture_width:
            raise BridgeError(
                "E_POLICY_DENIED",
                f"max_width must be 320..{self.settings.max_capture_width}",
                stage="validation",
            )
        input_tick_before = win.get_last_input()[0] if authorizable and region is None else 0
        captured_foreground = win.foreground_window()
        capture_target = replace(record, required_foreground_hwnd=captured_foreground)
        data = win.capture_window(
            capture_target,
            region=region,
            max_width=width,
            ignored_overlays=self.settings.capture_ignored_overlays,
        )
        input_tick_after = win.get_last_input()[0] if authorizable and region is None else 0
        standard_dialogs = self._visible_standard_dialogs(record)
        # A clipped full-window capture has a different origin from
        # normalized_point(record, ...), so it must never authorize input.
        capture_authorizable = bool(
            authorizable
            and region is None
            and input_tick_before == input_tick_after
            and data.rect == record.rect
            and win.capture_rect_covers_visible_main_chain(capture_target, data.rect)
            and not standard_dialogs
        )
        denial_reason = None
        if standard_dialogs:
            denial_reason = "standardDialogRequiresDedicatedTool"
        elif region is not None:
            denial_reason = "regionCaptureCannotAuthorizeInput"
        elif data.rect != record.rect:
            denial_reason = "windowNotFullyVisible"
        elif input_tick_before != input_tick_after:
            denial_reason = "inputOccurredDuringCapture"
        elif authorizable and not capture_authorizable:
            denial_reason = "captureOwnershipCouldNotBeProved"
        entry = CaptureEntry(
            capture_id=str(uuid.uuid4()),
            created_monotonic=time.monotonic(),
            created_at=datetime.now(timezone.utc).isoformat(),
            hwnd=record.hwnd,
            pid=record.pid,
            foreground_hwnd=captured_foreground,
            last_input_tick=input_tick_after,
            control_generation=self._control_generation.current(),
            window_fingerprint=record.fingerprint,
            region=tuple(float(value) for value in region) if region is not None else None,
            capture_max_width=width,
            data=data,
            authorizable=capture_authorizable,
            authorization_denial_reason=denial_reason,
        )
        if store:
            self._store_capture(entry)
        return entry

    def _store_capture(self, entry: CaptureEntry) -> None:
        self._purge_expired()
        with self._cache_lock:
            self._captures[entry.capture_id] = entry
            while len(self._captures) > 8:
                oldest = min(self._captures.values(), key=lambda item: item.created_monotonic)
                self._captures.pop(oldest.capture_id, None)

    def _capture_public(self, entry: CaptureEntry) -> dict[str, Any]:
        return {
            "captureId": entry.capture_id,
            "createdAt": entry.created_at,
            "expiresInSeconds": self.settings.capture_ttl_seconds,
            "windowId": str(entry.hwnd),
            "processId": entry.pid,
            "foregroundWindowId": str(entry.foreground_hwnd),
            "lastInputTick": entry.last_input_tick,
            "controlGeneration": entry.control_generation,
            "windowFingerprint": entry.window_fingerprint,
            "region": list(entry.region) if entry.region else None,
            "ignoredOverlayWindowIds": list(entry.data.ignored_overlays),
            "captureMaxWidth": entry.capture_max_width,
            "authorizableForInput": entry.authorizable,
            "inputAuthorizationBlockedBy": entry.authorization_denial_reason,
            "width": entry.data.width,
            "height": entry.data.height,
            "sourceWidth": entry.data.source_width,
            "sourceHeight": entry.data.source_height,
            "screenRect": list(entry.data.rect),
            "sha256": entry.data.sha256,
            "luminanceStddev": entry.data.luminance_stddev,
        }

    def _capture_entry(self, capture_id: str) -> CaptureEntry:
        self._purge_expired()
        with self._cache_lock:
            entry = self._captures.get(capture_id)
        if entry is None:
            raise BridgeError(
                "E_STALE_CAPTURE",
                "Capture is missing or expired; call csp_capture again",
                retryable=True,
                recovery=["Call csp_capture", "Retry with the new captureId"],
            )
        return entry

    def _assert_capture_matches(self, capture_id: str, record: win.WindowRecord) -> CaptureEntry:
        entry = self._capture_entry(capture_id)
        if not entry.authorizable:
            raise BridgeError(
                "E_STALE_CAPTURE",
                "Capture was already invalidated by an input operation; it remains available only for comparison",
                retryable=True,
                recovery=["Call csp_capture again before another input operation"],
            )
        if entry.control_generation != self._control_generation.current():
            entry.authorizable = False
            raise BridgeError(
                "E_STALE_CAPTURE",
                "Another MCP process sent CSP input after this capture",
                retryable=True,
                recovery=["Call csp_capture again"],
            )
        if entry.region is not None:
            raise BridgeError(
                "E_STALE_CAPTURE",
                "Region captures cannot authorize input; capture the full CSP window",
                retryable=True,
                recovery=["Call csp_capture without region"],
            )
        if entry.hwnd != record.hwnd or entry.pid != record.pid or entry.window_fingerprint != record.fingerprint:
            raise BridgeError(
                "E_STALE_CAPTURE",
                "CSP window moved, resized, changed title, or restarted after capture",
                retryable=True,
                details={"expectedWindowId": str(entry.hwnd), "actualWindowId": str(record.hwnd)},
                recovery=["Call csp_capture after the window is stable"],
            )
        current_input_tick = win.get_last_input()[0]
        if current_input_tick != entry.last_input_tick:
            entry.authorizable = False
            raise BridgeError(
                "E_USER_INTERRUPTED",
                "Any keyboard or mouse input after capture invalidates input authority",
                retryable=True,
                details={
                    "captureLastInputTick": entry.last_input_tick,
                    "currentLastInputTick": current_input_tick,
                },
                recovery=[
                    "Complete any Codex write approval first",
                    "Call csp_capture again",
                    "Retry with the new captureId",
                ],
            )
        if win.foreground_window() != entry.foreground_hwnd:
            raise BridgeError(
                "E_STALE_CAPTURE",
                "The active CSP window or dialog changed after capture",
                retryable=True,
                recovery=["Call csp_capture again"],
            )
        current = win.capture_window(
            record,
            max_width=entry.capture_max_width,
            ignored_overlays=self.settings.capture_ignored_overlays,
        )
        if win.get_last_input()[0] != current_input_tick:
            entry.authorizable = False
            raise BridgeError(
                "E_USER_INTERRUPTED",
                "Keyboard or mouse input occurred while validating the capture",
                retryable=True,
                recovery=["Call csp_capture again"],
            )
        difference = win.visual_difference(entry.data.png, current.png)
        if current.sha256 != entry.data.sha256:
            raise BridgeError(
                "E_STALE_CAPTURE",
                "Visible CSP pixels changed after capture",
                retryable=True,
                details={"visualDifferenceRatio": difference, "exactPixelMatchRequired": True},
                recovery=["Call csp_capture again and reassess the visible UI"],
            )
        return entry

    def activity(self) -> dict[str, Any]:
        tick, elapsed = win.get_last_input()
        pressed = win.pressed_input_keys()
        # GetLastInputInfo has no trustworthy per-event provenance. Never
        # exempt a recent event as "ours": a human event can race between
        # SendInput and sampling and would otherwise be misclassified.
        owned = False
        active = bool(pressed) or elapsed < self.settings.quiet_period_ms
        return {
            "userActive": active,
            "millisecondsSinceLastInput": elapsed,
            "quietPeriodRequiredMs": self.settings.quiet_period_ms,
            "lastInputOwnedByMcp": owned,
            "pressedInputs": pressed,
            "controlLocked": self._control_lock.locked(),
        }

    def _wait_for_quiet(self) -> dict[str, Any]:
        deadline = time.monotonic() + self.settings.quiet_wait_timeout_ms / 1000
        while True:
            self._check_cancelled()
            state = self.activity()
            if not state["userActive"]:
                return state
            if time.monotonic() >= deadline:
                raise BridgeError(
                    "E_USER_ACTIVE",
                    "Recent human input or a held key prevents CSP automation",
                    retryable=True,
                    recovery=["Stop using the keyboard and mouse briefly, then retry"],
                )
            time.sleep(0.1)

    def _mark_owned_input(self) -> None:
        # Kept as a compatibility hook for response warnings. Safety decisions
        # intentionally do not attribute the global last-input tick to MCP.
        self._owned_input_tick = None

    def _mark_owned_input_best_effort(self) -> str | None:
        try:
            self._mark_owned_input()
            return None
        except Exception as exc:
            # Failure to attribute our last input causes only a conservative
            # quiet-period wait on the next call. It must never prevent global
            # capture invalidation after input was already sent.
            return f"Input was sent, but activity attribution failed: {type(exc).__name__}."

    def _record_control_state_change(self) -> None:
        """Invalidate capture-bound authority locally and in every MCP process."""
        self._control_generation.advance()
        self._state_counter += 1
        with self._cache_lock:
            for entry in self._captures.values():
                entry.authorizable = False
            for confirmation in self._confirmations.values():
                confirmation.used = True

    def _locked(self) -> ControlLease:
        self._check_cancelled()
        if not self._control_lock.acquire(timeout=2):
            raise BridgeError("E_BUSY", "Another CSP tool call owns the input lock", retryable=True)
        cross_process = win.acquire_control_mutex("Local\\CspLocalMcp.Control.v1", timeout_ms=2000)
        if cross_process is None:
            self._control_lock.release()
            raise BridgeError("E_BUSY", "Another MCP client owns the CSP input lock", retryable=True)
        if cross_process.abandoned:
            # Windows transferred an abandoned mutex to us. The previous
            # process may have crashed after sending only part of an input
            # sequence, so invalidate all capture authority before recovery.
            try:
                # Abandonment does not prove that the prior owner held a
                # synthetic key/button. Blind global key-up events could
                # disrupt a human drag or shortcut in another application.
                self._record_control_state_change()
            finally:
                cross_process.release()
                self._control_lock.release()
            raise BridgeError(
                "E_RECOVERY_REQUIRED",
                "A previous MCP process abandoned the CSP input lock; visible state may have changed",
                retryable=True,
                state_change="possible",
                details={
                    "syntheticInputReleaseAttempted": False,
                    "reason": "Mutex abandonment cannot identify which input, if any, was held",
                },
                recovery=[
                    "Release any held keyboard keys or mouse buttons manually",
                    "Call csp_get_state",
                    "Call csp_capture",
                    "Retry only after reassessing CSP",
                ],
            )
        try:
            self._check_cancelled()
        except BridgeError:
            cross_process.release()
            self._control_lock.release()
            raise
        return ControlLease(self._control_lock, cross_process)

    def _prepare_input(
        self,
        hwnd: int,
        capture_id: str | None,
        *,
        require_capture: bool,
        allow_standard_dialog: bool = False,
    ) -> tuple[win.WindowRecord, CaptureEntry | None, str]:
        if require_capture and not capture_id:
            raise BridgeError(
                "E_STALE_CAPTURE",
                "This input operation requires a non-empty captureId",
                retryable=True,
                recovery=["Call csp_capture", "Retry with its captureId"],
            )
        self._wait_for_quiet()
        record = self._target(hwnd, for_input=True)
        standard_dialogs = self._visible_standard_dialogs(record)
        if not allow_standard_dialog:
            dialogs = standard_dialogs
            if dialogs:
                raise BridgeError(
                    "E_DEDICATED_DIALOG_TOOL_REQUIRED",
                    "Generic CSP input is disabled while a standard dialog is visible",
                    retryable=True,
                    details={"dialogIds": [str(item.hwnd) for item in dialogs]},
                    recovery=[
                        "Use csp_native_file_dialog for an Open or Save dialog",
                        "Use csp_cancel only to dismiss an unrelated dialog",
                    ],
                )
        entry = self._capture_entry(capture_id) if capture_id else None
        if entry is None:
            input_tick = win.get_last_input()[0]
            if standard_dialogs:
                if len(standard_dialogs) != 1:
                    raise BridgeError(
                        "E_AMBIGUOUS_TARGET",
                        "Exactly one standard dialog is required for generic cancellation",
                        retryable=True,
                    )
                dialog = win.focus_window(
                    standard_dialogs[0].hwnd,
                    restore=True,
                    expected=standard_dialogs[0],
                    expected_input_tick=input_tick,
                )
                record = replace(record, required_foreground_hwnd=dialog.hwnd)
            else:
                record = win.focus_window(
                    record.hwnd,
                    restore=True,
                    expected=record,
                    expected_input_tick=input_tick,
                )
        elif record.minimized:
            raise BridgeError(
                "E_STALE_CAPTURE",
                "A capture-bound operation cannot restore a minimized window",
                retryable=True,
                recovery=["Call csp_focus", "Call csp_capture again"],
            )
        self._wait_for_quiet()
        if entry is not None:
            record = replace(record, required_foreground_hwnd=entry.foreground_hwnd)
        win.assert_foreground_target(record)
        entry = self._assert_capture_matches(capture_id, record) if capture_id else None
        win.assert_foreground_target(record)
        self._check_cancelled()
        return record, entry, self._revision(record)

    def _verified_input(
        self,
        *,
        hwnd: int,
        capture_id: str | None,
        operation: Callable[[win.WindowRecord], Any],
        state_change: str,
        require_capture: bool = True,
        allow_standard_dialog: bool = False,
    ) -> dict[str, Any]:
        lock = self._locked()
        try:
            record, before_capture, before_revision = self._prepare_input(
                hwnd,
                capture_id,
                require_capture=require_capture,
                allow_standard_dialog=allow_standard_dialog,
            )
            if before_capture is None and not record.minimized:
                before_capture = self._capture_record(record, authorizable=False)
            if not allow_standard_dialog:
                dialogs = self._visible_standard_dialogs(record)
                if dialogs:
                    raise BridgeError(
                        "E_DEDICATED_DIALOG_TOOL_REQUIRED",
                        "A standard CSP dialog appeared immediately before generic input",
                        retryable=True,
                        details={"dialogIds": [str(item.hwnd) for item in dialogs]},
                    )
            if capture_id and before_capture is not None:
                final_input_tick = win.get_last_input()[0]
                if final_input_tick != before_capture.last_input_tick or win.pressed_input_keys():
                    before_capture.authorizable = False
                    raise BridgeError(
                        "E_USER_INTERRUPTED",
                        "Keyboard or mouse state changed immediately before CSP input",
                        retryable=True,
                        recovery=["Repeat preflight", "Capture again", "Retry the exact operation"],
                    )
            try:
                result = operation(record)
            except BridgeError as exc:
                if capture_id:
                    with self._cache_lock:
                        entry = self._captures.get(capture_id)
                        if entry is not None:
                            entry.authorizable = False
                # Once the operation callback starts, fail closed across all
                # MCP processes even when a lower layer cannot prove whether
                # Windows accepted an event before the error.
                self._record_control_state_change()
                raise
            except Exception as exc:
                if capture_id:
                    with self._cache_lock:
                        entry = self._captures.get(capture_id)
                        if entry is not None:
                            entry.authorizable = False
                self._record_control_state_change()
                self._mark_owned_input_best_effort()
                raise BridgeError(
                    "E_PARTIAL_COMPLETION",
                    f"Windows input failed: {type(exc).__name__}",
                    state_change="possible",
                    details={
                        "syntheticInputReleaseAttempted": False,
                        "reason": "Unknown exceptions do not identify which key or button, if any, is held",
                    },
                    recovery=[
                        "Release any held mouse buttons or modifier keys manually",
                        "Call csp_get_state",
                        "Call csp_capture",
                    ],
                ) from exc
            # Old captures stay readable for before/after comparison but become
            # unusable as authorization for subsequent input in every process.
            self._record_control_state_change()
            tracking_warning = self._mark_owned_input_best_effort()
            tracking_warnings = [tracking_warning] if tracking_warning else []
            time.sleep(0.25)
            try:
                refreshed = self._target(record.hwnd, for_input=False)
            except BridgeError as exc:
                return ok_result(
                    result if isinstance(result, dict) else {"value": result},
                    state_change=state_change,
                    before=before_revision,
                    after=None,
                    verification={"method": ["SendInput"], "confidence": 0.55},
                    warnings=[
                        f"Input was sent, but post-operation window verification failed: {exc.code}.",
                        "Call csp_get_state before any further action.",
                        *tracking_warnings,
                    ],
                )
            after_capture: CaptureEntry | None = None
            difference: float | None = None
            after_revision = self._revision(refreshed)
            try:
                if not refreshed.minimized:
                    after_capture = self._capture_record(refreshed, authorizable=False)
                    if before_capture:
                        difference = win.visual_difference(before_capture.data.png, after_capture.data.png)
            except BridgeError as exc:
                return ok_result(
                    result if isinstance(result, dict) else {"value": result},
                    state_change=state_change,
                    before=before_revision,
                    after=after_revision,
                    verification={"method": ["SendInput", "windowIdentity"], "confidence": 0.6},
                    warnings=[
                        f"Input was sent, but post-operation screenshot verification failed: {exc.code}.",
                        "Call csp_get_state and csp_capture before any further action.",
                        *tracking_warnings,
                    ],
                )
            verification = {
                "method": ["foregroundTarget", "screenshot"] if after_capture else ["foregroundTarget"],
                "confidence": 0.85 if after_capture else 0.65,
                "captureId": after_capture.capture_id if after_capture else None,
                "visualDifferenceRatio": difference,
            }
            return ok_result(
                result if isinstance(result, dict) else {"value": result},
                state_change=state_change,
                before=before_revision,
                after=after_revision,
                verification=verification,
                warnings=[
                    "Screenshot verification confirms visible change only; CSP exposes no semantic object API.",
                    *tracking_warnings,
                ],
            )
        finally:
            lock.release()

    def health(self) -> dict[str, Any]:
        identity = self._identity()
        windows = win.enum_csp_windows(self.settings.csp_executable)
        return ok_result(
            {
                "service": "csp-local-mcp",
                "version": "1.1.0",
                "transport": "stdio",
                "profileId": self.settings.profile_id,
                "binary": identity,
                "shortcutProfile": self._shortcut_profile_status(),
                "cspRunning": bool(windows),
                "mainWindowCount": len(windows),
                "locale": win.current_locale_name(),
                "displayInventory": win.display_inventory(),
                "activity": self.activity(),
            },
            verification={"method": ["WinVerifyTrust", "processEnumeration"], "confidence": 1.0},
        )

    def capabilities(self, hwnd: int = 0) -> dict[str, Any]:
        identity = self._identity()
        record: win.WindowRecord | None = None
        reason = None
        try:
            record = self._target(hwnd, for_input=False)
        except BridgeError as exc:
            reason = exc.code
        capture_ready = False
        capture_reason = reason
        if record is not None:
            capture_ready, capture_reason = win.capture_readiness(record, self.settings.capture_ignored_overlays)
        input_capture_ready = bool(
            capture_ready
            and record
            and win.capture_rect_covers_visible_main_chain(record, record.rect)
        )
        profile_matches = bool(
            record
            and record.dpi == self.settings.expected_dpi
            and self.settings.locale_matches(win.current_locale_name())
            and identity.get("supported")
        )
        enabled_actions = [item for item in self.auto_actions.values() if item.get("enabled", False)]
        shortcut_profile = self._shortcut_profile_status()
        valid_dialogs: list[win.WindowRecord] = []
        invalid_dialog_count = 0
        if record is not None:
            for dialog in win.list_process_dialogs(
                self.settings.csp_executable,
                record.pid,
                main_hwnd=record.hwnd,
            ):
                if dialog.class_name != "#32770":
                    continue
                try:
                    win.validate_native_file_dialog(dialog.hwnd)
                    valid_dialogs.append(dialog)
                except BridgeError:
                    invalid_dialog_count += 1
        root_status: list[dict[str, Any]] = []
        for root in self.settings.path_roots:
            try:
                root_path = self.path_policy.root_path(root.id, require_read=root.read)
                access_ok = (not root.read or os.access(root_path, os.R_OK)) and (
                    not root.write or os.access(root_path, os.W_OK)
                )
                root_status.append(
                    {"id": root.id, "available": access_ok, "read": root.read, "write": root.write}
                )
            except (BridgeError, OSError) as exc:
                root_status.append(
                    {
                        "id": root.id,
                        "available": False,
                        "read": root.read,
                        "write": root.write,
                        "reason": exc.code if isinstance(exc, BridgeError) else type(exc).__name__,
                    }
                )
        file_exchange_ready = all(item["available"] for item in root_status)
        input_root_ready = any(item["id"] == "input" and item["available"] for item in root_status)
        capabilities = {
            "processAndSignature": {"available": bool(identity.get("supported")), "backend": "WinVerifyTrust"},
            "windowState": {"available": record is not None, "backend": "Win32"},
            "windowCapture": {"available": capture_ready, "backend": "Pillow ImageGrab", "reason": capture_reason},
            "visibleUiInput": {
                "available": profile_matches and input_capture_ready,
                "backend": "Win32 SendInput",
                "reason": None if input_capture_ready else "E_CAPTURE_COORDINATE_MISMATCH",
            },
            "unicodeText": {"available": profile_matches and input_capture_ready, "backend": "KEYEVENTF_UNICODE"},
            "registeredCommands": {
                "available": profile_matches and input_capture_ready and shortcut_profile["supported"],
                "count": sum(bool(x.get("enabled")) for x in self.commands.values()),
                "shortcutProfile": shortcut_profile,
            },
            "registeredAutoActions": {
                "available": profile_matches and input_capture_ready and shortcut_profile["supported"] and bool(enabled_actions),
                "count": len(enabled_actions),
                "shortcutProfile": shortcut_profile,
            },
            "safeFileOpen": {"available": bool(identity.get("supported")) and input_root_ready, "backend": "fixed executable argv"},
            "nativeFileDialog": {
                "available": len(valid_dialogs) == 1,
                "backend": "strict Win32 file-dialog profile",
                "validDialogCount": len(valid_dialogs),
                "invalidDialogCount": invalid_dialog_count,
            },
            "fileExchange": {"available": file_exchange_ready, "roots": root_status},
            "uiaSemanticControls": {"available": False, "reason": "CSP exposes only unnamed custom panes"},
            "layerObjectApi": {"available": False, "reason": "CELSYS provides no public general editor API"},
            "clipBinaryMutation": {"available": False, "reason": "Undocumented format; intentionally denied"},
            "syntheticPenPressure": {"available": False, "reason": "Mouse SendInput has no trusted pressure channel"},
            "headlessMode": {"available": False, "reason": "CSP has no public headless CLI"},
        }
        return ok_result({"profileMatches": profile_matches, "capabilities": capabilities})

    def list_windows(self) -> dict[str, Any]:
        identity = self._identity()
        windows = win.enum_csp_windows(self.settings.csp_executable)
        return ok_result(
            {"binary": identity, "windows": [record.public() for record in windows]},
            verification={"method": ["processPath", "Win32EnumWindows"], "confidence": 1.0},
        )

    def get_state(self, hwnd: int = 0, include_dialogs: bool = True) -> dict[str, Any]:
        record: win.WindowRecord | None = None
        dialogs: list[win.WindowRecord] = []
        stable_generation = 0
        stable_foreground = 0
        for _attempt in range(3):
            generation_before = self._control_generation.current()
            input_before = win.get_last_input()[0]
            candidate = self._target(hwnd, for_input=False)
            candidate_dialogs = win.list_process_dialogs(
                self.settings.csp_executable,
                candidate.pid,
                main_hwnd=candidate.hwnd,
            ) if include_dialogs else []
            candidate_foreground = win.foreground_window()
            generation_after = self._control_generation.current()
            input_after = win.get_last_input()[0]
            if generation_before == generation_after and input_before == input_after:
                record = candidate
                dialogs = candidate_dialogs
                stable_generation = generation_after
                stable_foreground = candidate_foreground
                break
        if record is None:
            raise BridgeError(
                "E_CONCURRENT_CHANGE",
                "CSP state changed while a consistent snapshot was being read",
                retryable=True,
                recovery=["Retry csp_get_state after input stops"],
            )
        title = record.title
        dirty = "possible" if title.startswith("*") or title.endswith("*") else "unknown"
        revision = self._revision(record, stable_generation)
        return ok_result(
            {
                "window": record.public(),
                "foreground": stable_foreground == record.hwnd,
                "foregroundWindowId": str(stable_foreground),
                "dirtyState": dirty,
                "dialogs": [item.public() for item in dialogs],
                "stateRevision": revision,
                "observability": "window-level only; CSP does not expose document/layer objects",
            },
            before=revision,
            after=revision,
            verification={"method": ["Win32"], "confidence": 0.9},
        )

    def capture(self, hwnd: int = 0, region: Sequence[float] | None = None, max_width: int | None = None) -> tuple[dict[str, Any], bytes]:
        lock = self._locked()
        try:
            record = self._target(hwnd, for_input=False)
            entry = self._capture_record(record, region=region, max_width=max_width)
            return self._capture_public(entry), entry.data.png
        finally:
            lock.release()

    def compare_captures(self, first_id: str, second_id: str) -> dict[str, Any]:
        first = self._capture_entry(first_id)
        second = self._capture_entry(second_id)
        difference = win.visual_difference(first.data.png, second.data.png)
        return ok_result(
            {
                "firstCaptureId": first_id,
                "secondCaptureId": second_id,
                "visualDifferenceRatio": difference,
                "changed": difference >= 0.002,
            },
            verification={"method": ["downsampledPixelDiff"], "confidence": 0.95},
        )

    def sample_pixel(self, capture_id: str, x: float, y: float) -> dict[str, Any]:
        entry = self._capture_entry(capture_id)
        return ok_result({"captureId": capture_id, "x": x, "y": y, "rgba": win.sample_pixel(entry.data.png, x, y)})

    def inspect_ui(self, hwnd: int = 0, include_dialogs: bool = True, max_items: int = 200) -> dict[str, Any]:
        if max_items < 1 or max_items > 500:
            raise BridgeError("E_POLICY_DENIED", "max_items must be 1..500", stage="validation")
        record = self._target(hwnd, for_input=False)
        children = win.inspect_child_windows(record.hwnd, max_items=max_items)
        dialogs = win.list_process_dialogs(
            self.settings.csp_executable,
            record.pid,
            main_hwnd=record.hwnd,
        ) if include_dialogs else []
        return ok_result(
            {
                "window": record.public(),
                "children": children,
                "dialogs": [item.public() for item in dialogs],
                "limitations": [
                    "CSP is custom-drawn; Win32/UIA does not expose its menus, layers, or tool controls.",
                    "Use csp_capture plus capture-bound normalized input or registered shortcuts."
                ],
            }
        )

    def list_commands(self, category: str = "", available_only: bool = True) -> dict[str, Any]:
        shortcut_profile = self._shortcut_profile_status()
        items = []
        for command in self.commands.values():
            if category and command.get("category") != category:
                continue
            if available_only and (not command.get("enabled", False) or not shortcut_profile["supported"]):
                continue
            item = dict(command)
            item.pop("keys", None)
            items.append(item)
        return ok_result(
            {
                "profileId": self.settings.profile_id,
                "shortcutProfile": shortcut_profile,
                "commands": items,
                "semanticBoundary": "Shortcut semantics are attested by pinned CSP setting files, not an official query API.",
            }
        )

    def list_auto_actions(self) -> dict[str, Any]:
        shortcut_profile = self._shortcut_profile_status()
        items = []
        for action in self.auto_actions.values():
            item = dict(action)
            item.pop("keys", None)
            items.append(item)
        return ok_result(
            {
                "profileId": self.settings.profile_id,
                "shortcutProfile": shortcut_profile,
                "actions": items,
                "setupRequired": not bool(items),
                "note": "Bind Auto Actions to shortcuts inside CSP, then register only those shortcuts in ignored config/auto_actions.local.json."
            }
        )

    def focus(self, hwnd: int = 0) -> dict[str, Any]:
        lock = self._locked()
        try:
            self._wait_for_quiet()
            record = self._target(hwnd, for_input=True)
            self._wait_for_quiet()
            before = self._revision(record)
            input_tick = win.get_last_input()[0]
            record = win.focus_window(
                record.hwnd,
                restore=True,
                expected=record,
                expected_input_tick=input_tick,
            )
            self._record_control_state_change()
            return ok_result(
                {"window": record.public(), "foreground": win.foreground_window() == record.hwnd},
                state_change="confirmed",
                before=before,
                after=self._revision(record),
                verification={"method": ["GetForegroundWindow"], "confidence": 1.0},
            )
        finally:
            lock.release()

    def window_action(self, action: str, hwnd: int = 0) -> dict[str, Any]:
        lock = self._locked()
        try:
            self._wait_for_quiet()
            record = self._target(hwnd, for_input=True)
            self._wait_for_quiet()
            before = self._revision(record)
            input_tick = win.get_last_input()[0]
            record = win.set_window_state(
                record.hwnd,
                action,
                expected=record,
                expected_input_tick=input_tick,
            )
            self._record_control_state_change()
            return ok_result(
                {"window": record.public(), "action": action},
                state_change="confirmed",
                before=before,
                after=self._revision(record),
                verification={"method": ["GetWindowPlacement"], "confidence": 1.0},
            )
        finally:
            lock.release()

    def launch(self, wait_ready_ms: int = 15000) -> dict[str, Any]:
        if wait_ready_ms < 1000 or wait_ready_ms > 30000:
            raise BridgeError("E_POLICY_DENIED", "wait_ready_ms must be 1000..30000", stage="validation")
        self._assert_binary()
        existing = win.enum_csp_windows(self.settings.csp_executable)
        if existing:
            return ok_result({"alreadyRunning": True, "windows": [item.public() for item in existing]})
        lock = self._locked()
        try:
            self._wait_for_quiet()
            self._assert_binary()
            self._check_cancelled()
            self._wait_for_quiet()
            existing = win.enum_csp_windows(self.settings.csp_executable)
            if existing:
                return ok_result(
                    {"alreadyRunning": True, "windows": [item.public() for item in existing]},
                    verification={"method": ["crossProcessLock", "processEnumeration"], "confidence": 1.0},
                )
            process = subprocess.Popen(
                [str(self.settings.csp_executable)],
                cwd=str(self.settings.csp_executable.parent),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
                close_fds=True,
            )
            deadline = time.monotonic() + wait_ready_ms / 1000
            while time.monotonic() < deadline:
                self._check_cancelled(state_change="possible")
                windows = win.enum_csp_windows(self.settings.csp_executable)
                if windows:
                    self._record_control_state_change()
                    return ok_result(
                        {"alreadyRunning": False, "processId": process.pid, "windows": [item.public() for item in windows]},
                        state_change="confirmed",
                        verification={"method": ["processEnumeration"], "confidence": 1.0},
                    )
                if process.poll() is not None:
                    raise BridgeError(
                        "E_CSP_CRASHED",
                        "CSP exited before its main window appeared",
                        state_change="possible",
                        details={"processId": process.pid, "exitCode": process.returncode},
                        recovery=["Inspect CSP logs before retrying"],
                    )
                time.sleep(0.2)
            raise BridgeError(
                "E_UI_TIMEOUT",
                "CSP was launched but no main window appeared before the timeout",
                retryable=True,
                state_change="possible",
                details={"processId": process.pid, "processStillRunning": process.poll() is None},
                recovery=[
                    "Call csp_list_windows before retrying",
                    f"Check processId {process.pid} in Task Manager",
                    "Do not launch a duplicate until the first process state is known",
                ],
            )
        finally:
            lock.release()

    def open_document(self, path: str, wait_ready_ms: int = 15000) -> dict[str, Any]:
        if wait_ready_ms < 1000 or wait_ready_ms > 30000:
            raise BridgeError("E_POLICY_DENIED", "wait_ready_ms must be 1000..30000", stage="validation")
        validated = self.path_policy.validate(path, "input")
        self._assert_binary()
        lock = self._locked()
        try:
            self._wait_for_quiet()
            validated = self.path_policy.validate(path, "input")
            self._assert_binary()
            self._check_cancelled()
            self._wait_for_quiet()
            before_windows = win.enum_csp_windows(self.settings.csp_executable)
            before_titles = {item.hwnd: item.title for item in before_windows}
            process = subprocess.Popen(
                [str(self.settings.csp_executable), str(validated.path)],
                cwd=str(self.settings.csp_executable.parent),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
                close_fds=True,
            )
            self._record_control_state_change()
            deadline = time.monotonic() + wait_ready_ms / 1000
            observed: list[win.WindowRecord] = []
            visible_evidence = False
            while time.monotonic() < deadline:
                self._check_cancelled(state_change="possible")
                observed = win.enum_csp_windows(self.settings.csp_executable)
                visible_evidence = bool(observed and (
                    not before_windows
                    or any(before_titles.get(item.hwnd) != item.title for item in observed)
                ))
                if visible_evidence or (observed and time.monotonic() > deadline - (wait_ready_ms / 1000) + 2):
                    break
                time.sleep(0.2)
            if not observed:
                raise BridgeError(
                    "E_UI_TIMEOUT",
                    "CSP received the document-open request but did not present a main window",
                    retryable=True,
                    state_change="possible",
                    details={"processId": process.pid, "processStillRunning": process.poll() is None},
                    recovery=["Call csp_list_windows before retrying", "Verify the document manually in CSP"],
                )
            return ok_result(
                {
                    "openedPath": str(validated.path),
                    "rootId": validated.root.id,
                    "launchProcessId": process.pid,
                    "windows": [item.public() for item in observed],
                },
                state_change="confirmed" if visible_evidence else "possible",
                verification={
                    "method": ["pathPolicy", "processWindow"],
                    "confidence": 0.8 if visible_evidence else 0.55,
                },
                warnings=[
                    "CSP provides no API to confirm which tab owns the opened path; verify with csp_capture."
                ],
            )
        finally:
            lock.release()

    def _consume_bound_input_confirmation(
        self,
        token: str,
        identifier: str,
        canonical_parameters: str,
        capture_id: str,
        record: win.WindowRecord,
    ) -> ConfirmationEntry:
        return self._consume_confirmation(
            token,
            operation="input",
            identifier=identifier,
            capture_id=capture_id,
            main_hwnd=record.hwnd,
            main_fingerprint=record.fingerprint,
            parameters_json=canonical_parameters,
        )

    def _assert_atomic_capture_boundary(
        self,
        record: win.WindowRecord,
        capture_id: str,
    ) -> int:
        capture = self._capture_entry(capture_id)
        if (
            not capture.authorizable
            or capture.control_generation != self._control_generation.current()
            or win.get_last_input()[0] != capture.last_input_tick
            or win.pressed_input_keys()
        ):
            capture.authorizable = False
            raise BridgeError(
                "E_USER_INTERRUPTED",
                "Input authority changed at the final SendInput boundary",
                retryable=True,
                recovery=["Repeat preflight", "Capture again", "Retry the exact operation"],
            )
        dialogs = self._visible_standard_dialogs(record)
        if dialogs:
            capture.authorizable = False
            raise BridgeError(
                "E_DEDICATED_DIALOG_TOOL_REQUIRED",
                "A standard CSP dialog appeared at the final SendInput boundary",
                retryable=True,
                details={"dialogIds": [str(item.hwnd) for item in dialogs]},
            )
        win.assert_foreground_target(record)
        return capture.last_input_tick

    def move_pointer(
        self,
        x: float,
        y: float,
        region: str,
        capture_id: str,
        confirm_token: str,
        hwnd: int = 0,
    ) -> dict[str, Any]:
        binding, normalized, _metadata = self._normalize_input_binding(
            "csp_move_pointer",
            {"x": x, "y": y, "region": region},
        )
        def operation(record: win.WindowRecord) -> dict[str, Any]:
            self._consume_bound_input_confirmation(confirm_token, "csp_move_pointer", binding, capture_id, record)
            point = win.normalized_point(record, normalized["x"], normalized["y"], normalized["region"])
            approved_tick = self._assert_atomic_capture_boundary(record, capture_id)
            win.move_pointer(*point, target=record, expected_last_input_tick=approved_tick)
            return {"screenPoint": list(point)}
        return self._verified_input(
            hwnd=hwnd,
            capture_id=capture_id,
            operation=operation,
            state_change="confirmed",
        )

    def click(
        self,
        x: float,
        y: float,
        region: str,
        button: str,
        count: int,
        capture_id: str,
        confirm_token: str,
        hwnd: int = 0,
    ) -> dict[str, Any]:
        binding, normalized, _metadata = self._normalize_input_binding(
            "csp_click",
            {"x": x, "y": y, "region": region, "button": button, "count": count},
        )
        def operation(record: win.WindowRecord) -> dict[str, Any]:
            self._consume_bound_input_confirmation(confirm_token, "csp_click", binding, capture_id, record)
            point = win.normalized_point(record, normalized["x"], normalized["y"], normalized["region"])
            approved_tick = self._assert_atomic_capture_boundary(record, capture_id)
            win.click_pointer(
                *point,
                button=normalized["button"],
                count=normalized["count"],
                target=record,
                cancel_event=self._current_cancel_event(),
                expected_last_input_tick=approved_tick,
            )
            return {"screenPoint": list(point), "button": normalized["button"], "count": normalized["count"]}
        return self._verified_input(hwnd=hwnd, capture_id=capture_id, operation=operation, state_change="confirmed")

    def drag(
        self,
        start_x: float,
        start_y: float,
        end_x: float,
        end_y: float,
        region: str,
        button: str,
        duration_seconds: float,
        capture_id: str,
        confirm_token: str,
        hwnd: int = 0,
    ) -> dict[str, Any]:
        binding, normalized, _metadata = self._normalize_input_binding(
            "csp_drag",
            {
                "start_x": start_x,
                "start_y": start_y,
                "end_x": end_x,
                "end_y": end_y,
                "region": region,
                "button": button,
                "duration_seconds": duration_seconds,
            },
        )
        def operation(record: win.WindowRecord) -> dict[str, Any]:
            self._consume_bound_input_confirmation(confirm_token, "csp_drag", binding, capture_id, record)
            start = win.normalized_point(
                record,
                normalized["start_x"],
                normalized["start_y"],
                normalized["region"],
            )
            end = win.normalized_point(
                record,
                normalized["end_x"],
                normalized["end_y"],
                normalized["region"],
            )
            approved_tick = self._assert_atomic_capture_boundary(record, capture_id)
            win.drag_pointer(
                start,
                end,
                button=normalized["button"],
                duration=normalized["duration_seconds"],
                target=record,
                cancel_event=self._current_cancel_event(),
                expected_last_input_tick=approved_tick,
            )
            return {"startScreenPoint": list(start), "endScreenPoint": list(end), "button": normalized["button"]}
        return self._verified_input(hwnd=hwnd, capture_id=capture_id, operation=operation, state_change="confirmed")

    def scroll(
        self,
        x: float,
        y: float,
        region: str,
        delta: int,
        capture_id: str,
        confirm_token: str,
        hwnd: int = 0,
    ) -> dict[str, Any]:
        binding, normalized, _metadata = self._normalize_input_binding(
            "csp_scroll",
            {"x": x, "y": y, "region": region, "delta": delta},
        )
        def operation(record: win.WindowRecord) -> dict[str, Any]:
            self._consume_bound_input_confirmation(confirm_token, "csp_scroll", binding, capture_id, record)
            point = win.normalized_point(record, normalized["x"], normalized["y"], normalized["region"])
            approved_tick = self._assert_atomic_capture_boundary(record, capture_id)
            win.scroll_pointer(
                *point,
                delta=normalized["delta"],
                target=record,
                expected_last_input_tick=approved_tick,
            )
            return {"screenPoint": list(point), "delta": normalized["delta"]}
        return self._verified_input(hwnd=hwnd, capture_id=capture_id, operation=operation, state_change="confirmed")

    def type_text(self, text: str, capture_id: str, confirm_token: str, hwnd: int = 0) -> dict[str, Any]:
        binding, normalized, _metadata = self._normalize_input_binding("csp_type_text", {"text": text})
        def operation(record: win.WindowRecord) -> dict[str, Any]:
            self._consume_bound_input_confirmation(confirm_token, "csp_type_text", binding, capture_id, record)
            approved_tick = self._assert_atomic_capture_boundary(record, capture_id)
            win.send_unicode_text(
                normalized["text"],
                target=record,
                cancel_event=self._current_cancel_event(),
                expected_last_input_tick=approved_tick,
            )
            return {"charactersSent": len(normalized["text"])}
        return self._verified_input(
            hwnd=hwnd,
            capture_id=capture_id,
            operation=operation,
            state_change="confirmed",
        )

    def navigation_key(
        self,
        key: str,
        count: int,
        capture_id: str,
        confirm_token: str,
        hwnd: int = 0,
    ) -> dict[str, Any]:
        binding, normalized, _metadata = self._normalize_input_binding(
            "csp_navigation_key",
            {"key": key, "count": count},
        )
        def operation(record: win.WindowRecord) -> dict[str, Any]:
            self._consume_bound_input_confirmation(confirm_token, "csp_navigation_key", binding, capture_id, record)
            approved_tick = self._assert_atomic_capture_boundary(record, capture_id)
            completed = 0
            try:
                for _index in range(normalized["count"]):
                    self._check_cancelled(state_change="possible" if completed else "none")
                    win.send_chord(
                        [normalized["key"]],
                        target=record,
                        expected_last_input_tick=approved_tick if completed == 0 else None,
                    )
                    completed += 1
                    time.sleep(0.03)
            except BridgeError as exc:
                if completed:
                    raise BridgeError(
                        "E_PARTIAL_COMPLETION",
                        "Repeated navigation input stopped after one or more keys",
                        state_change="possible",
                        details={"completedKeys": completed, "cause": exc.code},
                    ) from exc
                raise
            return {"key": normalized["key"], "count": normalized["count"]}
        return self._verified_input(hwnd=hwnd, capture_id=capture_id, operation=operation, state_change="confirmed")

    def cancel(self, hwnd: int = 0) -> dict[str, Any]:
        return self._verified_input(
            hwnd=hwnd,
            capture_id=None,
            operation=lambda record: (win.send_chord(["ESCAPE"], target=record) or {"key": "ESCAPE"}),
            state_change="confirmed",
            require_capture=False,
            allow_standard_dialog=True,
        )

    @staticmethod
    def _parse_preflight_parameters(parameters_json: str) -> dict[str, Any]:
        if not parameters_json or len(parameters_json) > 65536:
            raise BridgeError(
                "E_POLICY_DENIED",
                "parameters_json must contain a JSON object of at most 65536 characters",
                stage="validation",
            )

        def exact_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError(f"Duplicate JSON key: {key}")
                result[key] = value
            return result

        try:
            value = json.loads(
                parameters_json,
                object_pairs_hook=exact_object,
                parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"Invalid number: {value}")),
            )
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise BridgeError(
                "E_POLICY_DENIED",
                "parameters_json must be strict JSON without duplicate keys or non-finite numbers",
                stage="validation",
            ) from exc
        if type(value) is not dict:
            raise BridgeError("E_POLICY_DENIED", "parameters_json must be a JSON object", stage="validation")
        return value

    @staticmethod
    def _require_parameter_keys(parameters: dict[str, Any], required: set[str]) -> None:
        actual = set(parameters)
        if actual != required:
            raise BridgeError(
                "E_POLICY_DENIED",
                "Preflight parameters do not match the exact tool schema",
                stage="validation",
                details={"required": sorted(required), "actual": sorted(actual)},
            )

    @staticmethod
    def _number_parameter(parameters: dict[str, Any], name: str, minimum: float, maximum: float) -> float:
        value = parameters.get(name)
        if type(value) not in {int, float}:
            raise BridgeError("E_POLICY_DENIED", f"{name} must be a number", stage="validation")
        normalized = float(value)
        if not math.isfinite(normalized) or not minimum <= normalized <= maximum:
            raise BridgeError(
                "E_POLICY_DENIED",
                f"{name} must be between {minimum} and {maximum}",
                stage="validation",
            )
        return normalized

    @staticmethod
    def _integer_parameter(parameters: dict[str, Any], name: str, minimum: int, maximum: int) -> int:
        value = parameters.get(name)
        if type(value) is not int or not minimum <= value <= maximum:
            raise BridgeError(
                "E_POLICY_DENIED",
                f"{name} must be an integer between {minimum} and {maximum}",
                stage="validation",
            )
        return value

    def _normalize_input_binding(
        self,
        identifier: str,
        parameters: dict[str, Any],
    ) -> tuple[str, dict[str, Any], dict[str, Any]]:
        """Return canonical JSON, normalized parameters, and approval metadata."""
        normalized: dict[str, Any]
        metadata: dict[str, Any] = {
            "risk": "open_world",
            "description": "Visible CSP input can reach self-drawn controls; approve the exact parameters only.",
            "dialog": False,
            "path": "",
        }
        regions = {"client", "window"}
        buttons = {"left", "right", "middle"}

        if identifier == "csp_move_pointer":
            self._require_parameter_keys(parameters, {"x", "y", "region"})
            region = parameters["region"]
            if type(region) is not str or region not in regions:
                raise BridgeError("E_POLICY_DENIED", "region must be client or window", stage="validation")
            normalized = {
                "region": region,
                "x": self._number_parameter(parameters, "x", 0.0, 1.0),
                "y": self._number_parameter(parameters, "y", 0.0, 1.0),
            }
            metadata.update(risk="low", description="Move the pointer inside the exact captured CSP region.")
        elif identifier == "csp_click":
            self._require_parameter_keys(parameters, {"x", "y", "region", "button", "count"})
            region = parameters["region"]
            button = parameters["button"]
            if type(region) is not str or region not in regions or type(button) is not str or button not in buttons:
                raise BridgeError("E_POLICY_DENIED", "Invalid click region or button", stage="validation")
            normalized = {
                "button": button,
                "count": self._integer_parameter(parameters, "count", 1, 2),
                "region": region,
                "x": self._number_parameter(parameters, "x", 0.0, 1.0),
                "y": self._number_parameter(parameters, "y", 0.0, 1.0),
            }
            metadata["description"] = "Click the exact normalized point in CSP; the server cannot infer control semantics."
        elif identifier == "csp_drag":
            self._require_parameter_keys(
                parameters,
                {"start_x", "start_y", "end_x", "end_y", "region", "button", "duration_seconds"},
            )
            region = parameters["region"]
            button = parameters["button"]
            if type(region) is not str or region not in regions or type(button) is not str or button not in buttons:
                raise BridgeError("E_POLICY_DENIED", "Invalid drag region or button", stage="validation")
            normalized = {
                "button": button,
                "duration_seconds": self._number_parameter(
                    parameters,
                    "duration_seconds",
                    0.05,
                    self.settings.max_drag_seconds,
                ),
                "end_x": self._number_parameter(parameters, "end_x", 0.0, 1.0),
                "end_y": self._number_parameter(parameters, "end_y", 0.0, 1.0),
                "region": region,
                "start_x": self._number_parameter(parameters, "start_x", 0.0, 1.0),
                "start_y": self._number_parameter(parameters, "start_y", 0.0, 1.0),
            }
            metadata["description"] = "Drag or draw between the exact normalized CSP points."
        elif identifier == "csp_scroll":
            self._require_parameter_keys(parameters, {"x", "y", "region", "delta"})
            region = parameters["region"]
            if type(region) is not str or region not in regions:
                raise BridgeError("E_POLICY_DENIED", "region must be client or window", stage="validation")
            delta = self._integer_parameter(parameters, "delta", -20, 20)
            if delta == 0:
                raise BridgeError("E_POLICY_DENIED", "delta cannot be zero", stage="validation")
            normalized = {
                "delta": delta,
                "region": region,
                "x": self._number_parameter(parameters, "x", 0.0, 1.0),
                "y": self._number_parameter(parameters, "y", 0.0, 1.0),
            }
            metadata["description"] = "Scroll the exact amount at the exact normalized CSP point."
        elif identifier == "csp_type_text":
            self._require_parameter_keys(parameters, {"text"})
            text = parameters["text"]
            if type(text) is not str or not text or len(text) > self.settings.max_text_chars or "\x00" in text:
                raise BridgeError(
                    "E_POLICY_DENIED",
                    f"text must contain 1..{self.settings.max_text_chars} non-NUL characters",
                    stage="validation",
                )
            try:
                text.encode("utf-16-le", "strict")
            except UnicodeEncodeError as exc:
                raise BridgeError(
                    "E_POLICY_DENIED",
                    "text contains an isolated Unicode surrogate",
                    stage="validation",
                ) from exc
            normalized = {"text": text}
            metadata["description"] = "Type the exact Unicode text into the currently focused CSP field."
        elif identifier == "csp_navigation_key":
            self._require_parameter_keys(parameters, {"key", "count"})
            key = parameters["key"]
            allowed = {
                "ESCAPE", "ENTER", "TAB", "LEFT", "RIGHT", "UP", "DOWN", "HOME", "END",
                "PAGEUP", "PAGEDOWN", "BACKSPACE", "DELETE",
            }
            if type(key) is not str or key.upper() not in allowed:
                raise BridgeError("E_POLICY_DENIED", "Navigation key is outside policy", stage="validation")
            normalized = {
                "count": self._integer_parameter(parameters, "count", 1, 20),
                "key": key.upper(),
            }
            metadata["description"] = "Send the exact repeated navigation key to CSP."
        elif identifier == "csp_run_command":
            self._require_parameter_keys(parameters, {"command_id"})
            command_id = parameters["command_id"]
            command = self.commands.get(command_id) if type(command_id) is str else None
            if command is None or not command.get("enabled", False):
                raise BridgeError("E_COMMAND_NOT_ALLOWLISTED", "Command is not registered", stage="validation")
            self._assert_shortcut_profile()
            normalized = {"command_id": command_id}
            metadata.update(risk=command.get("risk", "unknown"), description=command.get("description", "Registered command"))
        elif identifier == "csp_run_auto_action":
            self._require_parameter_keys(parameters, {"action_id"})
            action_id = parameters["action_id"]
            action = self.auto_actions.get(action_id) if type(action_id) is str else None
            if action is None or not action.get("enabled", False):
                raise BridgeError("E_AUTO_ACTION_NOT_ALLOWLISTED", "Auto Action is not registered", stage="validation")
            self._assert_shortcut_profile()
            normalized = {"action_id": action_id}
            metadata.update(risk=action.get("risk", "unknown"), description=action.get("description", "Registered Auto Action"))
        elif identifier == "csp_run_command_sequence":
            self._require_parameter_keys(parameters, {"command_ids"})
            command_ids = parameters["command_ids"]
            if type(command_ids) is not list or not command_ids or len(command_ids) > self.settings.max_macro_steps:
                raise BridgeError(
                    "E_POLICY_DENIED",
                    f"command_ids must contain 1..{self.settings.max_macro_steps} entries",
                    stage="validation",
                )
            for command_id in command_ids:
                command = self.commands.get(command_id) if type(command_id) is str else None
                if command is None or not command.get("enabled", False) or command_id not in _SEQUENCE_SAFE_COMMANDS:
                    raise BridgeError("E_POLICY_DENIED", "Command sequence contains a denied command", stage="validation")
                if command.get("requires_confirmation", False) or command.get("risk") == "destructive":
                    raise BridgeError("E_POLICY_DENIED", "Destructive commands cannot run in a sequence", stage="validation")
            self._assert_shortcut_profile()
            normalized = {"command_ids": list(command_ids)}
            metadata.update(risk="modify", description="Run the exact ordered allowlisted CSP command sequence.")
        elif identifier == "csp_native_file_dialog":
            self._require_parameter_keys(parameters, {"path", "intent", "submit"})
            path = parameters["path"]
            intent = parameters["intent"]
            submit = parameters["submit"]
            if type(path) is not str or type(intent) is not str or intent not in {"input", "output_new", "output_replace"}:
                raise BridgeError("E_POLICY_DENIED", "Invalid native file-dialog path or intent", stage="validation")
            if type(submit) is not bool:
                raise BridgeError("E_POLICY_DENIED", "submit must be a JSON boolean", stage="validation")
            validated = self.path_policy.validate(path, intent)
            normalized = {"intent": intent, "path": str(validated.path), "submit": submit}
            metadata.update(
                risk="destructive" if intent == "output_replace" and submit else "modify",
                description=(
                    "Replace the exact existing output path through the selected CSP dialog."
                    if intent == "output_replace" and submit
                    else "Set or submit the exact policy-approved path through the selected CSP dialog."
                ),
                dialog=True,
                path=str(validated.path),
                intent=intent,
            )
        else:
            raise BridgeError("E_POLICY_DENIED", "Unsupported preflight input tool", stage="validation")

        canonical = json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return canonical, normalized, metadata

    def preflight(
        self,
        operation: str,
        identifier: str,
        parameters_json: str = "",
        capture_id: str = "",
        path: str = "",
        main_hwnd: int = 0,
        dialog_hwnd: int = 0,
    ) -> dict[str, Any]:
        lock = self._locked()
        generation_before = self._control_generation.current()
        try:
            self._wait_for_quiet()
            try:
                return self._preflight_locked(
                    operation,
                    identifier,
                    parameters_json,
                    capture_id,
                    path,
                    main_hwnd,
                    dialog_hwnd,
                )
            except BridgeError as exc:
                if self._control_generation.current() != generation_before and exc.state_change == "none":
                    try:
                        payload = json.loads(str(exc))
                        error = payload.get("error", {})
                    except (TypeError, ValueError, json.JSONDecodeError):
                        error = {}
                    raise BridgeError(
                        exc.code,
                        str(error.get("message", "Preflight failed after attempting to focus CSP")),
                        retryable=bool(error.get("retryable", True)),
                        stage=str(error.get("stage", "operation")),
                        state_change="possible",
                        details={**dict(error.get("details", {})), "controlAuthorityInvalidated": True},
                        recovery=list(payload.get("recovery", [])) if isinstance(locals().get("payload"), dict) else [],
                    ) from exc
                raise
        finally:
            lock.release()

    def _preflight_locked(
        self,
        operation: str,
        identifier: str,
        parameters_json: str = "",
        capture_id: str = "",
        path: str = "",
        main_hwnd: int = 0,
        dialog_hwnd: int = 0,
    ) -> dict[str, Any]:
        if capture_id:
            raise BridgeError(
                "E_POLICY_DENIED",
                "Preflight must run before the authorizing capture",
                stage="validation",
                recovery=["Approve preflight", "Then call csp_capture", "Then execute the exact input"],
            )

        # Compatibility aliases from the first package revision are normalized
        # into the same exact input binding used by every capture-bound tool.
        if operation == "command":
            if parameters_json or path or dialog_hwnd:
                raise BridgeError("E_POLICY_DENIED", "Command alias received unrelated preflight fields", stage="validation")
            parameters = {"command_id": identifier}
            identifier = "csp_run_command"
        elif operation == "auto_action":
            if parameters_json or path or dialog_hwnd:
                raise BridgeError("E_POLICY_DENIED", "Auto Action alias received unrelated preflight fields", stage="validation")
            parameters = {"action_id": identifier}
            identifier = "csp_run_auto_action"
        elif operation == "output_replace":
            if parameters_json:
                raise BridgeError("E_POLICY_DENIED", "Output replacement alias received parameters_json", stage="validation")
            if identifier not in {"", "native_file_dialog", "csp_native_file_dialog"}:
                raise BridgeError(
                    "E_POLICY_DENIED",
                    "Output replacement identifier must be native_file_dialog",
                    stage="validation",
                )
            parameters = {"path": path, "intent": "output_replace", "submit": True}
            identifier = "csp_native_file_dialog"
        elif operation == "input":
            if path:
                raise BridgeError("E_POLICY_DENIED", "input preflight path must be inside parameters_json", stage="validation")
            parameters = self._parse_preflight_parameters(parameters_json)
        else:
            raise BridgeError("E_POLICY_DENIED", "Unsupported preflight operation", stage="validation")

        canonical_parameters, normalized_parameters, metadata = self._normalize_input_binding(identifier, parameters)
        bound_main = self._target(main_hwnd, for_input=True)
        before_revision = self._revision(bound_main)
        bound_dialog: win.WindowRecord | None = None
        focus_input_tick = win.get_last_input()[0]

        if metadata["dialog"] and not dialog_hwnd:
            raise BridgeError(
                "E_CONFIRM_REQUIRED",
                "Native file-dialog preflight requires the exact dialog_hwnd",
                stage="validation",
            )
        if not metadata["dialog"] and dialog_hwnd:
            raise BridgeError("E_POLICY_DENIED", "dialog_hwnd is valid only for native file-dialog input")

        # Invalidate every older capture/token before the first focus attempt.
        # This remains true even if SetForegroundWindow partially succeeds and
        # a later identity or input-tick check fails.
        self._record_control_state_change()

        if metadata["dialog"]:
            dialogs = [
                dialog
                for dialog in win.list_process_dialogs(
                    self.settings.csp_executable,
                    bound_main.pid,
                    main_hwnd=bound_main.hwnd,
                )
                if dialog.class_name == "#32770" and dialog.hwnd == dialog_hwnd
            ]
            if len(dialogs) != 1:
                raise BridgeError(
                    "E_WINDOW_NOT_FOUND",
                    "The exact CSP native file dialog was not found for preflight",
                    retryable=True,
                )
            win.validate_native_file_dialog(dialogs[0].hwnd, metadata["intent"])
            bound_dialog = win.focus_window(
                dialogs[0].hwnd,
                restore=True,
                expected=dialogs[0],
                expected_input_tick=focus_input_tick,
            )
        else:
            if self._visible_standard_dialogs(bound_main):
                raise BridgeError(
                    "E_DEDICATED_DIALOG_TOOL_REQUIRED",
                    "Generic input preflight is unavailable while a standard dialog is visible",
                    retryable=True,
                    recovery=["Use csp_cancel or csp_native_file_dialog first"],
                )
            bound_main = win.focus_window(
                bound_main.hwnd,
                restore=True,
                expected=bound_main,
                expected_input_tick=focus_input_tick,
            )

        snapshot_input_tick = win.get_last_input()[0]
        if snapshot_input_tick != focus_input_tick or win.pressed_input_keys():
            raise BridgeError(
                "E_USER_INTERRUPTED",
                "Keyboard or mouse input occurred while preflight focused CSP",
                retryable=True,
                state_change="possible",
                recovery=["Stop using the keyboard and mouse briefly", "Repeat preflight"],
            )

        refreshed_main = self._target(bound_main.hwnd, for_input=True)
        main_hwnd = refreshed_main.hwnd
        main_fingerprint = refreshed_main.fingerprint
        if bound_dialog is not None:
            refreshed_dialogs = [
                dialog
                for dialog in win.list_process_dialogs(
                    self.settings.csp_executable,
                    refreshed_main.pid,
                    main_hwnd=refreshed_main.hwnd,
                )
                if dialog.class_name == "#32770" and dialog.hwnd == bound_dialog.hwnd
            ]
            if len(refreshed_dialogs) != 1 or refreshed_dialogs[0].fingerprint != bound_dialog.fingerprint:
                raise BridgeError(
                    "E_STALE_CAPTURE",
                    "The exact CSP file dialog changed while preflight focused it",
                    retryable=True,
                    state_change="possible",
                )
            bound_dialog = refreshed_dialogs[0]
            win.validate_native_file_dialog(bound_dialog.hwnd, metadata["intent"])
            if win.foreground_window() != bound_dialog.hwnd:
                raise BridgeError("E_USER_INTERRUPTED", "The exact CSP file dialog is not foreground", retryable=True)
            dialog_hwnd = bound_dialog.hwnd
            dialog_fingerprint = bound_dialog.fingerprint
        else:
            if self._visible_standard_dialogs(refreshed_main):
                raise BridgeError(
                    "E_DEDICATED_DIALOG_TOOL_REQUIRED",
                    "A standard dialog appeared during generic input preflight",
                    retryable=True,
                    state_change="possible",
                )
            if win.foreground_window() != refreshed_main.hwnd:
                raise BridgeError("E_USER_INTERRUPTED", "CSP is not foreground after preflight", retryable=True)
            dialog_hwnd = 0
            dialog_fingerprint = ""

        path = metadata["path"]
        file_fingerprint = ""
        if path and Path(path).is_file():
            before_stat = Path(path).stat()
            digest = self._hash_file(Path(path))
            after_stat = Path(path).stat()
            if (before_stat.st_size, before_stat.st_mtime_ns) != (
                after_stat.st_size,
                after_stat.st_mtime_ns,
            ):
                raise BridgeError("E_FILE_CHANGED", "Target file changed during preflight", retryable=True)
            file_fingerprint = f"{after_stat.st_size}:{after_stat.st_mtime_ns}:{digest}"
        if win.get_last_input()[0] != snapshot_input_tick:
            raise BridgeError(
                "E_USER_INTERRUPTED",
                "Keyboard or mouse input changed during preflight",
                retryable=True,
                recovery=["Repeat preflight after the interface is stable"],
            )
        if self._target(main_hwnd, for_input=True).fingerprint != main_fingerprint:
            raise BridgeError("E_STALE_CAPTURE", "The CSP main window changed during preflight", retryable=True)

        token = secrets.token_urlsafe(32)
        created = time.monotonic()
        entry = ConfirmationEntry(
            token=token,
            created_monotonic=created,
            expires_monotonic=created + self.settings.confirmation_ttl_seconds,
            operation="input",
            identifier=identifier,
            capture_id="",
            path=path,
            file_fingerprint=file_fingerprint,
            control_generation=self._control_generation.current(),
            main_hwnd=main_hwnd,
            dialog_hwnd=dialog_hwnd,
            main_fingerprint=main_fingerprint,
            dialog_fingerprint=dialog_fingerprint,
            last_input_tick=snapshot_input_tick,
            parameters_json=canonical_parameters,
        )
        self._purge_expired()
        with self._cache_lock:
            self._confirmations[token] = entry
        return ok_result(
            {
                "operation": "input",
                "identifier": identifier,
                "parameters": normalized_parameters,
                "risk": metadata["risk"],
                "impact": metadata["description"],
                "confirmToken": token,
                "expiresInSeconds": self.settings.confirmation_ttl_seconds,
                "singleUse": True,
                "captureRequiredAfterPreflight": bound_dialog is None,
                "nextStep": (
                    "Call csp_capture after this approved preflight, then execute with that captureId"
                    if bound_dialog is None
                    else "Execute the exact bound native file-dialog input before the token expires"
                ),
            },
            state_change="confirmed",
            before=before_revision,
            after=self._revision(refreshed_main),
            verification={"method": ["exactWindowIdentity", "foreground", "inputTick"], "confidence": 1.0},
        )

    def _consume_confirmation(
        self,
        token: str,
        *,
        operation: str,
        identifier: str,
        capture_id: str,
        path: str = "",
        main_hwnd: int = 0,
        dialog_hwnd: int = 0,
        main_fingerprint: str = "",
        dialog_fingerprint: str = "",
        parameters_json: str = "",
    ) -> ConfirmationEntry:
        self._purge_expired()
        with self._cache_lock:
            entry = self._confirmations.get(token)
            if entry is None:
                raise BridgeError("E_CONFIRM_EXPIRED", "Confirmation token is invalid or expired", retryable=True)
            if entry.control_generation != self._control_generation.current():
                entry.used = True
                raise BridgeError(
                    "E_CONFIRM_EXPIRED",
                    "Control state changed after preflight",
                    retryable=True,
                )
            if entry.used:
                raise BridgeError("E_CONFIRM_EXPIRED", "Confirmation token was already used", retryable=True)
            execution_input_tick = win.get_last_input()[0]
            dynamic_capture_matches = entry.capture_id == capture_id
            capture: CaptureEntry | None = None
            if operation == "input" and not entry.dialog_hwnd and not entry.capture_id and capture_id:
                capture = self._capture_entry(capture_id)
                dynamic_capture_matches = bool(
                    capture.created_monotonic >= entry.created_monotonic
                    and capture.authorizable
                    and capture.control_generation == entry.control_generation
                    and capture.hwnd == entry.main_hwnd
                    and capture.foreground_hwnd == entry.main_hwnd
                    and capture.window_fingerprint == entry.main_fingerprint
                    and capture.last_input_tick == entry.last_input_tick
                    and execution_input_tick == capture.last_input_tick
                )
            if (
                entry.operation != operation
                or entry.identifier != identifier
                or entry.parameters_json != parameters_json
                or not dynamic_capture_matches
                or entry.path != path
                or entry.main_hwnd != main_hwnd
                or entry.dialog_hwnd != dialog_hwnd
                or entry.main_fingerprint != main_fingerprint
                or entry.dialog_fingerprint != dialog_fingerprint
            ):
                entry.used = True
                raise BridgeError("E_CONFIRM_REQUIRED", "Confirmation token does not match the exact operation")
            if execution_input_tick != entry.last_input_tick:
                entry.used = True
                raise BridgeError(
                    "E_CONFIRM_EXPIRED",
                    "Keyboard or mouse input occurred after the approved preflight",
                    retryable=True,
                    recovery=["Repeat preflight", "Capture again", "Retry the exact operation"],
                )
            if path and Path(path).is_file():
                before_stat = Path(path).stat()
                digest = self._hash_file(Path(path))
                after_stat = Path(path).stat()
                if (before_stat.st_size, before_stat.st_mtime_ns) != (
                    after_stat.st_size,
                    after_stat.st_mtime_ns,
                ):
                    entry.used = True
                    raise BridgeError("E_FILE_CHANGED", "Target file changed while confirmation was checked", retryable=True)
                actual = f"{after_stat.st_size}:{after_stat.st_mtime_ns}:{digest}"
                if actual != entry.file_fingerprint:
                    entry.used = True
                    raise BridgeError("E_FILE_CHANGED", "Target file changed after preflight", retryable=True)
            if time.monotonic() > entry.expires_monotonic:
                entry.used = True
                raise BridgeError("E_CONFIRM_EXPIRED", "Confirmation expired during verification", retryable=True)
            if win.get_last_input()[0] != execution_input_tick:
                entry.used = True
                raise BridgeError(
                    "E_CONFIRM_EXPIRED",
                    "Keyboard or mouse input occurred while confirmation was verified",
                    retryable=True,
                )
            entry.used = True
            return entry

    def run_command(self, command_id: str, capture_id: str, confirm_token: str, hwnd: int = 0) -> dict[str, Any]:
        binding, normalized, _metadata = self._normalize_input_binding(
            "csp_run_command",
            {"command_id": command_id},
        )
        command_id = normalized["command_id"]
        command = self.commands[command_id]
        keys = win.validate_keys(command.get("keys", []))
        def operation(record: win.WindowRecord) -> dict[str, Any]:
            self._consume_bound_input_confirmation(
                confirm_token,
                "csp_run_command",
                binding,
                capture_id,
                record,
            )
            self._assert_shortcut_profile()
            approved_tick = self._assert_atomic_capture_boundary(record, capture_id)
            win.send_chord(keys, target=record, expected_last_input_tick=approved_tick)
            return {"commandId": command_id}
        return self._verified_input(
            hwnd=hwnd,
            capture_id=capture_id,
            operation=operation,
            state_change="confirmed",
        )

    def run_auto_action(self, action_id: str, capture_id: str, confirm_token: str, hwnd: int = 0) -> dict[str, Any]:
        binding, normalized, _metadata = self._normalize_input_binding(
            "csp_run_auto_action",
            {"action_id": action_id},
        )
        action_id = normalized["action_id"]
        action = self.auto_actions[action_id]
        keys = win.validate_keys(action.get("keys", []))
        def operation(record: win.WindowRecord) -> dict[str, Any]:
            self._consume_bound_input_confirmation(
                confirm_token,
                "csp_run_auto_action",
                binding,
                capture_id,
                record,
            )
            self._assert_shortcut_profile()
            approved_tick = self._assert_atomic_capture_boundary(record, capture_id)
            win.send_chord(keys, target=record, expected_last_input_tick=approved_tick)
            return {"actionId": action_id}
        return self._verified_input(
            hwnd=hwnd,
            capture_id=capture_id,
            operation=operation,
            state_change="confirmed",
        )

    def run_command_sequence(
        self,
        command_ids: list[str],
        capture_id: str,
        confirm_token: str,
        hwnd: int = 0,
    ) -> dict[str, Any]:
        binding, normalized, _metadata = self._normalize_input_binding(
            "csp_run_command_sequence",
            {"command_ids": command_ids},
        )
        command_ids = normalized["command_ids"]
        commands = []
        for command_id in command_ids:
            command = self.commands[command_id]
            commands.append((command_id, win.validate_keys(command.get("keys", []))))
        def operation(record: win.WindowRecord) -> dict[str, Any]:
            self._consume_bound_input_confirmation(
                confirm_token,
                "csp_run_command_sequence",
                binding,
                capture_id,
                record,
            )
            completed: list[str] = []
            approved_tick: int | None = None
            try:
                for command_id, keys in commands:
                    self._check_cancelled(state_change="possible" if completed else "none")
                    self._assert_shortcut_profile()
                    if not completed:
                        approved_tick = self._assert_atomic_capture_boundary(record, capture_id)
                    win.send_chord(
                        keys,
                        target=record,
                        expected_last_input_tick=approved_tick if not completed else None,
                    )
                    self._mark_owned_input()
                    completed.append(command_id)
                    time.sleep(0.15)
            except BridgeError as exc:
                raise BridgeError(
                    "E_PARTIAL_COMPLETION",
                    "A registered command sequence stopped after one or more input attempts",
                    state_change="possible",
                    details={"completedCommands": completed, "cause": exc.code},
                    recovery=["Call csp_get_state", "Call csp_capture"],
                ) from exc
            return {"completedCommands": completed}
        return self._verified_input(hwnd=hwnd, capture_id=capture_id, operation=operation, state_change="confirmed")

    def validate_path(self, path: str, intent: PathIntent) -> dict[str, Any]:
        return ok_result(self.path_policy.validate(path, intent).public())

    def list_assets(self, root_id: str, recursive: bool = False, max_items: int = 200) -> dict[str, Any]:
        if max_items < 1 or max_items > 500:
            raise BridgeError("E_POLICY_DENIED", "max_items must be 1..500", stage="validation")
        root, candidates = self.path_policy.iter_files(root_id, recursive=recursive)
        items = []
        for path in candidates:
            if path.suffix.lower() not in (self.settings.input_extensions | self.settings.output_extensions):
                continue
            stat = path.stat()
            items.append(
                {
                    "path": str(path),
                    "relativePath": str(path.relative_to(root)),
                    "extension": path.suffix.lower(),
                    "size": stat.st_size,
                    "modifiedUtc": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                }
            )
            if len(items) >= max_items:
                break
        return ok_result({"rootId": root_id, "items": items, "truncated": len(items) >= max_items})

    def file_info(self, path: str, include_sha256: bool = True) -> dict[str, Any]:
        validated = self.path_policy.validate(path, "input")
        stat = validated.path.stat()
        result = {
            **validated.public(),
            "size": stat.st_size,
            "modifiedUtc": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
        }
        if include_sha256:
            result["sha256"] = self._hash_file(validated.path)
        return ok_result(result, verification={"method": ["filesystem"], "confidence": 1.0})

    def scan_exports(self, root_id: str, modified_since_utc: str, max_items: int = 200) -> dict[str, Any]:
        if max_items < 1 or max_items > 500:
            raise BridgeError("E_POLICY_DENIED", "max_items must be 1..500", stage="validation")
        try:
            since = datetime.fromisoformat(modified_since_utc.replace("Z", "+00:00"))
            if since.tzinfo is None:
                since = since.replace(tzinfo=timezone.utc)
            timestamp = since.timestamp()
        except ValueError as exc:
            raise BridgeError("E_POLICY_DENIED", "modified_since_utc must be ISO-8601", stage="validation") from exc
        root_policy = self.settings.root(root_id)
        if not root_policy.read or not root_policy.write:
            raise BridgeError("E_POLICY_DENIED", "Export scan requires a readable writable root")
        root, candidates = self.path_policy.iter_files(root_id, recursive=True)
        items = []
        for path in candidates:
            if path.suffix.lower() not in self.settings.output_extensions:
                continue
            stat = path.stat()
            if stat.st_mtime < timestamp:
                continue
            items.append(
                {
                    "path": str(path),
                    "relativePath": str(path.relative_to(root)),
                    "size": stat.st_size,
                    "modifiedUtc": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                }
            )
            if len(items) >= max_items:
                break
        return ok_result({"rootId": root_id, "items": items, "truncated": len(items) >= max_items})

    def wait_for_file(self, path: str, timeout_ms: int = 10000, stable_ms: int = 500) -> dict[str, Any]:
        if timeout_ms < 100 or timeout_ms > 30000 or stable_ms < 100 or stable_ms > 5000:
            raise BridgeError("E_POLICY_DENIED", "Timeout or stability period is outside policy", stage="validation")
        # Validate as a future output without requiring it to exist.
        try:
            validated = self.path_policy.validate(path, "output_new")
        except BridgeError as exc:
            if exc.code != "E_TARGET_EXISTS":
                raise
            validated = self.path_policy.validate(path, "output_replace")
        deadline = time.monotonic() + timeout_ms / 1000
        last_signature: tuple[int, int] | None = None
        stable_since = 0.0
        while time.monotonic() < deadline:
            self._check_cancelled()
            if validated.path.is_file():
                stat = validated.path.stat()
                signature = (stat.st_size, stat.st_mtime_ns)
                if stat.st_size > 0 and signature == last_signature:
                    if stable_since and (time.monotonic() - stable_since) * 1000 >= stable_ms:
                        try:
                            validated = self.path_policy.validate(str(validated.path), "output_replace")
                            before_hash_stat = validated.path.stat()
                            if (before_hash_stat.st_size, before_hash_stat.st_mtime_ns) != signature:
                                last_signature = (before_hash_stat.st_size, before_hash_stat.st_mtime_ns)
                                stable_since = time.monotonic()
                                continue
                            digest = self._hash_file(validated.path, deadline=deadline)
                            validated = self.path_policy.validate(str(validated.path), "output_replace")
                            after_stat = validated.path.stat()
                        except OSError:
                            last_signature = None
                            stable_since = 0.0
                            time.sleep(0.1)
                            continue
                        except BridgeError as exc:
                            if exc.code != "E_FILE_CHANGED":
                                raise
                            last_signature = None
                            stable_since = 0.0
                            time.sleep(0.1)
                            continue
                        after_signature = (after_stat.st_size, after_stat.st_mtime_ns)
                        if after_signature == signature and after_stat.st_size > 0:
                            return ok_result(
                                {
                                    "path": str(validated.path),
                                    "size": after_stat.st_size,
                                    "sha256": digest,
                                    "stableMs": stable_ms,
                                },
                                verification={
                                    "method": [
                                        "stableWindow",
                                        "prePostPathPolicy",
                                        "prePostHashStat",
                                        "sha256",
                                    ],
                                    "confidence": 1.0,
                                },
                            )
                        last_signature = after_signature
                        stable_since = time.monotonic()
                else:
                    last_signature = signature
                    stable_since = time.monotonic()
            time.sleep(0.1)
        raise BridgeError("E_UI_TIMEOUT", "Output file did not become stable before timeout", retryable=True)

    def native_file_dialog(
        self,
        path: str,
        intent: PathIntent,
        submit: bool,
        dialog_hwnd: int = 0,
        confirm_token: str = "",
        main_hwnd: int = 0,
    ) -> dict[str, Any]:
        binding, normalized, _metadata = self._normalize_input_binding(
            "csp_native_file_dialog",
            {"path": path, "intent": intent, "submit": submit},
        )
        path = normalized["path"]
        intent = normalized["intent"]
        submit = normalized["submit"]
        validated = self.path_policy.validate(path, intent)
        lock = self._locked()
        try:
            self._wait_for_quiet()
            record = self._target(main_hwnd, for_input=True)
            dialogs = [
                item
                for item in win.list_process_dialogs(
                    self.settings.csp_executable,
                    record.pid,
                    main_hwnd=record.hwnd,
                )
                if item.class_name == "#32770"
            ]
            if dialog_hwnd:
                dialogs = [item for item in dialogs if item.hwnd == dialog_hwnd]
            if len(dialogs) != 1:
                raise BridgeError(
                    "E_AMBIGUOUS_TARGET" if dialogs else "E_WINDOW_NOT_FOUND",
                    "Exactly one standard CSP file dialog must be selected",
                    retryable=True,
                    details={"dialogIds": [str(item.hwnd) for item in dialogs]},
                )
            dialog = dialogs[0]
            self._wait_for_quiet()
            if (
                win.foreground_window() != dialog.hwnd
                or not win.window_belongs_to_main(dialog.hwnd, record.hwnd)
            ):
                raise BridgeError(
                    "E_USER_INTERRUPTED",
                    "The preflight-bound CSP file dialog is no longer foreground",
                    retryable=True,
                    recovery=["Repeat csp_preflight for the exact file dialog"],
                )
            # Re-run path checks immediately before WM_SETTEXT/BM_CLICK to close
            # the validation-to-submit race as far as a UI bridge can.
            validated = self.path_policy.validate(path, intent)
            win.validate_native_file_dialog(dialog.hwnd, intent)
            consumed_confirmation = self._consume_confirmation(
                confirm_token,
                operation="input",
                identifier="csp_native_file_dialog",
                capture_id="",
                path=str(validated.path),
                main_hwnd=record.hwnd,
                dialog_hwnd=dialog.hwnd,
                main_fingerprint=record.fingerprint,
                dialog_fingerprint=dialog.fingerprint,
                parameters_json=binding,
            )
            if (
                win.foreground_window() != dialog.hwnd
                or not win.window_belongs_to_main(dialog.hwnd, record.hwnd)
            ):
                raise BridgeError(
                    "E_USER_INTERRUPTED",
                    "The exact CSP file dialog lost focus after confirmation verification",
                    retryable=True,
                    recovery=["Inspect the still-open dialog and repeat preflight if needed"],
                )
            try:
                self._check_cancelled()
                execution_input_tick = consumed_confirmation.last_input_tick
                result = win.submit_native_file_dialog(
                    dialog.hwnd,
                    validated.path,
                    intent=intent,
                    submit=submit,
                    cancel_event=self._current_cancel_event(),
                    expected_main_hwnd=record.hwnd,
                    expected_last_input_tick=execution_input_tick,
                    submission_deadline=consumed_confirmation.expires_monotonic,
                )
            except BridgeError as exc:
                if exc.state_change != "none":
                    self._record_control_state_change()
                    self._mark_owned_input_best_effort()
                raise
            except Exception as exc:
                self._record_control_state_change()
                self._mark_owned_input_best_effort()
                raise BridgeError(
                    "E_PARTIAL_COMPLETION",
                    f"Native file-dialog input failed: {type(exc).__name__}",
                    state_change="possible",
                    recovery=["Inspect and cancel the dialog before retrying"],
                ) from exc
            self._record_control_state_change()
            tracking_warning = self._mark_owned_input_best_effort()
            followups: list[str] = []
            if submit:
                followups = [
                    str(item.hwnd)
                    for item in win.list_process_dialogs(
                        self.settings.csp_executable,
                        record.pid,
                        main_hwnd=record.hwnd,
                    )
                    if item.class_name == "#32770"
                ]
                if followups:
                    result["submitted"] = False
                    result["manualFollowupRequired"] = True
                    result["followupDialogIds"] = followups
            warnings: list[str] = []
            if not submit:
                warnings.append("Path was filled but not submitted.")
            elif result.get("submitted") and intent == "input":
                warnings.append("The open dialog closed; verify the visible document with csp_get_state and csp_capture.")
            elif result.get("submitted"):
                warnings.append("The save dialog closed; verify file creation separately with csp_wait_for_file.")
            else:
                warnings.append(
                    "The original or a follow-up dialog remains open. No generic confirmation button was clicked; inspect it manually."
                )
            if tracking_warning:
                warnings.append(tracking_warning)
            return ok_result(
                {**result, "intent": intent, "rootId": validated.root.id},
                state_change="confirmed",
                verification={"method": ["nativeDialogProfile", "pathPolicy"], "confidence": 0.9},
                warnings=warnings,
            )
        finally:
            lock.release()

    def wait_visual_change(self, capture_id: str, threshold: float = 0.002, timeout_ms: int = 10000) -> dict[str, Any]:
        if threshold < 0.0001 or threshold > 1 or timeout_ms < 100 or timeout_ms > 30000:
            raise BridgeError("E_POLICY_DENIED", "Threshold or timeout is outside policy", stage="validation")
        baseline = self._capture_entry(capture_id)
        deadline = time.monotonic() + timeout_ms / 1000
        last_difference = 0.0
        while time.monotonic() < deadline:
            self._check_cancelled()
            record = self._target(baseline.hwnd, for_input=False)
            if record.minimized:
                raise BridgeError("E_CAPABILITY_UNAVAILABLE", "CSP became minimized", retryable=True)
            current = self._capture_record(
                record,
                region=baseline.region,
                max_width=baseline.capture_max_width,
                authorizable=False,
                store=False,
            )
            difference = win.visual_difference(baseline.data.png, current.data.png)
            last_difference = difference
            if difference >= threshold:
                self._store_capture(current)
                return ok_result(
                    {"changed": True, "visualDifferenceRatio": difference, "capture": self._capture_public(current)},
                    verification={"method": ["downsampledPixelDiff"], "confidence": 0.95},
                )
            time.sleep(0.2)
        return ok_result(
            {"changed": False, "visualDifferenceRatio": last_difference},
            verification={"method": ["downsampledPixelDiff"], "confidence": 0.95},
        )
