from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import hashlib
import io
import locale
import math
import mmap
import os
import struct
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

import win32api
import win32con
import win32gui
import win32process
from PIL import Image, ImageGrab, ImageStat

from .errors import BridgeError


user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
wintrust = ctypes.WinDLL("wintrust", use_last_error=True)
try:
    dwmapi = ctypes.WinDLL("dwmapi", use_last_error=True)
except OSError:
    dwmapi = None

kernel32.CreateMutexW.restype = wt.HANDLE
kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, wt.BOOL, wt.LPCWSTR]
kernel32.WaitForSingleObject.restype = wt.DWORD
kernel32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
kernel32.ReleaseMutex.restype = wt.BOOL
kernel32.ReleaseMutex.argtypes = [wt.HANDLE]
kernel32.CloseHandle.restype = wt.BOOL
kernel32.CloseHandle.argtypes = [wt.HANDLE]
kernel32.OpenProcess.restype = wt.HANDLE
kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
user32.SendMessageTimeoutW.restype = wt.LPARAM
user32.SendMessageTimeoutW.argtypes = [
    wt.HWND,
    wt.UINT,
    wt.WPARAM,
    wt.LPARAM,
    wt.UINT,
    wt.UINT,
    ctypes.POINTER(ctypes.c_size_t),
]


def enable_per_monitor_dpi_awareness() -> None:
    """Make all coordinates physical pixels. Safe to call more than once."""
    try:
        user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
    except (AttributeError, OSError):
        try:
            ctypes.WinDLL("shcore").SetProcessDpiAwareness(2)
        except (AttributeError, OSError):
            user32.SetProcessDPIAware()


class CrossProcessMutexLease:
    def __init__(self, handle: int, *, abandoned: bool = False) -> None:
        self.handle = handle
        self.abandoned = abandoned
        self._released = False

    def release(self) -> None:
        if self._released:
            return
        try:
            kernel32.ReleaseMutex(self.handle)
        finally:
            kernel32.CloseHandle(self.handle)
            self._released = True


class ControlGeneration:
    """Eight-byte named shared memory counter; callers serialize with the control mutex."""

    def __init__(self, name: str) -> None:
        self._mapping = mmap.mmap(-1, 8, tagname=name, access=mmap.ACCESS_WRITE)

    def current(self) -> int:
        return int(struct.unpack("<Q", self._mapping[:8])[0])

    def advance(self) -> int:
        value = (self.current() + 1) & 0xFFFFFFFFFFFFFFFF
        self._mapping[:8] = struct.pack("<Q", value)
        return value


def acquire_control_mutex(name: str, timeout_ms: int = 2000) -> CrossProcessMutexLease | None:
    handle = kernel32.CreateMutexW(None, False, name)
    if not handle:
        return None
    WAIT_OBJECT_0 = 0
    WAIT_ABANDONED = 0x80
    status = int(kernel32.WaitForSingleObject(handle, max(0, timeout_ms)))
    if status not in {WAIT_OBJECT_0, WAIT_ABANDONED}:
        kernel32.CloseHandle(handle)
        return None
    return CrossProcessMutexLease(int(handle), abandoned=status == WAIT_ABANDONED)


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wt.DWORD),
        ("Data2", wt.WORD),
        ("Data3", wt.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wt.DWORD),
        ("pcwszFilePath", wt.LPCWSTR),
        ("hFile", wt.HANDLE),
        ("pgKnownSubject", ctypes.c_void_p),
    ]


class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wt.DWORD),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", wt.DWORD),
        ("fdwRevocationChecks", wt.DWORD),
        ("dwUnionChoice", wt.DWORD),
        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
        ("dwStateAction", wt.DWORD),
        ("hWVTStateData", wt.HANDLE),
        ("pwszURLReference", wt.LPCWSTR),
        ("dwProvFlags", wt.DWORD),
        ("dwUIContext", wt.DWORD),
        ("pSignatureSettings", ctypes.c_void_p),
    ]


WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(
    0x00AAC56B,
    0xCD44,
    0x11D0,
    (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
)
WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_STATEACTION_VERIFY = 1
WTD_STATEACTION_CLOSE = 2
WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000


def verify_authenticode(path: Path) -> tuple[bool, int]:
    file_info = WINTRUST_FILE_INFO(
        ctypes.sizeof(WINTRUST_FILE_INFO), str(path), None, None
    )
    data = WINTRUST_DATA()
    data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    data.dwUIChoice = WTD_UI_NONE
    data.fdwRevocationChecks = WTD_REVOKE_NONE
    data.dwUnionChoice = WTD_CHOICE_FILE
    data.pFile = ctypes.pointer(file_info)
    data.dwStateAction = WTD_STATEACTION_VERIFY
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL
    status = ctypes.c_long(
        wintrust.WinVerifyTrust(None, ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2), ctypes.byref(data))
    ).value
    data.dwStateAction = WTD_STATEACTION_CLOSE
    wintrust.WinVerifyTrust(None, ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2), ctypes.byref(data))
    return status == 0, status


def _version_string(path: Path, key: str) -> str:
    try:
        translations = win32api.GetFileVersionInfo(str(path), r"\VarFileInfo\Translation")
    except Exception:
        translations = []
    for language, codepage in translations or [(0x0409, 1200), (0x0409, 1252)]:
        query = rf"\StringFileInfo\{language:04x}{codepage:04x}\{key}"
        try:
            value = win32api.GetFileVersionInfo(str(path), query)
        except Exception:
            continue
        if value:
            return str(value).strip()
    return ""


def file_version(path: Path) -> str:
    try:
        info = win32api.GetFileVersionInfo(str(path), "\\")
        ms = int(info["FileVersionMS"])
        ls = int(info["FileVersionLS"])
        return f"{win32api.HIWORD(ms)}.{win32api.LOWORD(ms)}.{win32api.HIWORD(ls)}.{win32api.LOWORD(ls)}"
    except Exception:
        return _version_string(path, "FileVersion")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def binary_identity(path: Path) -> dict[str, Any]:
    exists = path.is_file()
    if not exists:
        return {
            "exists": False,
            "path": str(path),
            "signatureValid": False,
            "signatureStatus": None,
            "fileVersion": "",
            "productVersion": "",
            "company": "",
            "sha256": "",
        }
    trusted, status = verify_authenticode(path)
    return {
        "exists": True,
        "path": str(path),
        "signatureValid": trusted,
        "signatureStatus": status,
        "fileVersion": file_version(path),
        "productVersion": _version_string(path, "ProductVersion"),
        "company": _version_string(path, "CompanyName"),
        "sha256": sha256_file(path),
    }


def process_path(pid: int) -> Path | None:
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        capacity = wt.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(capacity.value)
        if not kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(capacity)):
            return None
        return Path(buffer.value)
    finally:
        kernel32.CloseHandle(handle)


class POINT(ctypes.Structure):
    _fields_ = [("x", wt.LONG), ("y", wt.LONG)]


class RECT(ctypes.Structure):
    _fields_ = [("left", wt.LONG), ("top", wt.LONG), ("right", wt.LONG), ("bottom", wt.LONG)]


def visible_window_rect(hwnd: int) -> tuple[int, int, int, int]:
    """Return DWM's painted frame, excluding invisible resize borders/shadows."""
    fallback = tuple(int(value) for value in win32gui.GetWindowRect(hwnd))
    if dwmapi is None:
        return fallback
    bounds = RECT()
    try:
        status = int(dwmapi.DwmGetWindowAttribute(hwnd, 9, ctypes.byref(bounds), ctypes.sizeof(bounds)))
    except (AttributeError, OSError):
        return fallback
    visible = (int(bounds.left), int(bounds.top), int(bounds.right), int(bounds.bottom))
    if status == 0 and visible[2] > visible[0] and visible[3] > visible[1]:
        return visible
    return fallback


def _interaction_rect(
    hwnd: int,
    painted_rect: tuple[int, int, int, int],
    *,
    maximized: bool,
) -> tuple[int, int, int, int]:
    """Exclude taskbar-covered maximized frame pixels from capture and input.

    DWM can report a maximized resize frame a few physical pixels beyond the
    monitor work area. Those pixels are not CSP-controlled and must not be
    captured or used for normalized pointer authorization.
    """
    if not maximized:
        return painted_rect
    try:
        monitor = win32api.MonitorFromWindow(hwnd, 2)  # MONITOR_DEFAULTTONEAREST
        work = tuple(int(value) for value in win32api.GetMonitorInfo(monitor)["Work"])
    except Exception:
        return painted_rect
    left, top, right, bottom = painted_rect
    work_left, work_top, work_right, work_bottom = work
    clipped = (
        max(left, work_left),
        max(top, work_top),
        min(right, work_right),
        min(bottom, work_bottom),
    )
    if clipped[2] <= clipped[0] or clipped[3] <= clipped[1]:
        return painted_rect
    return clipped


class WINDOWPLACEMENT(ctypes.Structure):
    _fields_ = [
        ("length", wt.UINT),
        ("flags", wt.UINT),
        ("showCmd", wt.UINT),
        ("ptMinPosition", POINT),
        ("ptMaxPosition", POINT),
        ("rcNormalPosition", RECT),
        ("rcDevice", RECT),
    ]


def _window_placement(hwnd: int) -> dict[str, Any]:
    placement = WINDOWPLACEMENT()
    placement.length = ctypes.sizeof(WINDOWPLACEMENT)
    if not user32.GetWindowPlacement(hwnd, ctypes.byref(placement)):
        return {"showCmd": None, "normalRect": None}
    normal = placement.rcNormalPosition
    return {
        "showCmd": int(placement.showCmd),
        "normalRect": [int(normal.left), int(normal.top), int(normal.right), int(normal.bottom)],
    }


def dpi_for_window(hwnd: int) -> int:
    try:
        return int(user32.GetDpiForWindow(hwnd))
    except (AttributeError, OSError):
        return 96


@dataclass(frozen=True)
class WindowRecord:
    hwnd: int
    pid: int
    title: str
    class_name: str
    rect: tuple[int, int, int, int]
    client_rect: tuple[int, int, int, int]
    visible: bool
    minimized: bool
    maximized: bool
    owner: int
    dpi: int
    executable: str
    show_cmd: int | None
    normal_rect: tuple[int, int, int, int] | None
    required_foreground_hwnd: int = 0

    @property
    def area(self) -> int:
        left, top, right, bottom = self.rect
        return max(0, right - left) * max(0, bottom - top)

    @property
    def fingerprint(self) -> str:
        payload = "|".join(
            [
                str(self.hwnd), str(self.pid), self.title, self.class_name,
                ",".join(map(str, self.rect)), str(self.dpi), self.executable.casefold(),
            ]
        )
        return hashlib.sha256(payload.encode("utf-8", "surrogatepass")).hexdigest()[:24]

    def public(self) -> dict[str, Any]:
        return {
            "windowId": str(self.hwnd),
            "hwnd": self.hwnd,
            "processId": self.pid,
            "title": self.title,
            "className": self.class_name,
            "rect": list(self.rect),
            "clientRect": list(self.client_rect),
            "visible": self.visible,
            "minimized": self.minimized,
            "maximized": self.maximized,
            "owner": self.owner,
            "dpi": self.dpi,
            "executable": self.executable,
            "showCmd": self.show_cmd,
            "normalRect": list(self.normal_rect) if self.normal_rect else None,
            "fingerprint": self.fingerprint,
        }


def _record_window(hwnd: int) -> WindowRecord | None:
    if not win32gui.IsWindow(hwnd):
        return None
    try:
        _, pid = win32process.GetWindowThreadProcessId(hwnd)
        executable = process_path(pid)
        if executable is None:
            return None
        maximized = bool(user32.IsZoomed(hwnd))
        rect = _interaction_rect(hwnd, visible_window_rect(hwnd), maximized=maximized)
        client = win32gui.GetClientRect(hwnd)
        origin = win32gui.ClientToScreen(hwnd, (0, 0))
        client_rect = (
            int(origin[0]), int(origin[1]),
            int(origin[0] + client[2] - client[0]), int(origin[1] + client[3] - client[1]),
        )
        placement = _window_placement(hwnd)
        normal = placement.get("normalRect")
        return WindowRecord(
            hwnd=int(hwnd),
            pid=int(pid),
            title=win32gui.GetWindowText(hwnd),
            class_name=win32gui.GetClassName(hwnd),
            rect=rect,
            client_rect=client_rect,
            visible=bool(win32gui.IsWindowVisible(hwnd)),
            minimized=bool(win32gui.IsIconic(hwnd)),
            maximized=maximized,
            owner=int(win32gui.GetWindow(hwnd, win32con.GW_OWNER) or 0),
            dpi=dpi_for_window(hwnd),
            executable=str(executable),
            show_cmd=placement.get("showCmd"),
            normal_rect=tuple(normal) if normal else None,
        )
    except Exception:
        return None


def enum_csp_windows(expected_executable: Path, *, include_dialogs: bool = False) -> list[WindowRecord]:
    expected = os.path.normcase(os.path.abspath(str(expected_executable)))
    records: list[WindowRecord] = []

    def callback(hwnd: int, _: Any) -> bool:
        record = _record_window(hwnd)
        if record is None:
            return True
        if os.path.normcase(os.path.abspath(record.executable)) != expected:
            return True
        if not record.visible and not record.minimized:
            return True
        if include_dialogs or (record.owner == 0 and record.class_name != "#32770"):
            records.append(record)
        return True

    win32gui.EnumWindows(callback, None)
    records.sort(key=lambda item: (item.pid, -item.area, item.hwnd))
    return records


def choose_csp_window(expected_executable: Path, hwnd: int | None = None) -> WindowRecord:
    records = enum_csp_windows(expected_executable, include_dialogs=False)
    if hwnd:
        for record in records:
            if record.hwnd == int(hwnd):
                return record
        raise BridgeError("E_WINDOW_NOT_FOUND", "Requested CSP window was not found", retryable=True)
    if not records:
        raise BridgeError("E_CSP_NOT_RUNNING", "CLIP STUDIO PAINT is not running", retryable=True)
    # Fail closed even when several top-level document windows belong to the
    # same process. Area is not a safe semantic selector.
    if len(records) != 1:
        raise BridgeError(
            "E_AMBIGUOUS_TARGET",
            "Multiple CSP main windows are present; pass an explicit hwnd",
            retryable=True,
            details={"windowIds": [str(item.hwnd) for item in records]},
        )
    return records[0]


def foreground_window() -> int:
    return int(win32gui.GetForegroundWindow() or 0)


def _pid_for_window(hwnd: int) -> int:
    if not hwnd:
        return 0
    try:
        _, pid = win32process.GetWindowThreadProcessId(hwnd)
        return int(pid)
    except Exception:
        return 0


def root_owner_window(hwnd: int) -> int:
    """Return the ultimate unowned top-level window for a child/popup chain."""
    if not hwnd:
        return 0
    try:
        current = int(win32gui.GetAncestor(hwnd, win32con.GA_ROOT) or hwnd)
        visited: set[int] = set()
        while current and current not in visited:
            visited.add(current)
            owner = int(win32gui.GetWindow(current, win32con.GW_OWNER) or 0)
            if not owner:
                return current
            current = int(win32gui.GetAncestor(owner, win32con.GA_ROOT) or owner)
        return 0
    except Exception:
        return 0


def window_belongs_to_main(hwnd: int, main_hwnd: int) -> bool:
    """Bind a child or owned popup to one exact CSP main window."""
    return bool(hwnd and main_hwnd and root_owner_window(hwnd) == int(main_hwnd))


def assert_foreground_target(record: WindowRecord) -> None:
    foreground = foreground_window()
    if record.required_foreground_hwnd and foreground != record.required_foreground_hwnd:
        raise BridgeError(
            "E_USER_INTERRUPTED",
            "The active CSP window or dialog changed before input",
            retryable=True,
            state_change="none",
            details={
                "expectedForegroundWindowId": str(record.required_foreground_hwnd),
                "actualForegroundWindowId": str(foreground),
            },
            recovery=["Call csp_capture again"],
        )
    if _pid_for_window(foreground) != record.pid or not window_belongs_to_main(foreground, record.hwnd):
        raise BridgeError(
            "E_USER_INTERRUPTED",
            "Foreground focus left the selected CSP main-window chain before input",
            retryable=True,
            state_change="none",
            recovery=["Call csp_focus", "Call csp_capture again"],
        )


def window_at_point(x: int, y: int) -> int:
    user32.WindowFromPoint.restype = wt.HWND
    return int(user32.WindowFromPoint(POINT(x, y)) or 0)


def assert_point_target(record: WindowRecord, x: int, y: int) -> None:
    assert_foreground_target(record)
    hwnd = window_at_point(x, y)
    if _pid_for_window(hwnd) != record.pid or not window_belongs_to_main(hwnd, record.hwnd):
        raise BridgeError(
            "E_USER_INTERRUPTED",
            "Another window covers the requested point outside the selected CSP main-window chain",
            retryable=True,
            recovery=["Bring CSP fully to the front", "Call csp_capture again"],
        )


def assert_capture_target_visible(record: WindowRecord, rect: tuple[int, int, int, int]) -> None:
    assert_foreground_target(record)
    left, top, right, bottom = rect
    width = right - left
    height = bottom - top
    if width <= 0 or height <= 0:
        raise BridgeError("E_CAPABILITY_UNAVAILABLE", "CSP capture rectangle is empty")
    # EnumWindows/GetWindow z-order is used in addition to point sampling so a
    # small foreign notification between sample points cannot leak into the
    # screen-based ImageGrab result.
    above = int(win32gui.GetWindow(record.hwnd, win32con.GW_HWNDPREV) or 0)
    visited: set[int] = set()
    while above and above not in visited and len(visited) < 1024:
        visited.add(above)
        try:
            if win32gui.IsWindowVisible(above) and not win32gui.IsIconic(above):
                other_left, other_top, other_right, other_bottom = visible_window_rect(above)
                # Explorer and some GPU helpers expose visible 1x1 bookkeeping
                # HWNDs without a meaningful capturable surface. Point-level
                # authorization still rejects them if Windows reports one at
                # the requested input coordinate.
                if other_right - other_left <= 1 or other_bottom - other_top <= 1:
                    above = int(win32gui.GetWindow(above, win32con.GW_HWNDPREV) or 0)
                    continue
                intersects = (
                    max(left, other_left) < min(right, other_right)
                    and max(top, other_top) < min(bottom, other_bottom)
                )
                if intersects and (
                    _pid_for_window(above) != record.pid
                    or not window_belongs_to_main(above, record.hwnd)
                ):
                    raise BridgeError(
                        "E_CAPABILITY_UNAVAILABLE",
                        "A window outside the selected CSP main-window chain overlaps the capture rectangle",
                        retryable=True,
                        details={"overlappingWindowId": str(above)},
                        recovery=["Bring CSP fully to the front and retry"],
                    )
        except BridgeError:
            raise
        except Exception:
            # An uninspectable window above CSP is a privacy ambiguity.
            raise BridgeError(
                "E_CAPABILITY_UNAVAILABLE",
                "A top-level window above CSP could not be verified for capture",
                retryable=True,
                recovery=["Bring CSP fully to the front and retry"],
            )
        above = int(win32gui.GetWindow(above, win32con.GW_HWNDPREV) or 0)
    inset_x = min(max(8, width // 100), max(0, width // 4))
    inset_y = min(max(8, height // 100), max(0, height // 4))
    for row in range(7):
        y = top + inset_y + round((height - 2 * inset_y - 1) * row / 6)
        for column in range(7):
            x = left + inset_x + round((width - 2 * inset_x - 1) * column / 6)
            point_hwnd = window_at_point(x, y)
            if _pid_for_window(point_hwnd) != record.pid or not window_belongs_to_main(point_hwnd, record.hwnd):
                raise BridgeError(
                    "E_CAPABILITY_UNAVAILABLE",
                    "A window outside the selected CSP main-window chain overlaps the capture area",
                    retryable=True,
                    recovery=["Bring CSP fully to the front and retry"],
                )


def capture_readiness(record: WindowRecord) -> tuple[bool, str | None]:
    if record.minimized:
        return False, "E_CAPABILITY_UNAVAILABLE:minimized"
    try:
        assert_capture_target_visible(record, _clip_to_virtual_screen(record.rect))
        return True, None
    except BridgeError as exc:
        return False, exc.code


def _assert_window_side_effect_preconditions(
    hwnd: int,
    *,
    expected: WindowRecord | None,
    expected_input_tick: int | None,
) -> WindowRecord:
    current = _record_window(hwnd)
    if current is None:
        raise BridgeError("E_WINDOW_NOT_FOUND", "CSP window no longer exists", retryable=True)
    if expected is not None and current.fingerprint != expected.fingerprint:
        raise BridgeError(
            "E_STALE_CAPTURE",
            "CSP window identity or geometry changed before the window operation",
            retryable=True,
            details={
                "expectedWindowId": str(expected.hwnd),
                "actualWindowId": str(current.hwnd),
            },
            recovery=["Call csp_list_windows and retry"],
        )
    if expected_input_tick is not None:
        actual_tick = get_last_input()[0]
        pressed = pressed_input_keys()
        if actual_tick != expected_input_tick or pressed:
            raise BridgeError(
                "E_USER_INTERRUPTED",
                "Human input occurred immediately before the window operation",
                retryable=True,
                details={"pressedInputs": pressed},
                recovery=["Stop using the keyboard and mouse briefly, then retry"],
            )
    return current


def _assert_window_side_effect_result(
    record: WindowRecord,
    *,
    expected: WindowRecord | None,
    expected_input_tick: int | None,
) -> None:
    if expected is not None and (
        record.hwnd != expected.hwnd
        or record.pid != expected.pid
        or os.path.normcase(record.executable) != os.path.normcase(expected.executable)
    ):
        raise BridgeError(
            "E_WINDOW_IDENTITY_CHANGED",
            "The target HWND was reused or changed process identity during the operation",
            retryable=True,
            state_change="possible",
            recovery=["Call csp_list_windows and reassess CSP"],
        )
    if expected_input_tick is not None and (
        get_last_input()[0] != expected_input_tick or pressed_input_keys()
    ):
        raise BridgeError(
            "E_USER_INTERRUPTED",
            "Human input occurred during the window operation",
            retryable=True,
            state_change="possible",
            recovery=["Call csp_get_state before retrying"],
        )


def focus_window(
    hwnd: int,
    *,
    restore: bool = True,
    timeout_seconds: float = 3.0,
    expected: WindowRecord | None = None,
    expected_input_tick: int | None = None,
) -> WindowRecord:
    if not win32gui.IsWindow(hwnd):
        raise BridgeError("E_WINDOW_NOT_FOUND", "CSP window no longer exists", retryable=True)
    _assert_window_side_effect_preconditions(
        hwnd,
        expected=expected,
        expected_input_tick=expected_input_tick,
    )
    if restore and win32gui.IsIconic(hwnd):
        win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
        time.sleep(0.25)
    target_thread, _ = win32process.GetWindowThreadProcessId(hwnd)
    foreground = foreground_window()
    foreground_thread = 0
    if foreground:
        foreground_thread, _ = win32process.GetWindowThreadProcessId(foreground)
    current_thread = kernel32.GetCurrentThreadId()
    attached: list[int] = []
    try:
        for thread_id in {int(target_thread), int(foreground_thread)}:
            if thread_id and thread_id != current_thread:
                if user32.AttachThreadInput(current_thread, thread_id, True):
                    attached.append(thread_id)
        win32gui.BringWindowToTop(hwnd)
        win32gui.SetForegroundWindow(hwnd)
    finally:
        for thread_id in reversed(attached):
            user32.AttachThreadInput(current_thread, thread_id, False)
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if foreground_window() == hwnd:
            break
        time.sleep(0.05)
    if foreground_window() != hwnd:
        raise BridgeError("E_UI_TIMEOUT", "Windows refused to focus CSP", retryable=True)
    record = _record_window(hwnd)
    if record is None:
        raise BridgeError("E_WINDOW_NOT_FOUND", "CSP window disappeared", retryable=True)
    _assert_window_side_effect_result(
        record,
        expected=expected,
        expected_input_tick=expected_input_tick,
    )
    return record


def set_window_state(
    hwnd: int,
    action: str,
    *,
    expected: WindowRecord | None = None,
    expected_input_tick: int | None = None,
) -> WindowRecord:
    mapping = {
        "restore": win32con.SW_RESTORE,
        "maximize": win32con.SW_MAXIMIZE,
        "minimize": win32con.SW_MINIMIZE,
    }
    if action not in mapping:
        raise BridgeError("E_POLICY_DENIED", "Window action must be restore, maximize, or minimize", stage="validation")
    _assert_window_side_effect_preconditions(
        hwnd,
        expected=expected,
        expected_input_tick=expected_input_tick,
    )
    win32gui.ShowWindow(hwnd, mapping[action])
    time.sleep(0.25)
    record = _record_window(hwnd)
    if record is None:
        raise BridgeError("E_WINDOW_NOT_FOUND", "CSP window disappeared", retryable=True)
    _assert_window_side_effect_result(
        record,
        expected=expected,
        expected_input_tick=expected_input_tick,
    )
    return record


class LASTINPUTINFO(ctypes.Structure):
    _fields_ = [("cbSize", wt.UINT), ("dwTime", wt.DWORD)]


def get_last_input() -> tuple[int, int]:
    info = LASTINPUTINFO()
    info.cbSize = ctypes.sizeof(LASTINPUTINFO)
    if not user32.GetLastInputInfo(ctypes.byref(info)):
        raise OSError(ctypes.get_last_error(), "GetLastInputInfo failed")
    now = int(kernel32.GetTickCount64() & 0xFFFFFFFF)
    elapsed = (now - int(info.dwTime)) & 0xFFFFFFFF
    return int(info.dwTime), elapsed


def _virtual_key_name(code: int) -> str:
    names = {
        win32con.VK_LBUTTON: "leftMouse",
        win32con.VK_RBUTTON: "rightMouse",
        win32con.VK_MBUTTON: "middleMouse",
        win32con.VK_BACK: "backspace",
        win32con.VK_TAB: "tab",
        win32con.VK_RETURN: "enter",
        win32con.VK_SHIFT: "shift",
        win32con.VK_CONTROL: "ctrl",
        win32con.VK_MENU: "alt",
        win32con.VK_ESCAPE: "escape",
        win32con.VK_SPACE: "space",
        win32con.VK_DELETE: "delete",
        0x5B: "leftWin",
        0x5C: "rightWin",
    }
    if code in names:
        return names[code]
    if 0x30 <= code <= 0x39 or 0x41 <= code <= 0x5A:
        return chr(code)
    if 0x70 <= code <= 0x87:
        return f"F{code - 0x6F}"
    return f"VK_0x{code:02X}"


def pressed_input_keys() -> list[dict[str, int | str]]:
    """Return every currently depressed Windows virtual key, not just modifiers.

    GetLastInputInfo becomes quiet while a human keeps a key held. Scanning the
    complete public VK range prevents MCP chords from combining with that held
    key and also makes an abandoned synthetic key-down fail closed.
    """
    pressed: list[dict[str, int | str]] = []
    for code in range(0x01, 0xFF):
        if user32.GetAsyncKeyState(code) & 0x8000:
            pressed.append({"code": code, "hex": f"0x{code:02X}", "name": _virtual_key_name(code)})
    return pressed


def current_locale_name() -> str:
    buffer = ctypes.create_unicode_buffer(85)
    if kernel32.GetUserDefaultLocaleName(buffer, len(buffer)):
        return buffer.value
    name = locale.getlocale()[0] or "unknown"
    return name.replace("_", "-")


def display_inventory() -> list[dict[str, Any]]:
    displays: list[dict[str, Any]] = []
    for handle, _, _ in win32api.EnumDisplayMonitors():
        info = win32api.GetMonitorInfo(handle)
        displays.append(
            {
                "monitor": list(info["Monitor"]),
                "workArea": list(info["Work"]),
                "primary": bool(info["Flags"] & 1),
                "device": info.get("Device", ""),
            }
        )
    return displays


def _clip_to_virtual_screen(rect: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    vx = win32api.GetSystemMetrics(win32con.SM_XVIRTUALSCREEN)
    vy = win32api.GetSystemMetrics(win32con.SM_YVIRTUALSCREEN)
    vw = win32api.GetSystemMetrics(win32con.SM_CXVIRTUALSCREEN)
    vh = win32api.GetSystemMetrics(win32con.SM_CYVIRTUALSCREEN)
    left, top, right, bottom = rect
    clipped = (max(left, vx), max(top, vy), min(right, vx + vw), min(bottom, vy + vh))
    if clipped[2] <= clipped[0] or clipped[3] <= clipped[1]:
        raise BridgeError("E_CAPABILITY_UNAVAILABLE", "CSP window is outside the visible desktop")
    return clipped


def rect_fully_inside_virtual_screen(rect: tuple[int, int, int, int]) -> bool:
    """Whether screenshot coordinates and full-window input coordinates share one origin."""
    try:
        return _clip_to_virtual_screen(rect) == rect
    except BridgeError:
        return False


def capture_rect_covers_visible_main_chain(
    record: WindowRecord,
    capture_rect: tuple[int, int, int, int],
) -> bool:
    """Require every visible owned popup to be represented by an input-authorizing capture."""
    if capture_rect != record.rect or not rect_fully_inside_virtual_screen(capture_rect):
        return False
    foreground = foreground_window()
    if record.required_foreground_hwnd and foreground != record.required_foreground_hwnd:
        return False
    if not window_belongs_to_main(foreground, record.hwnd):
        return False
    left, top, right, bottom = capture_rect
    covered = True

    def callback(hwnd: int, _: Any) -> bool:
        nonlocal covered
        try:
            if hwnd == record.hwnd:
                return True
            if win32gui.IsWindowVisible(hwnd) and not win32gui.IsIconic(hwnd) and window_belongs_to_main(hwnd, record.hwnd):
                item_left, item_top, item_right, item_bottom = visible_window_rect(hwnd)
                # CSP keeps several owned 1x1 helper HWNDs marked WS_VISIBLE.
                # They have no capturable surface and must not disable every
                # legitimate full-window authorization.
                if item_right - item_left <= 1 or item_bottom - item_top <= 1:
                    return True
                if _pid_for_window(hwnd) != record.pid:
                    covered = False
                    return False
                if (
                    item_left < left
                    or item_top < top
                    or item_right > right
                    or item_bottom > bottom
                ):
                    covered = False
                    return False
        except Exception:
            covered = False
            return False
        return True

    try:
        win32gui.EnumWindows(callback, None)
    except Exception:
        return False
    return covered


@dataclass(frozen=True)
class CaptureData:
    png: bytes
    width: int
    height: int
    source_width: int
    source_height: int
    rect: tuple[int, int, int, int]
    sha256: str
    luminance_stddev: float


def capture_window(
    record: WindowRecord,
    *,
    region: Sequence[float] | None = None,
    max_width: int = 1600,
) -> CaptureData:
    if record.minimized:
        raise BridgeError(
            "E_CAPABILITY_UNAVAILABLE",
            "CSP is minimized; restore it before capture",
            retryable=True,
        )
    rect = _clip_to_virtual_screen(record.rect)
    assert_capture_target_visible(record, rect)
    try:
        image = ImageGrab.grab(bbox=rect, all_screens=True)
    except Exception as exc:
        raise BridgeError("E_CAPABILITY_UNAVAILABLE", f"Window capture failed: {exc}", retryable=True) from exc
    assert_capture_target_visible(record, rect)
    source_width, source_height = image.size
    if region is not None:
        if len(region) != 4:
            raise BridgeError("E_POLICY_DENIED", "Region must contain x, y, width, height", stage="validation")
        x, y, width, height = (float(v) for v in region)
        if not (0 <= x < 1 and 0 <= y < 1 and width > 0 and height > 0 and x + width <= 1 and y + height <= 1):
            raise BridgeError("E_POLICY_DENIED", "Region must be normalized inside 0..1", stage="validation")
        crop = (
            round(x * source_width), round(y * source_height),
            round((x + width) * source_width), round((y + height) * source_height),
        )
        image = image.crop(crop)
    if image.width > max_width:
        target_height = max(1, round(image.height * max_width / image.width))
        image = image.resize((max_width, target_height), Image.Resampling.LANCZOS)
    gray = image.convert("L")
    stddev = float(ImageStat.Stat(gray).stddev[0])
    output = io.BytesIO()
    image.save(output, format="PNG", optimize=True)
    png = output.getvalue()
    return CaptureData(
        png=png,
        width=image.width,
        height=image.height,
        source_width=source_width,
        source_height=source_height,
        rect=rect,
        sha256=hashlib.sha256(png).hexdigest(),
        luminance_stddev=round(stddev, 3),
    )


def visual_difference(first_png: bytes, second_png: bytes) -> float:
    with Image.open(io.BytesIO(first_png)) as first, Image.open(io.BytesIO(second_png)) as second:
        a = first.convert("RGB").resize((256, 256), Image.Resampling.BILINEAR)
        b = second.convert("RGB").resize((256, 256), Image.Resampling.BILINEAR)
        raw_a = a.tobytes()
        raw_b = b.tobytes()
    changed = sum(abs(x - y) >= 8 for x, y in zip(raw_a, raw_b))
    return round(changed / max(1, len(raw_a)), 6)


def sample_pixel(png: bytes, x: float, y: float) -> dict[str, int | str]:
    if not (0 <= x <= 1 and 0 <= y <= 1):
        raise BridgeError("E_POLICY_DENIED", "Pixel coordinates must be normalized 0..1", stage="validation")
    with Image.open(io.BytesIO(png)) as image:
        rgba = image.convert("RGBA")
        px = min(rgba.width - 1, round(x * (rgba.width - 1)))
        py = min(rgba.height - 1, round(y * (rgba.height - 1)))
        r, g, b, a = rgba.getpixel((px, py))
    return {"r": r, "g": g, "b": b, "a": a, "hex": f"#{r:02X}{g:02X}{b:02X}{a:02X}"}


ULONG_PTR = wt.WPARAM


class MOUSEINPUT(ctypes.Structure):
    _fields_ = [
        ("dx", wt.LONG), ("dy", wt.LONG), ("mouseData", wt.DWORD),
        ("dwFlags", wt.DWORD), ("time", wt.DWORD), ("dwExtraInfo", ULONG_PTR),
    ]


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [
        ("wVk", wt.WORD), ("wScan", wt.WORD), ("dwFlags", wt.DWORD),
        ("time", wt.DWORD), ("dwExtraInfo", ULONG_PTR),
    ]


class HARDWAREINPUT(ctypes.Structure):
    _fields_ = [("uMsg", wt.DWORD), ("wParamL", wt.WORD), ("wParamH", wt.WORD)]


class INPUT_UNION(ctypes.Union):
    _fields_ = [("mi", MOUSEINPUT), ("ki", KEYBDINPUT), ("hi", HARDWAREINPUT)]


class INPUT(ctypes.Structure):
    _anonymous_ = ("union",)
    _fields_ = [("type", wt.DWORD), ("union", INPUT_UNION)]


INPUT_MOUSE = 0
INPUT_KEYBOARD = 1
KEYEVENTF_KEYUP = 0x0002
KEYEVENTF_UNICODE = 0x0004
MOUSEEVENTF_MOVE = 0x0001
MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004
MOUSEEVENTF_RIGHTDOWN = 0x0008
MOUSEEVENTF_RIGHTUP = 0x0010
MOUSEEVENTF_MIDDLEDOWN = 0x0020
MOUSEEVENTF_MIDDLEUP = 0x0040
MOUSEEVENTF_WHEEL = 0x0800
MOUSEEVENTF_ABSOLUTE = 0x8000
MOUSEEVENTF_VIRTUALDESK = 0x4000
WHEEL_DELTA = 120


VK: dict[str, int] = {
    "CTRL": win32con.VK_CONTROL,
    "SHIFT": win32con.VK_SHIFT,
    "ALT": win32con.VK_MENU,
    "WIN": 0x5B,
    "ESCAPE": win32con.VK_ESCAPE,
    "ENTER": win32con.VK_RETURN,
    "TAB": win32con.VK_TAB,
    "SPACE": win32con.VK_SPACE,
    "BACKSPACE": win32con.VK_BACK,
    "DELETE": win32con.VK_DELETE,
    "INSERT": win32con.VK_INSERT,
    "HOME": win32con.VK_HOME,
    "END": win32con.VK_END,
    "PAGEUP": win32con.VK_PRIOR,
    "PAGEDOWN": win32con.VK_NEXT,
    "LEFT": win32con.VK_LEFT,
    "RIGHT": win32con.VK_RIGHT,
    "UP": win32con.VK_UP,
    "DOWN": win32con.VK_DOWN,
    "PLUS": 0xBB,
    "MINUS": 0xBD,
}
VK.update({chr(code): code for code in range(ord("A"), ord("Z") + 1)})
VK.update({str(value): ord(str(value)) for value in range(10)})
VK.update({f"F{value}": win32con.VK_F1 + value - 1 for value in range(1, 25)})


def validate_keys(keys: Iterable[str]) -> list[str]:
    normalized = [str(key).upper() for key in keys]
    if not normalized or len(normalized) > 5 or any(key not in VK for key in normalized):
        raise BridgeError("E_COMMAND_NOT_ALLOWLISTED", "Command contains an unsupported key", stage="validation")
    if len(set(normalized)) != len(normalized):
        raise BridgeError("E_COMMAND_NOT_ALLOWLISTED", "Command contains duplicate keys", stage="validation")
    return normalized


def _send(inputs: list[INPUT]) -> None:
    if not inputs:
        return
    array_type = INPUT * len(inputs)
    sent = user32.SendInput(len(inputs), array_type(*inputs), ctypes.sizeof(INPUT))
    if sent != len(inputs):
        raise BridgeError("E_UI_TIMEOUT", "Windows SendInput did not accept every event", state_change="possible")


def _assert_initial_input_authority(
    target: WindowRecord | None,
    expected_last_input_tick: int | None,
    *,
    allowed_pressed_codes: frozenset[int] = frozenset(),
) -> None:
    pressed = []
    if target is not None or expected_last_input_tick is not None:
        pressed = [
            item
            for item in pressed_input_keys()
            if int(item["code"]) not in allowed_pressed_codes
        ]
    actual_tick: int | None = None
    if expected_last_input_tick is not None:
        actual_tick = get_last_input()[0]
    if (
        expected_last_input_tick is not None
        and actual_tick != expected_last_input_tick
    ) or pressed:
        raise BridgeError(
            "E_USER_INTERRUPTED",
            "Keyboard or mouse state changed at the SendInput boundary",
            retryable=True,
            details={
                "expectedLastInputTick": expected_last_input_tick,
                "actualLastInputTick": actual_tick,
                "pressedInputs": pressed,
            },
        )
    if target is not None:
        assert_foreground_target(target)


def _key(vk: int, up: bool = False) -> INPUT:
    return INPUT(type=INPUT_KEYBOARD, ki=KEYBDINPUT(vk, 0, KEYEVENTF_KEYUP if up else 0, 0, 0))


def _best_effort_release(inputs: Sequence[INPUT]) -> None:
    """Attempt every release separately so one rejected event cannot skip the rest."""
    first_error: BridgeError | None = None
    for item in inputs:
        released = False
        last_error: BridgeError | None = None
        for _attempt in range(3):
            try:
                _send([item])
                released = True
                break
            except BridgeError as exc:
                last_error = exc
        if not released and first_error is None:
            first_error = last_error
    if first_error is not None:
        raise BridgeError(
            "E_PARTIAL_COMPLETION",
            "One or more synthetic key/button release events were rejected after retries",
            state_change="possible",
            details={"cause": first_error.code, "releaseRetries": 3},
            recovery=["Release any held key or mouse button manually", "Call csp_get_state"],
        ) from first_error


def send_chord(
    keys: Sequence[str],
    target: WindowRecord | None = None,
    *,
    expected_last_input_tick: int | None = None,
) -> None:
    normalized = validate_keys(keys)
    codes = [VK[key] for key in normalized]
    inputs = [_key(code, False) for code in codes]
    inputs.extend(_key(code, True) for code in reversed(codes))
    _assert_initial_input_authority(target, expected_last_input_tick)
    try:
        _send(inputs)
    except BridgeError:
        # A partial SendInput can stop after any key-down, including a
        # non-modifier such as Enter or S. Release every key that this chord
        # could have pressed. Do not send unrelated global modifier key-ups.
        release_codes = list(reversed(codes))
        _best_effort_release([_key(code, True) for code in release_codes])
        raise


def send_unicode_text(
    text: str,
    target: WindowRecord | None = None,
    *,
    cancel_event: threading.Event | None = None,
    batch_units: int = 32,
    expected_last_input_tick: int | None = None,
) -> None:
    encoded = text.encode("utf-16-le")
    units = [int.from_bytes(encoded[i:i + 2], "little") for i in range(0, len(encoded), 2)]
    completed_units = 0
    batch_units = max(1, min(batch_units, 128))
    batches: list[list[int]] = []
    current_batch: list[int] = []
    for character in text:
        encoded_character = character.encode("utf-16-le")
        character_units = [
            int.from_bytes(encoded_character[index:index + 2], "little")
            for index in range(0, len(encoded_character), 2)
        ]
        if current_batch and len(current_batch) + len(character_units) > batch_units:
            batches.append(current_batch)
            current_batch = []
        current_batch.extend(character_units)
    if current_batch:
        batches.append(current_batch)

    for batch in batches:
        if cancel_event is not None and cancel_event.is_set():
            raise BridgeError(
                "E_PARTIAL_COMPLETION" if completed_units else "E_CANCELLED",
                "Unicode input was cancelled before all UTF-16 units were sent",
                retryable=True,
                state_change="possible" if completed_units else "none",
                details={"completedUtf16Units": completed_units, "totalUtf16Units": len(units)},
            )
        if completed_units == 0:
            _assert_initial_input_authority(target, expected_last_input_tick)
        elif target is not None:
            try:
                _assert_initial_input_authority(target, None)
            except BridgeError as exc:
                if completed_units:
                    raise BridgeError(
                        "E_PARTIAL_COMPLETION",
                        "Unicode input stopped because focus or held-input state changed",
                        retryable=True,
                        state_change="possible",
                        details={
                            "completedUtf16Units": completed_units,
                            "totalUtf16Units": len(units),
                            "cause": exc.code,
                        },
                        recovery=["Call csp_get_state", "Call csp_capture before retrying"],
                    ) from exc
                raise
        inputs: list[INPUT] = []
        for unit in batch:
            inputs.append(INPUT(type=INPUT_KEYBOARD, ki=KEYBDINPUT(0, unit, KEYEVENTF_UNICODE, 0, 0)))
            inputs.append(INPUT(type=INPUT_KEYBOARD, ki=KEYBDINPUT(0, unit, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP, 0, 0)))
        try:
            _send(inputs)
        except BridgeError as exc:
            releases = [
                INPUT(
                    type=INPUT_KEYBOARD,
                    ki=KEYBDINPUT(0, unit, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP, 0, 0),
                )
                for unit in reversed(batch)
            ]
            cleanup_failed = False
            try:
                _send(releases)
            except BridgeError:
                try:
                    _best_effort_release(releases)
                except BridgeError:
                    cleanup_failed = True
            raise BridgeError(
                "E_PARTIAL_COMPLETION",
                "Unicode input stopped after a partial SendInput batch",
                state_change="possible",
                details={
                    "completedUtf16Units": completed_units,
                    "totalUtf16Units": len(units),
                    "releaseCleanupFailed": cleanup_failed,
                    "cause": exc.code,
                },
                recovery=["Release any held key manually", "Call csp_get_state", "Call csp_capture"],
            ) from exc
        completed_units += len(batch)


def release_all_inputs() -> None:
    key_inputs = [_key(code, True) for code in (VK["CTRL"], VK["SHIFT"], VK["ALT"], 0x5B, 0x5C)]
    mouse_inputs = [
        INPUT(type=INPUT_MOUSE, mi=MOUSEINPUT(0, 0, 0, MOUSEEVENTF_LEFTUP, 0, 0)),
        INPUT(type=INPUT_MOUSE, mi=MOUSEINPUT(0, 0, 0, MOUSEEVENTF_RIGHTUP, 0, 0)),
        INPUT(type=INPUT_MOUSE, mi=MOUSEINPUT(0, 0, 0, MOUSEEVENTF_MIDDLEUP, 0, 0)),
    ]
    _best_effort_release(key_inputs + mouse_inputs)


def normalized_point(record: WindowRecord, x: float, y: float, region: str) -> tuple[int, int]:
    if not (0 <= x <= 1 and 0 <= y <= 1):
        raise BridgeError("E_POLICY_DENIED", "Coordinates must be normalized 0..1", stage="validation")
    if region == "client":
        left, top, right, bottom = record.client_rect
    elif region == "window":
        left, top, right, bottom = record.rect
    else:
        raise BridgeError("E_POLICY_DENIED", "Region must be client or window", stage="validation")
    if right <= left or bottom <= top:
        raise BridgeError("E_CAPABILITY_UNAVAILABLE", "Target region has no visible area")
    return (
        min(right - 1, max(left, round(left + x * (right - left - 1)))),
        min(bottom - 1, max(top, round(top + y * (bottom - top - 1)))),
    )


def _absolute_mouse_input(x: int, y: int, flags: int, data: int = 0) -> INPUT:
    vx = win32api.GetSystemMetrics(win32con.SM_XVIRTUALSCREEN)
    vy = win32api.GetSystemMetrics(win32con.SM_YVIRTUALSCREEN)
    vw = win32api.GetSystemMetrics(win32con.SM_CXVIRTUALSCREEN)
    vh = win32api.GetSystemMetrics(win32con.SM_CYVIRTUALSCREEN)
    dx = round((x - vx) * 65535 / max(1, vw - 1))
    dy = round((y - vy) * 65535 / max(1, vh - 1))
    return INPUT(
        type=INPUT_MOUSE,
        mi=MOUSEINPUT(dx, dy, data, flags | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK, 0, 0),
    )


def move_pointer(
    x: int,
    y: int,
    target: WindowRecord | None = None,
    *,
    expected_last_input_tick: int | None = None,
) -> None:
    if target is not None:
        assert_point_target(target, x, y)
    _assert_initial_input_authority(target, expected_last_input_tick)
    _send([_absolute_mouse_input(x, y, MOUSEEVENTF_MOVE)])


def click_pointer(
    x: int,
    y: int,
    *,
    button: str = "left",
    count: int = 1,
    interval_ms: int = 100,
    target: WindowRecord | None = None,
    cancel_event: threading.Event | None = None,
    expected_last_input_tick: int | None = None,
) -> None:
    flags = {
        "left": (MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP),
        "right": (MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP),
        "middle": (MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP),
    }
    if button not in flags or count not in {1, 2}:
        raise BridgeError("E_POLICY_DENIED", "Invalid mouse button or click count", stage="validation")
    down, up = flags[button]
    completed = 0
    if cancel_event is not None and cancel_event.is_set():
        raise BridgeError("E_CANCELLED", "Mouse click was cancelled before input", retryable=True)
    if target is not None:
        assert_point_target(target, x, y)
    _assert_initial_input_authority(target, expected_last_input_tick)
    try:
        _send(
            [
                _absolute_mouse_input(x, y, MOUSEEVENTF_MOVE),
                _absolute_mouse_input(x, y, down),
                _absolute_mouse_input(x, y, up),
            ]
        )
        completed = 1
        for index in range(1, count):
            delay = max(0, min(interval_ms, 500)) / 1000
            if cancel_event is not None:
                if cancel_event.wait(delay):
                    raise BridgeError(
                        "E_CANCELLED",
                        "Mouse double-click was cancelled after the first click",
                        retryable=True,
                        state_change="possible",
                    )
            else:
                time.sleep(delay)
            if cancel_event is not None and cancel_event.is_set():
                raise BridgeError(
                    "E_CANCELLED",
                    "Mouse click was cancelled before the next click",
                    retryable=True,
                    state_change="possible" if completed else "none",
                )
            if target is not None:
                assert_point_target(target, x, y)
            _assert_initial_input_authority(target, None)
            _send([_absolute_mouse_input(x, y, down), _absolute_mouse_input(x, y, up)])
            completed += 1
    except BridgeError as exc:
        cleanup_error: BridgeError | None = None
        try:
            _best_effort_release([_absolute_mouse_input(x, y, up)])
        except BridgeError as cleanup_exc:
            cleanup_error = cleanup_exc
        if completed or cleanup_error is not None:
            raise BridgeError(
                "E_PARTIAL_COMPLETION",
                "Mouse click input may have stopped after a button-down event",
                state_change="possible",
                details={
                    "completedClicks": completed,
                    "cause": exc.code,
                    "releaseCleanupFailed": cleanup_error is not None,
                },
                recovery=["Release the mouse button manually", "Call csp_get_state", "Call csp_capture"],
            ) from exc
        raise


def drag_pointer(
    start: tuple[int, int],
    end: tuple[int, int],
    *,
    button: str,
    duration: float,
    target: WindowRecord | None = None,
    cancel_event: threading.Event | None = None,
    expected_last_input_tick: int | None = None,
) -> None:
    flags = {
        "left": (MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP),
        "right": (MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP),
        "middle": (MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP),
    }
    if button not in flags:
        raise BridgeError("E_POLICY_DENIED", "Invalid drag button", stage="validation")
    duration = max(0.05, duration)
    steps = max(2, min(240, round(duration * 60)))
    down, up = flags[button]
    held_mouse_code = {
        "left": win32con.VK_LBUTTON,
        "right": win32con.VK_RBUTTON,
        "middle": win32con.VK_MBUTTON,
    }[button]
    if target is not None:
        assert_point_target(target, *end)
    if cancel_event is not None and cancel_event.is_set():
        raise BridgeError("E_CANCELLED", "Drag was cancelled before mouse-down", retryable=True)
    if target is not None:
        assert_point_target(target, *start)
    _assert_initial_input_authority(target, expected_last_input_tick)
    current = start
    started = False
    primary_error: BridgeError | None = None
    try:
        _send(
            [
                _absolute_mouse_input(*start, MOUSEEVENTF_MOVE),
                _absolute_mouse_input(*start, down),
            ]
        )
        started = True
        for step in range(1, steps + 1):
            if cancel_event is not None and cancel_event.is_set():
                raise BridgeError(
                    "E_CANCELLED",
                    "Drag was cancelled after mouse-down",
                    retryable=True,
                    state_change="possible",
                )
            ratio = step / steps
            eased = ratio * ratio * (3 - 2 * ratio)
            x = round(start[0] + (end[0] - start[0]) * eased)
            y = round(start[1] + (end[1] - start[1]) * eased)
            if target is not None:
                assert_point_target(target, x, y)
            _assert_initial_input_authority(
                target,
                None,
                allowed_pressed_codes=frozenset({held_mouse_code}),
            )
            _send([_absolute_mouse_input(x, y, MOUSEEVENTF_MOVE)])
            current = (x, y)
            time.sleep(duration / steps)
    except BridgeError as exc:
        primary_error = exc
    cleanup_error: BridgeError | None = None
    if started:
        try:
            _best_effort_release([_absolute_mouse_input(*current, up)])
        except BridgeError as exc:
            cleanup_error = exc
    if primary_error is not None:
        if started or cleanup_error is not None:
            raise BridgeError(
                "E_PARTIAL_COMPLETION",
                "Drag input was interrupted after mouse-down or release could not be confirmed",
                state_change="possible",
                details={
                    "lastScreenPoint": list(current),
                    "cause": primary_error.code,
                    "releaseCleanupFailed": cleanup_error is not None,
                },
                recovery=[
                    "Release the mouse button manually",
                    "Call csp_get_state",
                    "Call csp_capture",
                ],
            ) from primary_error
        raise primary_error
    if cleanup_error is not None:
        raise cleanup_error


def scroll_pointer(
    x: int,
    y: int,
    *,
    delta: int,
    target: WindowRecord | None = None,
    expected_last_input_tick: int | None = None,
) -> None:
    if delta == 0 or abs(delta) > 20:
        raise BridgeError("E_POLICY_DENIED", "Scroll delta must be between -20 and 20, excluding zero", stage="validation")
    if target is not None:
        assert_point_target(target, x, y)
    _assert_initial_input_authority(target, expected_last_input_tick)
    wheel_data = ctypes.c_ulong(delta * WHEEL_DELTA).value
    _send(
        [
            _absolute_mouse_input(x, y, MOUSEEVENTF_MOVE),
            _absolute_mouse_input(x, y, MOUSEEVENTF_WHEEL, wheel_data),
        ]
    )


def inspect_child_windows(hwnd: int, *, max_items: int = 200) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []

    def callback(child: int, _: Any) -> bool:
        if len(items) >= max_items:
            return False
        try:
            rect = win32gui.GetWindowRect(child)
            items.append(
                {
                    "hwnd": int(child),
                    "parent": int(win32gui.GetParent(child) or 0),
                    "className": win32gui.GetClassName(child),
                    "text": win32gui.GetWindowText(child)[:256],
                    "rect": list(rect),
                    "visible": bool(win32gui.IsWindowVisible(child)),
                    "enabled": bool(win32gui.IsWindowEnabled(child)),
                    "controlId": int(win32gui.GetDlgCtrlID(child)),
                }
            )
        except Exception:
            pass
        return True

    win32gui.EnumChildWindows(hwnd, callback, None)
    return items


def list_process_dialogs(
    expected_executable: Path,
    pid: int,
    *,
    main_hwnd: int = 0,
) -> list[WindowRecord]:
    return [
        record for record in enum_csp_windows(expected_executable, include_dialogs=True)
        if record.pid == pid and (record.owner != 0 or record.class_name == "#32770")
        and (not main_hwnd or window_belongs_to_main(record.hwnd, main_hwnd))
    ]


def _native_file_dialog_controls(dialog_hwnd: int) -> tuple[int, int, str]:
    if not win32gui.IsWindow(dialog_hwnd):
        raise BridgeError("E_WINDOW_NOT_FOUND", "Native file dialog no longer exists", retryable=True)
    if win32gui.GetClassName(dialog_hwnd) != "#32770":
        raise BridgeError("E_CAPABILITY_UNAVAILABLE", "Target is not a standard Windows file dialog")
    children = inspect_child_windows(dialog_hwnd, max_items=500)
    shell_views = [
        item for item in children
        if item["className"] == "SHELLDLL_DefView" and item["controlId"] == 1121 and item["visible"]
    ]
    edits = [
        item for item in children
        if item["className"] == "Edit"
        and item["controlId"] in {1148, 1152}
        and item["visible"]
        and item["enabled"]
    ]
    ok_buttons = [
        item for item in children
        if item["className"] == "Button"
        and item["controlId"] == win32con.IDOK
        and item["visible"]
        and item["enabled"]
    ]
    if len(shell_views) != 1 or len(edits) != 1 or len(ok_buttons) != 1:
        raise BridgeError(
            "E_CAPABILITY_UNAVAILABLE",
            "Dialog does not match the validated Windows file-dialog control profile",
            retryable=True,
            details={
                "shellViewCount": len(shell_views),
                "fileNameEditCount": len(edits),
                "okButtonCount": len(ok_buttons),
            },
        )
    title = win32gui.GetWindowText(dialog_hwnd).strip()
    button_text = str(ok_buttons[0]["text"]).strip()
    if "打开" in title and "打开" in button_text:
        mode = "input"
    elif any(token in title for token in ("另存为", "保存", "导出")) and any(
        token in button_text for token in ("保存", "导出")
    ):
        mode = "output"
    else:
        raise BridgeError(
            "E_CAPABILITY_UNAVAILABLE",
            "File dialog title and IDOK label do not match the pinned zh-CN open/save profile",
            retryable=True,
        )
    return int(edits[0]["hwnd"]), int(ok_buttons[0]["hwnd"]), mode


def validate_native_file_dialog(dialog_hwnd: int, intent: str | None = None) -> dict[str, Any]:
    edit_handle, ok_button, mode = _native_file_dialog_controls(dialog_hwnd)
    expected_mode = "input" if intent == "input" else "output" if intent in {"output_new", "output_replace"} else None
    if expected_mode is not None and mode != expected_mode:
        raise BridgeError(
            "E_POLICY_DENIED",
            f"A {mode} file dialog cannot be used for {intent}",
            stage="validation",
        )
    return {
        "dialogHwnd": dialog_hwnd,
        "fileNameEditHwnd": edit_handle,
        "okButtonHwnd": ok_button,
        "mode": mode,
    }


def submit_native_file_dialog(
    dialog_hwnd: int,
    path: Path,
    *,
    intent: str,
    submit: bool,
    cancel_event: threading.Event | None = None,
    expected_main_hwnd: int = 0,
    expected_last_input_tick: int | None = None,
    submission_deadline: float | None = None,
) -> dict[str, Any]:
    def assert_exact_target(*, path_may_be_filled: bool) -> None:
        if expected_main_hwnd and (
            foreground_window() != dialog_hwnd
            or _pid_for_window(dialog_hwnd) != _pid_for_window(expected_main_hwnd)
            or not window_belongs_to_main(dialog_hwnd, expected_main_hwnd)
        ):
            raise BridgeError(
                "E_USER_INTERRUPTED",
                "The exact CSP file dialog lost foreground ownership",
                retryable=True,
                state_change="possible" if path_may_be_filled else "none",
                details={"pathMayBeFilled": path_may_be_filled, "submitted": False},
                recovery=["Inspect or cancel the still-open file dialog"],
            )
        if expected_last_input_tick is not None and get_last_input()[0] != expected_last_input_tick:
            raise BridgeError(
                "E_USER_INTERRUPTED",
                "Keyboard or mouse input occurred after destructive confirmation",
                retryable=True,
                state_change="possible" if path_may_be_filled else "none",
                details={"pathMayBeFilled": path_may_be_filled, "submitted": False},
                recovery=["Inspect the dialog and repeat preflight"],
            )
        if submission_deadline is not None and time.monotonic() > submission_deadline:
            raise BridgeError(
                "E_CONFIRM_EXPIRED",
                "Destructive confirmation expired before dialog submission",
                retryable=True,
                state_change="possible" if path_may_be_filled else "none",
                details={"pathMayBeFilled": path_may_be_filled, "submitted": False},
                recovery=["Inspect the dialog and repeat preflight"],
            )

    assert_exact_target(path_may_be_filled=False)
    profile = validate_native_file_dialog(dialog_hwnd, intent)
    edit_handle = int(profile["fileNameEditHwnd"])
    button = int(profile["okButtonHwnd"])
    text_buffer = ctypes.create_unicode_buffer(str(path))
    message_result = ctypes.c_size_t()
    sent = user32.SendMessageTimeoutW(
        edit_handle,
        win32con.WM_SETTEXT,
        0,
        ctypes.cast(text_buffer, ctypes.c_void_p).value or 0,
        win32con.SMTO_ABORTIFHUNG | win32con.SMTO_BLOCK,
        2000,
        ctypes.byref(message_result),
    )
    read_buffer = ctypes.create_unicode_buffer(max(2, len(str(path)) + 2))
    read_result = ctypes.c_size_t()
    read = user32.SendMessageTimeoutW(
        edit_handle,
        win32con.WM_GETTEXT,
        len(read_buffer),
        ctypes.cast(read_buffer, ctypes.c_void_p).value or 0,
        win32con.SMTO_ABORTIFHUNG | win32con.SMTO_BLOCK,
        2000,
        ctypes.byref(read_result),
    )
    if not sent or not read or read_buffer.value != str(path):
        raise BridgeError(
            "E_PARTIAL_COMPLETION",
            "The file-name field did not accept the validated path exactly",
            state_change="possible",
            recovery=["Inspect the dialog and cancel it before retrying"],
        )
    assert_exact_target(path_may_be_filled=True)
    if cancel_event is not None and cancel_event.is_set():
        raise BridgeError(
            "E_CANCELLED",
            "The path was filled, but cancellation prevented dialog submission",
            retryable=True,
            state_change="possible",
            details={"pathFilled": True, "submitted": False},
            recovery=["Inspect or cancel the still-open file dialog"],
        )
    result: dict[str, Any] = {
        "dialogHwnd": dialog_hwnd,
        "dialogMode": profile["mode"],
        "pathSet": True,
        "submissionRequested": False,
        "submitted": False,
    }
    if not submit:
        return result
    assert_exact_target(path_may_be_filled=True)
    refreshed_profile = validate_native_file_dialog(dialog_hwnd, intent)
    if (
        int(refreshed_profile["fileNameEditHwnd"]) != edit_handle
        or int(refreshed_profile["okButtonHwnd"]) != button
    ):
        raise BridgeError(
            "E_USER_INTERRUPTED",
            "The native dialog control identity changed before submission",
            retryable=True,
            state_change="possible",
            recovery=["Inspect or cancel the still-open file dialog"],
        )
    final_buffer = ctypes.create_unicode_buffer(max(2, len(str(path)) + 2))
    final_read_result = ctypes.c_size_t()
    final_read = user32.SendMessageTimeoutW(
        edit_handle,
        win32con.WM_GETTEXT,
        len(final_buffer),
        ctypes.cast(final_buffer, ctypes.c_void_p).value or 0,
        win32con.SMTO_ABORTIFHUNG | win32con.SMTO_BLOCK,
        2000,
        ctypes.byref(final_read_result),
    )
    if not final_read or final_buffer.value != str(path):
        raise BridgeError(
            "E_USER_INTERRUPTED",
            "The file-name field changed before submission",
            retryable=True,
            state_change="possible",
            details={"submitted": False},
            recovery=["Inspect or cancel the still-open file dialog"],
        )
    if cancel_event is not None and cancel_event.is_set():
        raise BridgeError(
            "E_CANCELLED",
            "Cancellation prevented dialog submission after path verification",
            retryable=True,
            state_change="possible",
            details={"pathFilled": True, "submitted": False},
            recovery=["Inspect or cancel the still-open file dialog"],
        )
    assert_exact_target(path_may_be_filled=True)
    clicked = user32.SendMessageTimeoutW(
        button,
        win32con.BM_CLICK,
        0,
        0,
        win32con.SMTO_ABORTIFHUNG | win32con.SMTO_BLOCK,
        2000,
        ctypes.byref(message_result),
    )
    if not clicked:
        raise BridgeError(
            "E_PARTIAL_COMPLETION",
            "The validated file dialog did not accept its IDOK action",
            state_change="possible",
            recovery=["Inspect the dialog and cancel it before retrying"],
        )
    result["submissionRequested"] = True
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline and win32gui.IsWindow(dialog_hwnd) and win32gui.IsWindowVisible(dialog_hwnd):
        time.sleep(0.05)
    result["submitted"] = not win32gui.IsWindow(dialog_hwnd) or not win32gui.IsWindowVisible(dialog_hwnd)
    return result
