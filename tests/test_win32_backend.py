from __future__ import annotations

import unittest
import uuid
import threading
from pathlib import Path
from unittest.mock import patch

from csp_mcp import win32_backend as backend
from csp_mcp.config import OverlayIdentity
from csp_mcp.errors import BridgeError
from csp_mcp.win32_backend import (
    ControlGeneration,
    KEYEVENTF_KEYUP,
    KEYEVENTF_UNICODE,
    WindowRecord,
    capture_rect_covers_visible_main_chain,
    click_pointer,
    choose_csp_window,
    normalized_point,
    pressed_input_keys,
    rect_fully_inside_virtual_screen,
    root_owner_window,
    send_chord,
    send_unicode_text,
    validate_keys,
    window_belongs_to_main,
)


class Win32BackendTests(unittest.TestCase):
    def setUp(self) -> None:
        self.window = WindowRecord(
            hwnd=1,
            pid=2,
            title="CSP",
            class_name="test",
            rect=(100, 100, 1100, 900),
            client_rect=(120, 140, 1080, 880),
            visible=True,
            minimized=False,
            maximized=False,
            owner=0,
            dpi=120,
            executable=r"D:\CSP.exe",
            show_cmd=1,
            normal_rect=(100, 100, 1100, 900),
        )

    def test_normalized_coordinates_stay_inside_target(self) -> None:
        self.assertEqual(normalized_point(self.window, 0, 0, "window"), (100, 100))
        self.assertEqual(normalized_point(self.window, 1, 1, "window"), (1099, 899))
        x, y = normalized_point(self.window, 0.5, 0.5, "client")
        self.assertTrue(120 <= x < 1080)
        self.assertTrue(140 <= y < 880)

    def test_maximized_interaction_rect_excludes_taskbar_and_dwm_overflow(self) -> None:
        with (
            patch.object(backend.win32api, "MonitorFromWindow", return_value=object()),
            patch.object(
                backend.win32api,
                "GetMonitorInfo",
                return_value={"Work": (0, 0, 2560, 1380)},
            ),
        ):
            self.assertEqual(
                backend._interaction_rect(
                    1,
                    (-9, -9, 2569, 1389),
                    maximized=True,
                ),
                (0, 0, 2560, 1380),
            )
            self.assertEqual(
                backend._interaction_rect(
                    1,
                    (100, 100, 1100, 900),
                    maximized=False,
                ),
                (100, 100, 1100, 900),
            )

    def test_registered_key_validation(self) -> None:
        self.assertEqual(validate_keys(["ctrl", "z"]), ["CTRL", "Z"])
        with self.assertRaises(Exception):
            validate_keys(["CTRL", "NOT_A_KEY"])

    def test_named_control_generation_is_shared(self) -> None:
        name = f"Local\\CspLocalMcp.Test.{uuid.uuid4()}"
        first = ControlGeneration(name)
        second = ControlGeneration(name)
        baseline = first.current()
        self.assertEqual(second.current(), baseline)
        self.assertEqual(first.advance(), baseline + 1)
        self.assertEqual(second.current(), baseline + 1)

    def test_multiple_same_process_windows_require_explicit_hwnd(self) -> None:
        second = WindowRecord(**{**self.window.__dict__, "hwnd": 2})
        with patch("csp_mcp.win32_backend.enum_csp_windows", return_value=[self.window, second]):
            with self.assertRaises(BridgeError) as raised:
                choose_csp_window(Path(r"D:\CSP.exe"))
            self.assertEqual(raised.exception.code, "E_AMBIGUOUS_TARGET")
            self.assertEqual(choose_csp_window(Path(r"D:\CSP.exe"), hwnd=2).hwnd, 2)

    def test_owned_popup_and_child_are_bound_to_exact_main_window(self) -> None:
        roots = {10: 20, 20: 20, 1: 1, 2: 2}
        owners = {20: 1, 1: 0, 2: 0}
        with (
            patch("csp_mcp.win32_backend.win32gui.GetAncestor", side_effect=lambda hwnd, _: roots[hwnd]),
            patch("csp_mcp.win32_backend.win32gui.GetWindow", side_effect=lambda hwnd, _: owners.get(hwnd, 0)),
        ):
            self.assertEqual(root_owner_window(10), 1)
            self.assertTrue(window_belongs_to_main(10, 1))
            self.assertFalse(window_belongs_to_main(10, 2))
            self.assertFalse(window_belongs_to_main(2, 1))

    def test_partial_virtual_desktop_rect_is_not_input_safe(self) -> None:
        metrics = {
            76: 0,   # SM_XVIRTUALSCREEN
            77: 0,   # SM_YVIRTUALSCREEN
            78: 1920,  # SM_CXVIRTUALSCREEN
            79: 1080,  # SM_CYVIRTUALSCREEN
        }
        with patch("csp_mcp.win32_backend.win32api.GetSystemMetrics", side_effect=lambda key: metrics[key]):
            self.assertTrue(rect_fully_inside_virtual_screen((0, 0, 1920, 1080)))
            self.assertFalse(rect_fully_inside_virtual_screen((-10, 0, 1000, 800)))
            self.assertFalse(rect_fully_inside_virtual_screen((0, 0, 1930, 1080)))

    def test_capture_authority_requires_owned_popup_inside_screenshot(self) -> None:
        def enumerate_windows(callback, context):
            callback(1, context)
            callback(20, context)

        rects = {1: self.window.rect, 20: (200, 200, 900, 700)}
        with (
            patch("csp_mcp.win32_backend.rect_fully_inside_virtual_screen", return_value=True),
            patch("csp_mcp.win32_backend.foreground_window", return_value=20),
            patch("csp_mcp.win32_backend.window_belongs_to_main", side_effect=lambda hwnd, main: hwnd in {1, 20} and main == 1),
            patch("csp_mcp.win32_backend._pid_for_window", return_value=2),
            patch("csp_mcp.win32_backend.win32gui.EnumWindows", side_effect=enumerate_windows),
            patch("csp_mcp.win32_backend.win32gui.IsWindowVisible", return_value=True),
            patch("csp_mcp.win32_backend.win32gui.IsIconic", return_value=False),
            patch("csp_mcp.win32_backend.win32gui.GetWindowRect", side_effect=lambda hwnd: rects[hwnd]),
        ):
            self.assertTrue(capture_rect_covers_visible_main_chain(self.window, self.window.rect))
            rects[20] = (0, 0, 1, 1)
            self.assertTrue(capture_rect_covers_visible_main_chain(self.window, self.window.rect))
            rects[20] = (200, 200, 1200, 700)
            self.assertFalse(capture_rect_covers_visible_main_chain(self.window, self.window.rect))

    def test_capture_visibility_ignores_only_non_surface_one_pixel_helpers(self) -> None:
        rect = [(100, 100, 101, 101)]

        def previous_window(hwnd, _relation):
            return 20 if hwnd == self.window.hwnd else 0

        with (
            patch("csp_mcp.win32_backend.assert_foreground_target"),
            patch("csp_mcp.win32_backend.win32gui.GetWindow", side_effect=previous_window),
            patch("csp_mcp.win32_backend.win32gui.IsWindowVisible", return_value=True),
            patch("csp_mcp.win32_backend.win32gui.IsIconic", return_value=False),
            patch("csp_mcp.win32_backend.visible_window_rect", side_effect=lambda _hwnd: rect[0]),
            patch("csp_mcp.win32_backend.window_at_point", return_value=self.window.hwnd),
            patch(
                "csp_mcp.win32_backend._pid_for_window",
                side_effect=lambda hwnd: self.window.pid if hwnd == self.window.hwnd else 999,
            ),
            patch("csp_mcp.win32_backend.window_belongs_to_main", return_value=True),
        ):
            backend.assert_capture_target_visible(self.window, self.window.rect)
            rect[0] = (100, 100, 102, 102)
            with self.assertRaises(BridgeError):
                backend.assert_capture_target_visible(self.window, self.window.rect)

    def test_capture_visibility_skips_only_an_allowlisted_click_through_overlay(self) -> None:
        overlay = OverlayIdentity("Discord.exe", "Chrome_WidgetWin_1", "Discord Overlay")
        style = [backend.WS_EX_LAYERED | backend.WS_EX_TRANSPARENT]
        title = ["Discord Overlay"]

        def previous_window(hwnd, _relation):
            return 20 if hwnd == self.window.hwnd else 0

        with (
            patch("csp_mcp.win32_backend.assert_foreground_target"),
            patch("csp_mcp.win32_backend.win32gui.GetWindow", side_effect=previous_window),
            patch("csp_mcp.win32_backend.win32gui.IsWindowVisible", return_value=True),
            patch("csp_mcp.win32_backend.win32gui.IsIconic", return_value=False),
            patch("csp_mcp.win32_backend.visible_window_rect", return_value=(0, 0, 2000, 2000)),
            patch("csp_mcp.win32_backend.window_at_point", return_value=self.window.hwnd),
            patch(
                "csp_mcp.win32_backend._pid_for_window",
                side_effect=lambda hwnd: self.window.pid if hwnd == self.window.hwnd else 999,
            ),
            patch("csp_mcp.win32_backend.window_belongs_to_main", side_effect=lambda hwnd, main: hwnd == main),
            patch("csp_mcp.win32_backend.win32gui.GetWindowLong", side_effect=lambda _hwnd, _index: style[0]),
            patch("csp_mcp.win32_backend.win32gui.GetClassName", return_value="Chrome_WidgetWin_1"),
            patch("csp_mcp.win32_backend.win32gui.GetWindowText", side_effect=lambda _hwnd: title[0]),
            patch("csp_mcp.win32_backend.process_path", return_value=Path(r"C:\Discord\Discord.exe")),
        ):
            # Not configured: the overlay blocks capture as any foreign window does.
            with self.assertRaises(BridgeError):
                backend.assert_capture_target_visible(self.window, self.window.rect)
            self.assertEqual(
                backend.assert_capture_target_visible(self.window, self.window.rect, [overlay]),
                (20,),
            )
            # Same identity, but a window that takes mouse input is not an overlay.
            style[0] = backend.WS_EX_LAYERED
            with self.assertRaises(BridgeError):
                backend.assert_capture_target_visible(self.window, self.window.rect, [overlay])
            style[0] = backend.WS_EX_LAYERED | backend.WS_EX_TRANSPARENT
            title[0] = "Discord"
            with self.assertRaises(BridgeError):
                backend.assert_capture_target_visible(self.window, self.window.rect, [overlay])

    def test_every_held_virtual_key_counts_as_human_activity(self) -> None:
        with patch(
            "csp_mcp.win32_backend.user32.GetAsyncKeyState",
            side_effect=lambda key: 0x8000 if key in {0x41, 0x5C} else 0,
        ):
            self.assertEqual(
                pressed_input_keys(),
                [
                    {"code": 0x41, "hex": "0x41", "name": "A"},
                    {"code": 0x5C, "hex": "0x5C", "name": "rightWin"},
                ],
            )

    def test_partial_chord_send_releases_every_chord_key_without_unrelated_modifiers(self) -> None:
        calls = []

        def partial_first(inputs):
            calls.append(inputs)
            if len(calls) == 1:
                raise BridgeError("E_UI_TIMEOUT", "partial", state_change="possible")

        with patch("csp_mcp.win32_backend._send", side_effect=partial_first):
            with self.assertRaises(BridgeError):
                send_chord(["ENTER"])
        self.assertEqual(len(calls), 2)
        released = calls[1:]
        self.assertTrue(all(len(batch) == 1 for batch in released))
        self.assertTrue(all(batch[0].ki.dwFlags & KEYEVENTF_KEYUP for batch in released))
        self.assertEqual(released[0][0].ki.wVk, 13)

    def test_partial_unicode_send_releases_utf16_unit(self) -> None:
        calls = []

        def partial_first(inputs):
            calls.append(inputs)
            if len(calls) == 1:
                raise BridgeError("E_UI_TIMEOUT", "partial", state_change="possible")

        with patch("csp_mcp.win32_backend._send", side_effect=partial_first):
            with self.assertRaises(BridgeError):
                send_unicode_text("晴")
        self.assertEqual(len(calls), 2)
        release = calls[1][0].ki
        self.assertEqual(release.wScan, ord("晴"))
        self.assertEqual(release.dwFlags, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP)

    def test_unicode_batches_never_split_a_surrogate_pair(self) -> None:
        calls = []

        with patch("csp_mcp.win32_backend._send", side_effect=lambda inputs: calls.append(inputs)):
            send_unicode_text("A😀B", batch_units=1)

        key_down_scans = [
            [item.ki.wScan for item in batch if not (item.ki.dwFlags & KEYEVENTF_KEYUP)]
            for batch in calls
        ]
        self.assertEqual(key_down_scans, [[ord("A")], [0xD83D, 0xDE00], [ord("B")]])

    def test_failure_in_later_unicode_batch_reports_possible_partial_state(self) -> None:
        calls = []

        def fail_second_batch(inputs):
            calls.append(inputs)
            if len(calls) == 2:
                raise BridgeError("E_UI_TIMEOUT", "partial", state_change="possible")

        with patch("csp_mcp.win32_backend._send", side_effect=fail_second_batch):
            with self.assertRaises(BridgeError) as raised:
                send_unicode_text("A晴", batch_units=1)

        self.assertEqual(raised.exception.code, "E_PARTIAL_COMPLETION")
        self.assertEqual(raised.exception.state_change, "possible")
        self.assertEqual(len(calls), 3)
        cleanup = calls[2][0].ki
        self.assertEqual(cleanup.wScan, ord("晴"))
        self.assertEqual(cleanup.dwFlags, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP)

    def test_cancelled_double_click_never_sends_the_second_click(self) -> None:
        cancelled = threading.Event()
        calls = []

        def record(inputs):
            calls.append(inputs)
            if len(calls) == 1:
                cancelled.set()

        with patch("csp_mcp.win32_backend._send", side_effect=record):
            with self.assertRaises(BridgeError) as raised:
                click_pointer(200, 200, count=2, cancel_event=cancelled)

        self.assertEqual(raised.exception.code, "E_PARTIAL_COMPLETION")
        self.assertEqual(raised.exception.state_change, "possible")
        self.assertEqual(len(calls), 2)  # atomic move+first click, best-effort button-up

    def test_human_input_at_first_mouse_send_boundary_emits_zero_input(self) -> None:
        with (
            patch("csp_mcp.win32_backend.get_last_input", return_value=(124, 9999)),
            patch("csp_mcp.win32_backend.pressed_input_keys", return_value=[]),
            patch("csp_mcp.win32_backend._send") as send,
        ):
            with self.assertRaises(BridgeError) as raised:
                click_pointer(200, 200, expected_last_input_tick=123)
        self.assertEqual(raised.exception.code, "E_USER_INTERRUPTED")
        send.assert_not_called()

    def test_held_key_blocks_chord_even_without_tick_binding(self) -> None:
        with (
            patch(
                "csp_mcp.win32_backend.pressed_input_keys",
                return_value=[{"code": 0x12, "hex": "0x12", "name": "alt"}],
            ),
            patch("csp_mcp.win32_backend._send") as send,
        ):
            with self.assertRaises(BridgeError) as raised:
                send_chord(["ESCAPE"], target=self.window)
        self.assertEqual(raised.exception.code, "E_USER_INTERRUPTED")
        send.assert_not_called()


if __name__ == "__main__":
    unittest.main()
