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
    verified_new_dialog,
    assert_new_dialog_visible,
    new_dialog_owner_diagnostic,
    inspect_expanded_new_dialog_overlaps,
    send_expanded_new_dialog_escape,
    select_new_dialog_work_icon,
    confirm_expanded_new_dialog,
    enable_new_comic_multiple_pages,
    verified_page_copy_warning,
    choose_page_copy_warning,
    verified_cst_conversion_warning,
    accept_cst_conversion_warning,
    verified_cst_story_folder_dialog,
    confirm_cst_story_folder_dialog,
    verified_cst_conversion_error,
    send_cst_conversion_error_escape,
)


class Win32BackendTests(unittest.TestCase):
    def test_modern_save_dialog_requires_unique_filename_ancestor_chain(self) -> None:
        dialog = 10
        children = [
            {"hwnd": 11, "parent": dialog, "className": "SHELLDLL_DefView", "controlId": 1121, "visible": True, "enabled": True, "text": ""},
            {"hwnd": 12, "parent": dialog, "className": "DUIViewWndClassName", "controlId": 0, "visible": True, "enabled": True, "text": ""},
            {"hwnd": 13, "parent": 12, "className": "DirectUIHWND", "controlId": 0, "visible": True, "enabled": True, "text": ""},
            {"hwnd": 14, "parent": 13, "className": "FloatNotifySink", "controlId": 0, "visible": True, "enabled": True, "text": ""},
            {"hwnd": 15, "parent": 14, "className": "ComboBox", "controlId": 0, "visible": True, "enabled": True, "text": ""},
            {"hwnd": 16, "parent": 15, "className": "Edit", "controlId": 1001, "visible": True, "enabled": True, "text": "sample_16.clip"},
            {"hwnd": 17, "parent": dialog, "className": "Button", "controlId": backend.win32con.IDOK, "visible": True, "enabled": True, "text": "&Save"},
        ]

        def validate(items: list[dict[str, object]], title: str = "Save as") -> tuple[int, int, str]:
            with (
                patch.object(backend.win32gui, "IsWindow", return_value=True),
                patch.object(backend.win32gui, "GetClassName", return_value="#32770"),
                patch.object(backend.win32gui, "GetWindowText", return_value=title),
                patch.object(backend, "inspect_child_windows", return_value=items),
            ):
                return backend._native_file_dialog_controls(dialog)

        self.assertEqual(validate(children), (16, 17, "output"))
        with self.assertRaises(BridgeError):
            validate([{**item, "parent": dialog} if item["hwnd"] == 16 else item for item in children])
        with self.assertRaises(BridgeError):
            validate(children + [{**children[5], "hwnd": 18}])
        with self.assertRaises(BridgeError):
            validate(children, title="Open")
        legacy = [
            {**item, "controlId": 1148} if item["hwnd"] == 16 else item
            for item in children
        ]
        self.assertEqual(validate(legacy), (16, 17, "output"))

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

    def test_new_dialog_profile_rejects_ambiguous_and_detached_windows(self) -> None:
        main = WindowRecord(**{
            **self.window.__dict__, "hwnd": 10, "class_name": "CspMain",
            "rect": (0, 0, 2560, 1392), "dpi": 96,
        })
        dialog = WindowRecord(**{
            **main.__dict__, "hwnd": 20, "title": "New", "owner": 30,
            "class_name": main.class_name + backend.NEW_DIALOG_CLASS_SUFFIX,
            "rect": (509, 303, 1009, 878), "client_rect": (509, 303, 1009, 878),
        })
        owner = WindowRecord(**{
            **main.__dict__, "hwnd": 30, "title": "", "owner": main.hwnd,
            "class_name": main.class_name + backend.NEW_DIALOG_OWNER_CLASS_SUFFIX,
            "rect": (0, 0, 1, 1), "client_rect": (0, 0, 1, 1),
        })
        with (
            patch.object(backend, "enum_csp_windows", side_effect=[[main], [main, dialog]]),
            patch.object(backend, "_record_window", return_value=owner),
            patch.object(backend, "foreground_window", return_value=dialog.hwnd),
        ):
            self.assertEqual(verified_new_dialog(Path(main.executable), main, dialog.hwnd), dialog)
        second_main = WindowRecord(**{**main.__dict__, "hwnd": 11})
        with patch.object(backend, "enum_csp_windows", return_value=[main, second_main, dialog]):
            with self.assertRaises(BridgeError):
                verified_new_dialog(Path(main.executable), main, dialog.hwnd)
        detached = WindowRecord(**{**dialog.__dict__, "owner": 999})
        with (
            patch.object(backend, "enum_csp_windows", side_effect=[[main], [main, detached]]),
            patch.object(backend, "_record_window", return_value=None),
            patch.object(backend, "_pid_for_window", return_value=999),
            patch.object(backend, "foreground_window", return_value=dialog.hwnd),
        ):
            with self.assertRaises(BridgeError):
                verified_new_dialog(Path(main.executable), main, detached.hwnd)
        moved = WindowRecord(**{**dialog.__dict__, "rect": (509, 303, 1010, 878)})
        with patch.object(backend, "enum_csp_windows", side_effect=[[main], [main, moved]]):
            with self.assertRaises(BridgeError):
                verified_new_dialog(Path(main.executable), main, moved.hwnd)
        bad_owners = [
            WindowRecord(**{**owner.__dict__, "pid": 999}),
            WindowRecord(**{**owner.__dict__, "visible": False}),
            WindowRecord(**{**owner.__dict__, "rect": (0, 0, 2, 1)}),
            WindowRecord(**{**owner.__dict__, "class_name": main.class_name}),
            WindowRecord(**{**owner.__dict__, "owner": 0}),
            WindowRecord(**{**owner.__dict__, "title": "Other"}),
            WindowRecord(**{**owner.__dict__, "executable": r"D:\Other.exe"}),
        ]
        for bad_owner in bad_owners:
            with self.subTest(bad_owner=bad_owner):
                with (
                    patch.object(backend, "enum_csp_windows", side_effect=[[main], [main, dialog]]),
                    patch.object(backend, "_record_window", return_value=bad_owner),
                ):
                    with self.assertRaises(BridgeError) as raised:
                        verified_new_dialog(Path(main.executable), main, dialog.hwnd)
                    self.assertEqual(raised.exception.code, "E_WINDOW_AMBIGUOUS")

    def test_new_dialog_capture_refuses_foreign_overlap(self) -> None:
        dialog = WindowRecord(**{
            **self.window.__dict__, "hwnd": 20, "rect": (509, 303, 1009, 878),
            "client_rect": (509, 303, 1009, 878), "dpi": 96,
        })
        with (
            patch.object(backend, "foreground_window", return_value=20),
            patch.object(backend, "_pid_for_window", return_value=dialog.pid),
            patch.object(backend.win32gui, "GetWindow", return_value=99),
            patch.object(backend.win32gui, "IsWindowVisible", return_value=True),
            patch.object(backend.win32gui, "IsIconic", return_value=False),
            patch.object(backend, "visible_window_rect", return_value=(600, 400, 700, 500)),
            patch.object(backend.win32gui, "GetClassName", return_value="ForeignPopup"),
        ):
            with self.assertRaises(BridgeError) as raised:
                assert_new_dialog_visible(dialog)
            self.assertEqual(raised.exception.code, "E_CAPABILITY_UNAVAILABLE")

    def test_expanded_new_dialog_requires_opt_in_and_overlap_inspection_sends_no_input(self) -> None:
        main = WindowRecord(**{
            **self.window.__dict__, "hwnd": 10, "class_name": "CspMain",
            "rect": (0, 0, 2560, 1392), "dpi": 96,
        })
        dialog = WindowRecord(**{
            **main.__dict__, "hwnd": 20, "title": "New", "owner": 30,
            "class_name": main.class_name + backend.NEW_DIALOG_CLASS_SUFFIX,
            "rect": (509, 303, 1418, 1136), "client_rect": (509, 303, 1418, 1136),
        })
        owner = WindowRecord(**{
            **main.__dict__, "hwnd": 30, "title": "", "owner": main.hwnd,
            "class_name": main.class_name + backend.NEW_DIALOG_OWNER_CLASS_SUFFIX,
            "rect": (0, 0, 1, 1),
        })
        foreign = WindowRecord(**{
            **main.__dict__, "hwnd": 952, "pid": 999, "title": "Overlay",
            "class_name": "ForeignPopup", "rect": (600, 400, 700, 500),
            "executable": r"D:\Other.exe",
        })
        with patch.object(backend, "enum_csp_windows", side_effect=[[main], [main, dialog]]):
            with self.assertRaises(BridgeError):
                verified_new_dialog(Path(main.executable), main, dialog.hwnd)
        with (
            patch.object(backend, "enum_csp_windows", side_effect=[[main], [main, dialog]]),
            patch.object(backend, "_record_window", side_effect=lambda hwnd: owner if hwnd == 30 else foreign),
            patch.object(backend, "foreground_window", return_value=main.hwnd),
            patch.object(backend.win32gui, "GetWindow", side_effect=lambda hwnd, _: 952 if hwnd == dialog.hwnd else 0),
            patch.object(backend.win32gui, "IsWindowVisible", return_value=True),
            patch.object(backend.win32gui, "IsIconic", return_value=False),
            patch.object(backend, "visible_window_rect", return_value=foreign.rect),
            patch.object(backend, "_send") as send,
        ):
            result = inspect_expanded_new_dialog_overlaps(Path(main.executable), main, dialog.hwnd)
        self.assertEqual(result["overlaps"][0]["hwnd"], foreign.hwnd)
        self.assertFalse(result["overlaps"][0]["executableMatchesPinned"])
        self.assertFalse(result["authorizesInput"])
        send.assert_not_called()

    def test_expanded_new_dialog_escape_rejects_foreign_focus(self) -> None:
        dialog = WindowRecord(**{
            **self.window.__dict__, "hwnd": 20, "rect": (509, 303, 1418, 1136),
        })
        with (
            patch.object(backend, "_record_window", return_value=dialog),
            patch.object(backend, "foreground_window", return_value=999),
            patch.object(backend, "_send") as send,
        ):
            with self.assertRaises(BridgeError) as raised:
                send_expanded_new_dialog_escape(dialog, 123)
            self.assertEqual(raised.exception.code, "E_USER_INTERRUPTED")
            send.assert_not_called()

    def test_expanded_new_dialog_work_icon_uses_only_fixed_profiled_point(self) -> None:
        dialog = WindowRecord(**{
            **self.window.__dict__, "hwnd": 20, "rect": (509, 303, 1418, 1136),
            "client_rect": (509, 303, 1418, 1136),
        })
        with (
            patch.object(backend, "assert_new_dialog_visible"),
            patch.object(backend, "window_at_point", return_value=20),
            patch.object(backend, "_pid_for_window", return_value=dialog.pid),
            patch.object(backend.win32gui, "GetAncestor", return_value=dialog.hwnd),
            patch.object(backend, "_assert_initial_input_authority"),
            patch.object(backend, "_send") as send,
        ):
            self.assertEqual(select_new_dialog_work_icon(dialog, 3, 123), (714, 361))
            send.assert_called_once()
        with patch.object(backend, "_send") as send:
            with self.assertRaises(BridgeError):
                select_new_dialog_work_icon(dialog, 7, 123)
            send.assert_not_called()

    def test_new_comic_confirmation_rejects_wrong_layout_before_input(self) -> None:
        dialog = WindowRecord(**{
            **self.window.__dict__, "hwnd": 20, "rect": (509, 303, 1009, 878),
        })
        with patch.object(backend, "_send") as send:
            with self.assertRaises(BridgeError):
                confirm_expanded_new_dialog(dialog, 123)
            send.assert_not_called()

    def test_multiple_pages_click_requires_exact_visible_comic_dialog(self) -> None:
        dialog = WindowRecord(**{
            **self.window.__dict__, "hwnd": 20, "rect": (509, 303, 1418, 1136),
            "client_rect": (509, 303, 1418, 1136),
        })
        with (
            patch.object(backend, "assert_new_dialog_visible"),
            patch.object(backend, "window_at_point", return_value=20),
            patch.object(backend, "_pid_for_window", return_value=dialog.pid),
            patch.object(backend.win32gui, "GetAncestor", return_value=dialog.hwnd),
            patch.object(backend, "_assert_initial_input_authority"),
            patch.object(backend, "_record_window", return_value=dialog),
            patch.object(backend, "foreground_window", return_value=dialog.hwnd),
            patch.object(backend, "_send") as send,
        ):
            self.assertEqual(enable_new_comic_multiple_pages(dialog, 123), (538, 910))
            send.assert_called_once()
        with (
            patch.object(backend, "assert_new_dialog_visible"),
            patch.object(backend, "window_at_point", return_value=999),
            patch.object(backend, "_pid_for_window", return_value=999),
            patch.object(backend, "_send") as send,
        ):
            with self.assertRaises(BridgeError):
                enable_new_comic_multiple_pages(dialog, 123)
            send.assert_not_called()

    def test_page_copy_warning_profile_and_fixed_choice(self) -> None:
        main = WindowRecord(**{
            **self.window.__dict__, "hwnd": 10, "class_name": "CspMain",
            "rect": (0, 0, 2560, 1392), "dpi": 96,
        })
        warning = WindowRecord(**{
            **main.__dict__, "hwnd": 20, "title": "CLIP STUDIO PAINT EX", "owner": 30,
            "class_name": main.class_name + backend.NEW_DIALOG_CLASS_SUFFIX,
            "rect": (1061, 427, 1499, 536), "client_rect": (1061, 427, 1499, 536),
        })
        owner = WindowRecord(**{
            **main.__dict__, "hwnd": 30, "title": "", "owner": main.hwnd,
            "class_name": main.class_name + backend.NEW_DIALOG_OWNER_CLASS_SUFFIX,
            "rect": (0, 0, 1, 1),
        })
        with (
            patch.object(backend, "enum_csp_windows", side_effect=[[main], [main, warning]]),
            patch.object(backend, "_record_window", return_value=owner),
            patch.object(backend, "foreground_window", return_value=warning.hwnd),
        ):
            self.assertEqual(verified_page_copy_warning(Path(main.executable), main, warning.hwnd), warning)
        wrong = WindowRecord(**{**warning.__dict__, "title": "Other"})
        with patch.object(backend, "enum_csp_windows", side_effect=[[main], [main, wrong]]):
            with self.assertRaises(BridgeError):
                verified_page_copy_warning(Path(main.executable), main, wrong.hwnd)
        resized = WindowRecord(**{**warning.__dict__, "rect": (1061, 427, 1500, 536)})
        with patch.object(backend, "enum_csp_windows", side_effect=[[main], [main, resized]]):
            with self.assertRaises(BridgeError):
                verified_page_copy_warning(Path(main.executable), main, resized.hwnd)
        foreign_owner = WindowRecord(**{**owner.__dict__, "pid": 999})
        with (
            patch.object(backend, "enum_csp_windows", side_effect=[[main], [main, warning]]),
            patch.object(backend, "_record_window", return_value=foreign_owner),
        ):
            with self.assertRaises(BridgeError):
                verified_page_copy_warning(Path(main.executable), main, warning.hwnd)
        with (
            patch.object(backend, "assert_new_dialog_visible"),
            patch.object(backend, "window_at_point", return_value=warning.hwnd),
            patch.object(backend, "_pid_for_window", return_value=warning.pid),
            patch.object(backend.win32gui, "GetAncestor", return_value=warning.hwnd),
            patch.object(backend, "_assert_initial_input_authority"),
            patch.object(backend, "_record_window", return_value=warning),
            patch.object(backend, "foreground_window", return_value=warning.hwnd),
            patch.object(backend, "_send") as send,
        ):
            self.assertEqual(choose_page_copy_warning(warning, "proceed_copy", 123), (1355, 512))
            send.assert_called_once()
        with patch.object(backend, "_send") as send:
            with self.assertRaises(BridgeError):
                choose_page_copy_warning(warning, "toggle_checkbox", 123)
            send.assert_not_called()

    def test_new_owner_diagnostic_refuses_arbitrary_window(self) -> None:
        main = WindowRecord(**{**self.window.__dict__, "class_name": "CspMain", "dpi": 96})
        unrelated = WindowRecord(**{
            **main.__dict__, "hwnd": 22, "title": "Other", "owner": 33,
            "rect": (200, 200, 700, 775),
        })
        with (
            patch.object(backend, "enum_csp_windows", side_effect=[[main], [main, unrelated]]),
            patch.object(backend, "foreground_window", return_value=unrelated.hwnd),
        ):
            with self.assertRaises(BridgeError):
                new_dialog_owner_diagnostic(Path(main.executable), main, unrelated.hwnd)

    def test_cst_story_folder_requires_exact_profile_and_fixed_ok(self) -> None:
        main = WindowRecord(**{
            **self.window.__dict__, "hwnd": 10, "class_name": "CspMain",
            "rect": (0, 0, 2560, 1392), "dpi": 96,
        })
        dialog = WindowRecord(**{
            **main.__dict__, "hwnd": 20, "title": "Create story folder", "owner": 7147922,
            "class_name": main.class_name + backend.NEW_DIALOG_CLASS_SUFFIX,
            "rect": (655, 420, 1375, 619), "client_rect": (655, 420, 1375, 619),
        })
        owner = WindowRecord(**{
            **main.__dict__, "hwnd": 7147922, "title": "", "owner": main.hwnd,
            "class_name": main.class_name + backend.NEW_DIALOG_OWNER_CLASS_SUFFIX,
            "rect": (0, 0, 1, 1),
        })
        with (
            patch.object(backend, "enum_csp_windows", side_effect=[[main], [main, dialog]]),
            patch.object(backend, "_record_window", return_value=owner),
            patch.object(backend, "foreground_window", return_value=dialog.hwnd),
        ):
            self.assertEqual(verified_cst_story_folder_dialog(Path(main.executable), main, dialog.hwnd), dialog)
        for changed in (
            WindowRecord(**{**dialog.__dict__, "owner": 999}),
            WindowRecord(**{**dialog.__dict__, "rect": (655, 420, 1376, 619)}),
            WindowRecord(**{**dialog.__dict__, "title": "Other"}),
        ):
            with (
                patch.object(backend, "enum_csp_windows", side_effect=[[main], [main, changed]]),
                patch.object(backend, "_record_window", return_value=owner),
            ):
                with self.assertRaises(BridgeError):
                    verified_cst_story_folder_dialog(Path(main.executable), main, changed.hwnd)
        with (
            patch.object(backend, "assert_new_dialog_visible"),
            patch.object(backend, "window_at_point", return_value=dialog.hwnd),
            patch.object(backend, "_pid_for_window", return_value=dialog.pid),
            patch.object(backend.win32gui, "GetAncestor", return_value=dialog.hwnd),
            patch.object(backend, "_assert_initial_input_authority"),
            patch.object(backend, "_record_window", return_value=dialog),
            patch.object(backend, "foreground_window", return_value=dialog.hwnd),
            patch.object(backend, "_send") as send,
        ):
            self.assertEqual(confirm_cst_story_folder_dialog(dialog, 123), (1320, 466))
            send.assert_called_once()

    def test_cst_error_escape_requires_exact_foreground_modal(self) -> None:
        main = WindowRecord(**{
            **self.window.__dict__, "hwnd": 10, "class_name": "CspMain",
            "rect": (0, 0, 2560, 1392), "dpi": 96,
        })
        error = WindowRecord(**{
            **main.__dict__, "hwnd": 20, "title": "CLIP STUDIO PAINT EX", "owner": 7147922,
            "class_name": main.class_name + backend.NEW_DIALOG_CLASS_SUFFIX,
            "rect": (1164, 427, 1395, 536), "client_rect": (1164, 427, 1395, 536),
        })
        owner = WindowRecord(**{
            **main.__dict__, "hwnd": 7147922, "title": "", "owner": main.hwnd,
            "class_name": main.class_name + backend.NEW_DIALOG_OWNER_CLASS_SUFFIX,
            "rect": (0, 0, 1, 1),
        })
        with (
            patch.object(backend, "enum_csp_windows", side_effect=[[main], [main, error]]),
            patch.object(backend, "_record_window", return_value=owner),
            patch.object(backend, "foreground_window", return_value=error.hwnd),
        ):
            self.assertEqual(verified_cst_conversion_error(Path(main.executable), main, error.hwnd), error)
        wrong = WindowRecord(**{**error.__dict__, "rect": (1164, 427, 1396, 536)})
        with patch.object(backend, "enum_csp_windows", side_effect=[[main], [main, wrong]]):
            with self.assertRaises(BridgeError):
                verified_cst_conversion_error(Path(main.executable), main, wrong.hwnd)
        with (
            patch.object(backend, "_record_window", return_value=error),
            patch.object(backend, "foreground_window", return_value=999),
            patch.object(backend, "_send") as send,
        ):
            with self.assertRaises(BridgeError):
                send_cst_conversion_error_escape(error, 123)
            send.assert_not_called()

    def test_cst_conversion_accepts_only_exact_warning_and_ok_point(self) -> None:
        main = WindowRecord(**{
            **self.window.__dict__, "hwnd": 10, "class_name": "CspMain",
            "rect": (0, 0, 2560, 1392), "dpi": 96,
        })
        warning = WindowRecord(**{
            **main.__dict__, "hwnd": 20, "title": "CLIP STUDIO PAINT EX", "owner": 7147922,
            "class_name": main.class_name + backend.NEW_DIALOG_CLASS_SUFFIX,
            "rect": (1130, 425, 1430, 541), "client_rect": (1130, 425, 1430, 541),
        })
        owner = WindowRecord(**{
            **main.__dict__, "hwnd": 7147922, "title": "", "owner": main.hwnd,
            "class_name": main.class_name + backend.NEW_DIALOG_OWNER_CLASS_SUFFIX,
            "rect": (0, 0, 1, 1),
        })
        with (
            patch.object(backend, "enum_csp_windows", side_effect=[[main], [main, warning]]),
            patch.object(backend, "_record_window", return_value=owner),
            patch.object(backend, "foreground_window", return_value=warning.hwnd),
        ):
            self.assertEqual(verified_cst_conversion_warning(Path(main.executable), main, warning.hwnd), warning)
        for changed in (
            WindowRecord(**{**warning.__dict__, "owner": 999}),
            WindowRecord(**{**warning.__dict__, "rect": (1130, 425, 1431, 541)}),
            WindowRecord(**{**warning.__dict__, "title": "Other"}),
        ):
            with (
                patch.object(backend, "enum_csp_windows", side_effect=[[main], [main, changed]]),
                patch.object(backend, "_record_window", return_value=owner),
            ):
                with self.assertRaises(BridgeError):
                    verified_cst_conversion_warning(Path(main.executable), main, changed.hwnd)
        with (
            patch.object(backend, "assert_new_dialog_visible"),
            patch.object(backend, "window_at_point", return_value=warning.hwnd),
            patch.object(backend, "_pid_for_window", return_value=warning.pid),
            patch.object(backend.win32gui, "GetAncestor", return_value=warning.hwnd),
            patch.object(backend, "_assert_initial_input_authority"),
            patch.object(backend, "_record_window", return_value=warning),
            patch.object(backend, "foreground_window", return_value=warning.hwnd),
            patch.object(backend, "_send") as send,
        ):
            self.assertEqual(accept_cst_conversion_warning(warning, 123), (1286, 518))
            send.assert_called_once()

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
