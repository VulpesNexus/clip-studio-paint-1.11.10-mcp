from __future__ import annotations

import json
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from csp_mcp.controller import CaptureEntry, CspController
from csp_mcp.errors import BridgeError
from csp_mcp.win32_backend import CaptureData, WindowRecord


class ControllerStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.controller = CspController()
        self.working = self.controller.settings.root("working").path
        self.working.mkdir(parents=True, exist_ok=True)

    def _temporary_output(self, payload: bytes = b"one") -> Path:
        handle = tempfile.NamedTemporaryFile(dir=self.working, suffix=".png", delete=False)
        try:
            handle.write(payload)
            return Path(handle.name)
        finally:
            handle.close()

    def _main_window(self) -> WindowRecord:
        return WindowRecord(
            hwnd=1,
            pid=2,
            title="CSP",
            class_name="main",
            rect=(0, 0, 800, 600),
            client_rect=(0, 0, 800, 600),
            visible=True,
            minimized=False,
            maximized=False,
            owner=0,
            dpi=120,
            executable=str(self.controller.settings.csp_executable),
            show_cmd=1,
            normal_rect=(0, 0, 800, 600),
        )

    def _capture_fixture(
        self,
        main: WindowRecord,
        *,
        capture_id: str | None = None,
        created_monotonic: float | None = None,
        last_input_tick: int = 123,
    ) -> CaptureEntry:
        return CaptureEntry(
            capture_id=capture_id or str(uuid.uuid4()),
            created_monotonic=created_monotonic if created_monotonic is not None else time.monotonic(),
            created_at="2026-08-25T00:00:00+00:00",
            hwnd=main.hwnd,
            pid=main.pid,
            foreground_hwnd=main.hwnd,
            last_input_tick=last_input_tick,
            control_generation=self.controller._control_generation.current(),
            window_fingerprint=main.fingerprint,
            region=None,
            capture_max_width=320,
            data=CaptureData(
                png=b"fixture",
                width=1,
                height=1,
                source_width=1,
                source_height=1,
                rect=main.rect,
                sha256="fixture",
                luminance_stddev=0.0,
            ),
        )

    def _output_replace_preflight(self, target: Path):
        main = WindowRecord(
            hwnd=1,
            pid=2,
            title="CSP",
            class_name="main",
            rect=(0, 0, 800, 600),
            client_rect=(0, 0, 800, 600),
            visible=True,
            minimized=False,
            maximized=False,
            owner=0,
            dpi=120,
            executable=str(self.controller.settings.csp_executable),
            show_cmd=1,
            normal_rect=(0, 0, 800, 600),
        )
        dialog = WindowRecord(
            **{
                **main.__dict__,
                "hwnd": 3,
                "title": "另存为",
                "class_name": "#32770",
                "owner": main.hwnd,
            }
        )
        with (
            patch.object(self.controller, "_wait_for_quiet", return_value={}),
            patch.object(self.controller, "_target", return_value=main),
            patch("csp_mcp.controller.win.list_process_dialogs", return_value=[dialog]),
            patch("csp_mcp.controller.win.validate_native_file_dialog", return_value={"mode": "output"}),
            patch("csp_mcp.controller.win.get_last_input", return_value=(123, 9999)),
            patch("csp_mcp.controller.win.pressed_input_keys", return_value=[]),
            patch("csp_mcp.controller.win.focus_window", return_value=dialog),
            patch("csp_mcp.controller.win.foreground_window", return_value=dialog.hwnd),
        ):
            result = self.controller.preflight(
                "output_replace",
                "",
                path=str(target),
                main_hwnd=main.hwnd,
                dialog_hwnd=dialog.hwnd,
            )
        return result, main, dialog

    def _consume_output_confirmation(self, token: str, target: Path, main: WindowRecord, dialog: WindowRecord):
        entry = self.controller._confirmations[token]
        return self.controller._consume_confirmation(
            token,
            operation="input",
            identifier="csp_native_file_dialog",
            capture_id="",
            path=str(target.resolve()),
            main_hwnd=main.hwnd,
            dialog_hwnd=dialog.hwnd,
            main_fingerprint=main.fingerprint,
            dialog_fingerprint=dialog.fingerprint,
            parameters_json=entry.parameters_json,
        )

    def test_output_replace_confirmation_is_single_use(self) -> None:
        target = self._temporary_output()
        try:
            preflight, main, dialog = self._output_replace_preflight(target)
            token = preflight["result"]["confirmToken"]
            input_tick = self.controller._confirmations[token].last_input_tick
            with patch("csp_mcp.controller.win.get_last_input", return_value=(input_tick, 9999)):
                self._consume_output_confirmation(token, target, main, dialog)
            with self.assertRaises(BridgeError):
                self._consume_output_confirmation(token, target, main, dialog)
        finally:
            target.unlink(missing_ok=True)

    def test_output_replace_confirmation_detects_file_change(self) -> None:
        target = self._temporary_output()
        try:
            preflight, main, dialog = self._output_replace_preflight(target)
            token = preflight["result"]["confirmToken"]
            input_tick = self.controller._confirmations[token].last_input_tick
            target.write_bytes(b"two")
            with patch("csp_mcp.controller.win.get_last_input", return_value=(input_tick, 9999)):
                with self.assertRaises(BridgeError) as raised:
                    self._consume_output_confirmation(token, target, main, dialog)
            self.assertEqual(raised.exception.code, "E_FILE_CHANGED")
        finally:
            target.unlink(missing_ok=True)

    def test_output_replace_confirmation_binds_generation_and_dialog_identity(self) -> None:
        target = self._temporary_output()
        try:
            preflight, main, dialog = self._output_replace_preflight(target)
            token = preflight["result"]["confirmToken"]
            self.controller._control_generation.advance()
            with self.assertRaises(BridgeError) as raised:
                self._consume_output_confirmation(token, target, main, dialog)
            self.assertEqual(raised.exception.code, "E_CONFIRM_EXPIRED")
        finally:
            target.unlink(missing_ok=True)

    def test_wait_for_file_revalidates_the_final_output_before_and_after_hashing(self) -> None:
        target = self._temporary_output(b"stable-output")
        original_validate = self.controller.path_policy.validate
        try:
            with patch.object(
                self.controller.path_policy,
                "validate",
                wraps=original_validate,
            ) as validate:
                result = self.controller.wait_for_file(str(target), timeout_ms=1000, stable_ms=100)

            self.assertEqual(result["result"]["path"], str(target))
            replace_calls = [call for call in validate.call_args_list if call.args[1] == "output_replace"]
            self.assertGreaterEqual(len(replace_calls), 3)
            self.assertIn("prePostPathPolicy", result["verification"]["method"])
        finally:
            target.unlink(missing_ok=True)

    def test_control_state_change_keeps_capture_for_comparison_but_revokes_authority(self) -> None:
        generation = self.controller._control_generation.current()
        entry = CaptureEntry(
            capture_id=str(uuid.uuid4()),
            created_monotonic=time.monotonic(),
            created_at="2026-08-25T00:00:00+00:00",
            hwnd=1,
            pid=2,
            foreground_hwnd=1,
            last_input_tick=0,
            control_generation=generation,
            window_fingerprint="fixture",
            region=None,
            capture_max_width=320,
            data=CaptureData(
                png=b"fixture",
                width=1,
                height=1,
                source_width=1,
                source_height=1,
                rect=(0, 0, 1, 1),
                sha256="fixture",
                luminance_stddev=0.0,
            ),
        )
        self.controller._store_capture(entry)
        self.controller._record_control_state_change()
        self.assertIs(self.controller._capture_entry(entry.capture_id), entry)
        self.assertFalse(entry.authorizable)
        self.assertNotEqual(entry.control_generation, self.controller._control_generation.current())

    def test_abandoned_cross_process_lock_requires_recovery_and_invalidates_captures(self) -> None:
        class AbandonedLease:
            abandoned = True

            def __init__(self) -> None:
                self.released = False

            def release(self) -> None:
                self.released = True

        lease = AbandonedLease()
        baseline = self.controller._control_generation.current()
        with (
            patch("csp_mcp.controller.win.acquire_control_mutex", return_value=lease),
            patch("csp_mcp.controller.win.release_all_inputs") as release_inputs,
        ):
            with self.assertRaises(BridgeError) as raised:
                self.controller._locked()
        self.assertEqual(raised.exception.code, "E_RECOVERY_REQUIRED")
        self.assertEqual(raised.exception.state_change, "possible")
        self.assertTrue(lease.released)
        release_inputs.assert_not_called()
        self.assertFalse(self.controller._control_lock.locked())
        self.assertNotEqual(self.controller._control_generation.current(), baseline)

    def test_post_capture_human_input_revokes_capture_authority(self) -> None:
        main = self._main_window()
        capture = self._capture_fixture(main, last_input_tick=123)
        self.controller._store_capture(capture)

        with patch("csp_mcp.controller.win.get_last_input", return_value=(124, 9999)):
            with self.assertRaises(BridgeError) as raised:
                self.controller._assert_capture_matches(capture.capture_id, main)

        self.assertEqual(raised.exception.code, "E_USER_INTERRUPTED")
        self.assertFalse(capture.authorizable)

    def test_standard_dialog_revokes_capture_authority_and_blocks_generic_input(self) -> None:
        main = self._main_window()
        dialog = WindowRecord(
            **{
                **main.__dict__,
                "hwnd": 3,
                "title": "打开",
                "class_name": "#32770",
                "owner": main.hwnd,
            }
        )
        data = CaptureData(
            png=b"fixture",
            width=1,
            height=1,
            source_width=800,
            source_height=600,
            rect=main.rect,
            sha256="fixture",
            luminance_stddev=0.0,
        )
        with (
            patch("csp_mcp.controller.win.get_last_input", return_value=(123, 9999)),
            patch("csp_mcp.controller.win.foreground_window", return_value=main.hwnd),
            patch("csp_mcp.controller.win.capture_window", return_value=data),
            patch("csp_mcp.controller.win.capture_rect_covers_visible_main_chain", return_value=True),
            patch.object(self.controller, "_visible_standard_dialogs", return_value=[dialog]),
        ):
            capture = self.controller._capture_record(main, store=False)

        self.assertFalse(capture.authorizable)
        self.assertEqual(capture.authorization_denial_reason, "standardDialogRequiresDedicatedTool")

        with (
            patch.object(self.controller, "_wait_for_quiet", return_value={}),
            patch.object(self.controller, "_target", return_value=main),
            patch.object(self.controller, "_visible_standard_dialogs", return_value=[dialog]),
        ):
            with self.assertRaises(BridgeError) as raised:
                self.controller._prepare_input(
                    main.hwnd,
                    capture.capture_id,
                    require_capture=True,
                )

        self.assertEqual(raised.exception.code, "E_DEDICATED_DIALOG_TOOL_REQUIRED")

    def test_command_preflight_token_requires_a_capture_created_after_preflight(self) -> None:
        main = self._main_window()
        with patch("csp_mcp.controller.win.get_last_input", return_value=(123, 9999)):
            with self.assertRaises(BridgeError) as raised:
                self.controller._preflight_locked(
                    "command",
                    "document.close",
                    capture_id="capture-created-too-early",
                )
        self.assertEqual(raised.exception.code, "E_POLICY_DENIED")

        with (
            patch("csp_mcp.controller.win.get_last_input", return_value=(123, 9999)),
            patch("csp_mcp.controller.win.pressed_input_keys", return_value=[]),
            patch("csp_mcp.controller.win.focus_window", return_value=main),
            patch("csp_mcp.controller.win.foreground_window", return_value=main.hwnd),
            patch.object(self.controller, "_target", return_value=main),
            patch.object(self.controller, "_visible_standard_dialogs", return_value=[]),
            patch.object(self.controller, "_assert_shortcut_profile", return_value={"supported": True}),
        ):
            preflight = self.controller._preflight_locked("command", "document.close")

        self.assertTrue(preflight["result"]["captureRequiredAfterPreflight"])
        token = preflight["result"]["confirmToken"]
        confirmation = self.controller._confirmations[token]
        old_capture = self._capture_fixture(
            main,
            created_monotonic=confirmation.created_monotonic - 0.001,
        )
        new_capture = self._capture_fixture(
            main,
            created_monotonic=confirmation.created_monotonic + 0.001,
        )
        self.controller._store_capture(old_capture)
        self.controller._store_capture(new_capture)

        with patch("csp_mcp.controller.win.get_last_input", return_value=(123, 9999)):
            with self.assertRaises(BridgeError) as raised:
                self.controller._consume_confirmation(
                    token,
                    operation="input",
                    identifier="csp_run_command",
                    capture_id=old_capture.capture_id,
                    main_hwnd=main.hwnd,
                    main_fingerprint=main.fingerprint,
                    parameters_json=confirmation.parameters_json,
                )

        self.assertEqual(raised.exception.code, "E_CONFIRM_REQUIRED")
        self.assertTrue(confirmation.used)
        with patch("csp_mcp.controller.win.get_last_input", return_value=(123, 9999)):
            with self.assertRaises(BridgeError) as reused:
                self.controller._consume_confirmation(
                    token,
                    operation="input",
                    identifier="csp_run_command",
                    capture_id=new_capture.capture_id,
                    main_hwnd=main.hwnd,
                    main_fingerprint=main.fingerprint,
                    parameters_json=confirmation.parameters_json,
                )
        self.assertEqual(reused.exception.code, "E_CONFIRM_EXPIRED")

        with (
            patch("csp_mcp.controller.win.get_last_input", return_value=(123, 9999)),
            patch("csp_mcp.controller.win.pressed_input_keys", return_value=[]),
            patch("csp_mcp.controller.win.focus_window", return_value=main),
            patch("csp_mcp.controller.win.foreground_window", return_value=main.hwnd),
            patch.object(self.controller, "_target", return_value=main),
            patch.object(self.controller, "_visible_standard_dialogs", return_value=[]),
            patch.object(self.controller, "_assert_shortcut_profile", return_value={"supported": True}),
        ):
            second = self.controller._preflight_locked("command", "document.close")
        second_token = second["result"]["confirmToken"]
        second_confirmation = self.controller._confirmations[second_token]
        authorized_capture = self._capture_fixture(
            main,
            created_monotonic=second_confirmation.created_monotonic + 0.001,
        )
        self.controller._store_capture(authorized_capture)
        with patch("csp_mcp.controller.win.get_last_input", return_value=(123, 9999)):
            consumed = self.controller._consume_confirmation(
                second_token,
                operation="input",
                identifier="csp_run_command",
                capture_id=authorized_capture.capture_id,
                main_hwnd=main.hwnd,
                main_fingerprint=main.fingerprint,
                parameters_json=second_confirmation.parameters_json,
            )
        self.assertTrue(consumed.used)

    def test_generic_input_preflight_binds_exact_parameters_and_input_tick(self) -> None:
        main = self._main_window()
        payload = {"x": 0.25, "y": 0.75, "region": "client", "button": "left", "count": 1}
        with (
            patch("csp_mcp.controller.win.get_last_input", return_value=(123, 9999)),
            patch("csp_mcp.controller.win.pressed_input_keys", return_value=[]),
            patch("csp_mcp.controller.win.focus_window", return_value=main),
            patch("csp_mcp.controller.win.foreground_window", return_value=main.hwnd),
            patch.object(self.controller, "_target", return_value=main),
            patch.object(self.controller, "_visible_standard_dialogs", return_value=[]),
        ):
            result = self.controller._preflight_locked(
                "input",
                "csp_click",
                json.dumps(payload),
            )

        token = result["result"]["confirmToken"]
        self.assertEqual(result["stateChange"], "confirmed")
        self.assertIsNotNone(result["stateRevisionBefore"])
        self.assertIsNotNone(result["stateRevisionAfter"])
        confirmation = self.controller._confirmations[token]
        capture = self._capture_fixture(
            main,
            created_monotonic=confirmation.created_monotonic + 0.001,
            last_input_tick=123,
        )
        self.controller._store_capture(capture)
        with patch("csp_mcp.controller.win.get_last_input", return_value=(123, 9999)):
            consumed = self.controller._consume_confirmation(
                token,
                operation="input",
                identifier="csp_click",
                capture_id=capture.capture_id,
                main_hwnd=main.hwnd,
                main_fingerprint=main.fingerprint,
                parameters_json=confirmation.parameters_json,
            )
        self.assertTrue(consumed.used)

    def test_isolated_unicode_surrogate_is_rejected_before_control_state_changes(self) -> None:
        baseline = self.controller._control_generation.current()
        with self.assertRaises(BridgeError) as raised:
            self.controller.type_text("\ud800", "unused-capture", "unused-token")
        self.assertEqual(raised.exception.code, "E_POLICY_DENIED")
        self.assertEqual(raised.exception.state_change, "none")
        self.assertEqual(self.controller._control_generation.current(), baseline)

    def test_preflight_focus_failure_invalidates_old_authority_and_reports_possible_change(self) -> None:
        main = self._main_window()
        old_capture = self._capture_fixture(main)
        self.controller._store_capture(old_capture)
        baseline = self.controller._control_generation.current()
        payload = json.dumps({"x": 0.5, "y": 0.5, "region": "client"})
        with (
            patch.object(self.controller, "_wait_for_quiet", return_value={}),
            patch.object(self.controller, "_target", return_value=main),
            patch.object(self.controller, "_visible_standard_dialogs", return_value=[]),
            patch("csp_mcp.controller.win.get_last_input", return_value=(123, 9999)),
            patch("csp_mcp.controller.win.focus_window", side_effect=BridgeError("E_UI_TIMEOUT", "focus failed", retryable=True)),
        ):
            with self.assertRaises(BridgeError) as raised:
                self.controller.preflight("input", "csp_move_pointer", payload)
        self.assertEqual(raised.exception.code, "E_UI_TIMEOUT")
        self.assertEqual(raised.exception.state_change, "possible")
        self.assertNotEqual(self.controller._control_generation.current(), baseline)
        self.assertFalse(old_capture.authorizable)


if __name__ == "__main__":
    unittest.main()
