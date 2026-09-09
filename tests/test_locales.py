from dataclasses import replace
import unittest
from unittest.mock import patch

from csp_mcp import win32_backend as backend
from csp_mcp.config import load_settings
from csp_mcp.controller import CspController
from csp_mcp.errors import BridgeError


class LocaleTests(unittest.TestCase):
    def test_any_culture_and_legacy_pin(self):
        settings = replace(load_settings(), expected_locale="*")
        for culture in ("fr-FR", "en-GB", "ja-JP", "zh-CN", "ar-SA"):
            self.assertTrue(settings.locale_matches(culture))
        pinned = replace(settings, expected_locale="fr-FR")
        self.assertTrue(pinned.locale_matches("FR-fr"))
        self.assertFalse(pinned.locale_matches("zh-CN"))

    def test_input_accepts_french_but_keeps_dpi_and_binary_checks(self):
        from types import SimpleNamespace
        controller = CspController()
        controller.settings = replace(controller.settings, expected_locale="*")
        window = SimpleNamespace(dpi=controller.settings.expected_dpi)
        with (
            patch.object(controller, "_assert_binary") as binary,
            patch("csp_mcp.controller.win.choose_csp_window", return_value=window),
            patch("csp_mcp.controller.win.current_locale_name", return_value="fr-FR"),
        ):
            self.assertIs(controller._target(for_input=True), window)
            binary.assert_called_once()
            window.dpi += 24
            with self.assertRaises(BridgeError) as error:
                controller._target(for_input=True)
            self.assertEqual(error.exception.code, "E_DPI_PROFILE_MISMATCH")
            window.dpi = controller.settings.expected_dpi
            controller.settings = replace(controller.settings, expected_locale="zh-CN")
            with self.assertRaises(BridgeError) as error:
                controller._target(for_input=True)
            self.assertEqual(error.exception.code, "E_LOCALE_UNSUPPORTED")

    def test_localized_dialog_labels(self):
        for title, button, mode in (
            ("Ouvrir", "&Ouvrir", "input"),
            ("Enregistrer sous", "&Enregistrer", "output"),
            ("Exporter", "Exporter…", "output"),
            ("Open", "&Open", "input"),
            ("Save As", "&Save", "output"),
            ("打开", "打开(&O)", "input"),
            ("另存为", "保存(&S)", "output"),
            ("Enregistrer sous", "&Save", "output"),
        ):
            with self.subTest(title=title, button=button):
                self.assertEqual(backend._file_dialog_mode(title, button), mode)
        for title, button in (
            ("Open", "Save"), ("Enregistrer sous", "Ouvrir"),
            ("Do not save", "Save"), ("Save changes?", "Save"),
            ("Unknown", "OK"), ("???", "??"), ("Ouvrir", "OK"),
        ):
            with self.subTest(title=title, button=button):
                with self.assertRaises(BridgeError):
                    backend._file_dialog_mode(title, button)

    def test_french_native_dialog_structure_and_intent(self):
        children = [
            dict(className="SHELLDLL_DefView", controlId=1121, visible=True, enabled=True, hwnd=2, text=""),
            dict(className="Edit", controlId=1148, visible=True, enabled=True, hwnd=3, text=""),
            dict(className="Button", controlId=1, visible=True, enabled=True, hwnd=4, text="&Enregistrer"),
        ]
        with (
            patch.object(backend.win32gui, "IsWindow", return_value=True),
            patch.object(backend.win32gui, "GetClassName", return_value="#32770"),
            patch.object(backend.win32gui, "GetWindowText", return_value="Enregistrer sous"),
            patch.object(backend, "inspect_child_windows", return_value=children),
        ):
            self.assertEqual(backend.validate_native_file_dialog(1, "output_new")["mode"], "output")
            with self.assertRaises(BridgeError) as error:
                backend.validate_native_file_dialog(1, "input")
            self.assertEqual(error.exception.code, "E_POLICY_DENIED")
            children.append(dict(children[1], hwnd=5))
            with self.assertRaises(BridgeError):
                backend.validate_native_file_dialog(1, "output_new")
            children.pop()
            children[0]["visible"] = False
            with self.assertRaises(BridgeError):
                backend.validate_native_file_dialog(1, "output_new")
