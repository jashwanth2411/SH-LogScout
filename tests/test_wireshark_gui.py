"""Offline tests for the optional Wireshark desktop GUI launcher."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import wireshark_gui


class WiresharkGUITests(unittest.TestCase):
    def test_missing_gui_has_clear_error(self):
        with patch.object(wireshark_gui.shutil, "which", return_value=None), patch.dict(os.environ, {"ProgramFiles": "Z:/missing", "ProgramFiles(x86)": "Z:/missing"}):
            with self.assertRaisesRegex(wireshark_gui.WiresharkGUIError, "Wireshark desktop GUI was not found"):
                wireshark_gui.resolve_wireshark("missing-wireshark")

    def test_requires_selected_interface(self):
        with self.assertRaisesRegex(wireshark_gui.WiresharkGUIError, "Choose a capture interface"):
            wireshark_gui.launch_wireshark_gui("wireshark", "")

    def test_launch_uses_argument_list_without_shell(self):
        with tempfile.TemporaryDirectory() as td:
            exe = Path(td) / "Wireshark.exe"
            exe.write_text("placeholder", encoding="utf-8")
            with patch.object(wireshark_gui.subprocess, "Popen") as popen:
                result = wireshark_gui.launch_wireshark_gui(str(exe), r"\\Device\\NPF_{ABC}")
            self.assertEqual(result, str(exe.resolve()))
            args, kwargs = popen.call_args
            self.assertEqual(args[0], [str(exe.resolve()), "-i", r"\\Device\\NPF_{ABC}", "-k"])
            self.assertFalse(kwargs["shell"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
