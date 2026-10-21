"""Tests for safe platform handling in the Windows event scanner."""
import unittest
from datetime import datetime, timezone
from unittest.mock import patch
import windows_event_scanner as scanner

class ScannerTests(unittest.TestCase):
    def test_refuses_non_windows_platform(self):
        with patch.object(scanner.platform, "system", return_value="Linux"):
            with self.assertRaisesRegex(scanner.WindowsEventScanError, "only when LogScout-SH runs on Windows"):
                scanner.scan_security_events(datetime.now(timezone.utc))

if __name__ == "__main__":
    unittest.main()
