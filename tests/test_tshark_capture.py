"""Offline tests for TShark discovery and packet metadata parsing."""
import unittest
from unittest.mock import patch, Mock

import tshark_capture as capture


class TSharkCaptureTests(unittest.TestCase):
    def test_parse_ipv4_tcp_row(self):
        row = '"7","1792600000.125","74","eth:ethertype:ip:tcp","192.0.2.1","","198.51.100.8","","44321","443","","",""'
        parsed = capture.parse_packet_line(row)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["frame_number"], 7)
        self.assertEqual(parsed["source"], "192.0.2.1")
        self.assertEqual(parsed["destination"], "198.51.100.8")
        self.assertEqual(parsed["destination_port"], "443")
        self.assertEqual(parsed["length_bytes"], 74)
        self.assertIn("+00:00", parsed["timestamp"])

    def test_parse_ipv6_and_dns_row(self):
        row = '"8","1792600001.000","90","eth:ethertype:ipv6:udp:dns","","2001:db8::1","","2001:db8::2","","","5353","53","example.org"'
        parsed = capture.parse_packet_line(row)
        self.assertEqual(parsed["source"], "2001:db8::1")
        self.assertEqual(parsed["destination"], "2001:db8::2")
        self.assertEqual(parsed["dns_query"], "example.org")
        self.assertEqual(parsed["source_port"], "5353")

    def test_malformed_row_is_ignored(self):
        self.assertIsNone(capture.parse_packet_line('"1","not-a-time","abc"'))

    def test_missing_tshark_has_helpful_error(self):
        with patch.object(capture.shutil, "which", return_value=None), patch.object(capture.os.path, "isfile", return_value=False):
            with self.assertRaisesRegex(capture.TSharkError, "Install Wireshark with the TShark component"):
                capture.resolve_tshark("missing-tshark-binary")

    def test_interface_listing_parses_windows_adapters(self):
        mocked = Mock(stdout='1. \\Device\\NPF_{ABC} (Ethernet)\n2. \\Device\\NPF_{DEF} (Wi-Fi)\n', stderr='', returncode=0)
        with patch.object(capture, "resolve_tshark", return_value="tshark.exe"), patch.object(capture, "_run_checked", return_value=mocked):
            interfaces = capture.list_interfaces()
        self.assertEqual(len(interfaces), 2)
        self.assertEqual(interfaces[0]["id"], "1")
        self.assertEqual(interfaces[1]["label"], r"\Device\NPF_{DEF} (Wi-Fi)")

    def test_no_interfaces_is_clear_error(self):
        mocked = Mock(stdout="", stderr="", returncode=0)
        with patch.object(capture, "resolve_tshark", return_value="tshark.exe"), patch.object(capture, "_run_checked", return_value=mocked):
            with self.assertRaisesRegex(capture.TSharkError, "no capture interfaces were listed"):
                capture.list_interfaces()


if __name__ == "__main__":
    unittest.main()
