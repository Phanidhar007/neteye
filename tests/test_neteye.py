import unittest
from unittest.mock import MagicMock, patch

from neteye.banner import guess_os_by_ttl
from neteye.discovery import _oui_lookup, is_private
from neteye.scan import SERVICES, _result


class TestDiscovery(unittest.TestCase):
    def test_oui_lookup(self):
        self.assertEqual(_oui_lookup("08:00:27:ab:cd:ef"), "VirtualBox")
        self.assertEqual(_oui_lookup("02:42:ac:11:00:02"), "Docker")
        self.assertEqual(_oui_lookup("aa:bb:cc:dd:ee:ff"), "unknown")

    def test_is_private(self):
        self.assertTrue(is_private("192.168.1.1"))
        self.assertTrue(is_private("10.0.0.5"))
        self.assertFalse(is_private("8.8.8.8"))

    @patch("neteye.discovery.get_scapy")
    def test_arp_sweep_parses_replies(self, mock_get):
        sent = MagicMock()
        recv = MagicMock()
        recv.psrc = "192.168.1.10"
        recv.hwsrc = "08:00:27:12:34:56"
        conf = MagicMock()
        s = {
            "Ether": MagicMock(), "ARP": MagicMock(), "conf": conf, "srp": MagicMock(
                return_value=([(sent, recv)], [])),
        }
        mock_get.return_value = s
        from neteye.discovery import arp_sweep
        results = arp_sweep("192.168.1.0/24", timeout=1)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["ip"], "192.168.1.10")
        self.assertEqual(results[0]["vendor"], "VirtualBox")


class TestOSGuess(unittest.TestCase):
    def test_ttl_guesses(self):
        self.assertIn("Linux", guess_os_by_ttl(64))
        self.assertIn("Windows", guess_os_by_ttl(128))
        self.assertEqual(guess_os_by_ttl(None), "unknown")


class TestServices(unittest.TestCase):
    def test_result(self):
        self.assertEqual(_result(443), {"port": 443, "service": "https"})
        self.assertEqual(SERVICES[22], "ssh")


if __name__ == "__main__":
    unittest.main()
