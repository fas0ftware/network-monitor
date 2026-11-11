import unittest
from unittest import mock

import main
from tests.helpers import TempDatabaseTestCase

IP_RANGE = "192.168.1.0/24"
DEVICE = {"ip": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:01", "vendor": "V"}


class RunRoundTests(TempDatabaseTestCase):
    """run_round with the network and notifications replaced by fakes."""

    def setUp(self):
        super().setUp()
        self.devices = [DEVICE]
        self.ports = []
        self.alerts = []
        self.port_scans = []

        def fake_scan_ports(ip):
            self.port_scans.append(ip)
            return self.ports

        for name, value in {
            "scan": lambda ip_range: self.devices,
            "scan_ports": fake_scan_ports,
            "send_notification": lambda title, message: self.alerts.append((title, message)),
            "last_port_scan": {},
        }.items():
            patcher = mock.patch.object(main, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_silent_first_round_does_not_alert(self):
        main.run_round(IP_RANGE, silent=True)
        self.assertEqual(self.alerts, [])

    def test_new_device_triggers_alert(self):
        main.run_round(IP_RANGE, silent=False)
        self.assertEqual(len(self.alerts), 1)
        self.assertIn("New device", self.alerts[0][0])

    def test_known_device_does_not_alert_again(self):
        main.run_round(IP_RANGE, silent=False)
        main.run_round(IP_RANGE, silent=False)
        self.assertEqual(len(self.alerts), 1)

    def test_new_port_alert_only_after_baseline(self):
        self.ports = [(22, "ssh")]
        main.run_round(IP_RANGE, silent=True)  # baseline scan
        self.assertEqual(self.alerts, [])

        self.ports = [(22, "ssh"), (23, "telnet")]
        with mock.patch.object(main, "PORT_RESCAN_INTERVAL", 0):  # rescan right away
            main.run_round(IP_RANGE, silent=False)

        self.assertEqual(len(self.alerts), 1)
        self.assertIn("23/telnet", self.alerts[0][1])
        self.assertIn("risky", self.alerts[0][1])

    def test_ports_not_rescanned_before_interval(self):
        main.run_round(IP_RANGE, silent=True)
        main.run_round(IP_RANGE, silent=True)
        self.assertEqual(len(self.port_scans), 1)


if __name__ == "__main__":
    unittest.main()
