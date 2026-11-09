import sqlite3
import unittest

import db
from tests.helpers import TempDatabaseTestCase

DEVICE = {"ip": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:ff", "vendor": "TestVendor"}


class DeviceTests(TempDatabaseTestCase):
    def test_new_device_is_reported_once(self):
        self.assertTrue(db.save_device(DEVICE))
        self.assertFalse(db.save_device(DEVICE))
        self.assertEqual(db.count_devices(), 1)

    def test_known_device_gets_new_ip(self):
        db.save_device(DEVICE)
        db.save_device({**DEVICE, "ip": "192.168.1.99"})
        with db.get_connection() as conn:
            ip = conn.execute("SELECT ip FROM devices").fetchone()[0]
        self.assertEqual(ip, "192.168.1.99")

    def test_update_device(self):
        db.save_device(DEVICE)
        self.assertTrue(db.update_device(DEVICE["mac"], "Laptop", True))
        with db.get_connection() as conn:
            name, trusted = conn.execute("SELECT name, trusted FROM devices").fetchone()
        self.assertEqual((name, trusted), ("Laptop", 1))

    def test_update_unknown_device_returns_false(self):
        self.assertFalse(db.update_device("00:00:00:00:00:00", "x", False))

    def test_create_tables_is_idempotent(self):
        db.save_device(DEVICE)
        db.create_tables()
        self.assertEqual(db.count_devices(), 1)

    def test_connection_is_closed_after_use(self):
        with db.get_connection() as conn:
            conn.execute("SELECT 1")
        with self.assertRaises(sqlite3.ProgrammingError):
            conn.execute("SELECT 1")

    def test_failed_transaction_is_rolled_back(self):
        with self.assertRaises(RuntimeError):
            with db.get_connection() as conn:
                conn.execute(
                    "INSERT INTO devices (mac, ip, vendor, first_seen, last_seen) "
                    "VALUES ('x', 'y', 'z', 'a', 'b')"
                )
                raise RuntimeError("boom")
        self.assertEqual(db.count_devices(), 0)


class MigrationTests(TempDatabaseTestCase):
    def test_old_schema_gets_new_columns(self):
        # Rebuild the devices table the way the very first version had it.
        with db.get_connection() as conn:
            conn.execute("DROP TABLE devices")
            conn.execute(
                "CREATE TABLE devices (mac TEXT PRIMARY KEY, ip TEXT, vendor TEXT, "
                "first_seen TEXT, last_seen TEXT)"
            )
            conn.execute(
                "INSERT INTO devices VALUES ('aa:bb:cc:dd:ee:ff', '1.1.1.1', 'V', 't', 't')"
            )
        db.create_tables()
        with db.get_connection() as conn:
            columns = [row[1] for row in conn.execute("PRAGMA table_info(devices)")]
            name, trusted = conn.execute("SELECT name, trusted FROM devices").fetchone()
        self.assertIn("name", columns)
        self.assertIn("trusted", columns)
        self.assertEqual((name, trusted), ("", 0))


class PortTests(TempDatabaseTestCase):
    MAC = "aa:bb:cc:dd:ee:ff"

    def test_first_scan_reports_all_ports_as_new(self):
        new = db.save_ports(self.MAC, [(22, "ssh"), (80, "http")])
        self.assertEqual(sorted(new), [22, 80])

    def test_only_newly_opened_ports_are_reported(self):
        db.save_ports(self.MAC, [(22, "ssh")])
        new = db.save_ports(self.MAC, [(22, "ssh"), (445, "microsoft-ds")])
        self.assertEqual(new, [445])

    def test_closed_ports_are_removed(self):
        db.save_ports(self.MAC, [(22, "ssh"), (80, "http")])
        db.save_ports(self.MAC, [(22, "ssh")])
        self.assertEqual(db.get_all_ports()[self.MAC], [{"port": 22, "service": "ssh"}])

    def test_all_ports_closed_clears_the_device(self):
        db.save_ports(self.MAC, [(22, "ssh")])
        db.save_ports(self.MAC, [])
        self.assertNotIn(self.MAC, db.get_all_ports())

    def test_ports_are_grouped_per_device_and_sorted(self):
        db.save_ports("aa:aa:aa:aa:aa:aa", [(80, "http"), (22, "ssh")])
        db.save_ports("bb:bb:bb:bb:bb:bb", [(443, "https")])
        ports = db.get_all_ports()
        self.assertEqual([p["port"] for p in ports["aa:aa:aa:aa:aa:aa"]], [22, 80])
        self.assertEqual(len(ports["bb:bb:bb:bb:bb:bb"]), 1)


if __name__ == "__main__":
    unittest.main()
