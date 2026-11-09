import unittest
from datetime import datetime, timedelta

import db
from app import app
from tests.helpers import TempDatabaseTestCase

MAC = "aa:bb:cc:dd:ee:ff"


def iso(delta):
    return (datetime.now() - delta).isoformat(timespec="seconds")


class ApiTests(TempDatabaseTestCase):
    def setUp(self):
        super().setUp()
        self.client = app.test_client()

    def add_device(self, mac=MAC, last_seen=None):
        db.save_device({"ip": "192.168.1.10", "mac": mac, "vendor": "V"})
        if last_seen:
            with db.get_connection() as conn:
                conn.execute("UPDATE devices SET last_seen = ? WHERE mac = ?", (last_seen, mac))

    def test_dashboard_page_loads(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Açık portlar".encode(), response.data)

    def test_devices_list_with_online_flag(self):
        self.add_device("aa:aa:aa:aa:aa:aa")
        self.add_device("bb:bb:bb:bb:bb:bb", last_seen=iso(timedelta(minutes=10)))
        devices = {d["mac"]: d for d in self.client.get("/api/devices").get_json()}
        self.assertTrue(devices["aa:aa:aa:aa:aa:aa"]["online"])
        self.assertFalse(devices["bb:bb:bb:bb:bb:bb"]["online"])

    def test_ports_carry_a_risky_flag(self):
        self.add_device()
        db.save_ports(MAC, [(22, "ssh"), (23, "telnet")])
        ports = self.client.get("/api/devices").get_json()[0]["ports"]
        risky = {p["port"]: p["risky"] for p in ports}
        self.assertEqual(risky, {22: False, 23: True})

    def test_save_name_and_trust(self):
        self.add_device()
        response = self.client.post(f"/api/devices/{MAC}", json={"name": "  Laptop  ", "trusted": True})
        self.assertEqual(response.status_code, 200)
        device = self.client.get("/api/devices").get_json()[0]
        self.assertEqual(device["name"], "Laptop")
        self.assertTrue(device["trusted"])

    def test_name_is_limited_to_50_characters(self):
        self.add_device()
        self.client.post(f"/api/devices/{MAC}", json={"name": "x" * 80, "trusted": False})
        self.assertEqual(len(self.client.get("/api/devices").get_json()[0]["name"]), 50)

    def test_mac_in_url_is_case_insensitive(self):
        self.add_device()
        response = self.client.post(f"/api/devices/{MAC.upper()}", json={"name": "A", "trusted": False})
        self.assertEqual(response.status_code, 200)

    def test_bad_requests_are_rejected(self):
        self.add_device()
        cases = [
            ("not-a-mac", {"name": "A", "trusted": True}, 400),
            (MAC, {"name": 5, "trusted": True}, 400),
            (MAC, {"name": "A", "trusted": "false"}, 400),  # a string must not count as True
            ("00:00:00:00:00:00", {"name": "A", "trusted": True}, 404),
        ]
        for mac, body, status in cases:
            with self.subTest(mac=mac, body=body):
                self.assertEqual(self.client.post(f"/api/devices/{mac}", json=body).status_code, status)

    def test_non_json_body_is_rejected(self):
        self.add_device()
        response = self.client.post(f"/api/devices/{MAC}", data="name=x", content_type="text/plain")
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
