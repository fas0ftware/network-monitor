import os
import tempfile
import unittest

import db


class AppTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        db.DB_NAME = os.path.join(self.tmp.name, "test.db")
        db.create_tables()

        from app import app
        app.config["TESTING"] = True
        self.client = app.test_client()

        self.mac = "aa:bb:cc:dd:ee:01"
        db.save_device({"mac": self.mac, "ip": "192.168.1.20", "vendor": "TestVendor"})
        db.save_ports(self.mac, [(23, "telnet"), (443, "https")])

    def tearDown(self):
        self.tmp.cleanup()

    def post_json(self, url, payload):
        return self.client.post(url, json=payload)

    def test_devices_include_risk_and_port_details(self):
        device = self.client.get("/api/devices").get_json()[0]
        self.assertEqual(device["risk"], "critical")
        ports = {p["port"]: p for p in device["ports"]}
        self.assertEqual(ports[23]["name"], "Telnet")
        self.assertEqual(ports[23]["risk"], "critical")
        self.assertFalse(ports[23]["accepted"])
        self.assertEqual(ports[443]["risk"], "low")

    def test_summary(self):
        summary = self.client.get("/api/summary").get_json()
        self.assertEqual(summary["counts"]["critical"], 1)
        self.assertEqual(summary["counts"]["low"], 1)
        self.assertEqual(summary["untrusted_devices"], 1)
        self.assertEqual(summary["top_actions"][0]["port"], 23)

    def test_advice_endpoint(self):
        advice = self.client.get("/api/advice/23").get_json()
        self.assertEqual(advice["risk"], "critical")
        self.assertTrue(advice["fix"])
        self.assertTrue(advice["verify"])

    def test_advice_for_unknown_port_and_invalid_port(self):
        self.assertEqual(self.client.get("/api/advice/54321").status_code, 200)
        self.assertEqual(self.client.get("/api/advice/0").status_code, 404)
        self.assertEqual(self.client.get("/api/advice/70000").status_code, 404)

    def test_accept_port_removes_it_from_score_and_actions(self):
        url = f"/api/devices/{self.mac}/ports/23/accept"
        self.assertEqual(self.post_json(url, {"accepted": True}).status_code, 200)

        device = self.client.get("/api/devices").get_json()[0]
        telnet = next(p for p in device["ports"] if p["port"] == 23)
        self.assertTrue(telnet["accepted"])
        self.assertEqual(device["risk"], "low")

        summary = self.client.get("/api/summary").get_json()
        self.assertEqual(summary["counts"]["critical"], 0)
        self.assertEqual(summary["top_actions"], [])

        self.assertEqual(self.post_json(url, {"accepted": False}).status_code, 200)
        self.assertFalse(
            next(p for p in self.client.get("/api/devices").get_json()[0]["ports"] if p["port"] == 23)["accepted"]
        )

    def test_accept_requires_json_and_valid_input(self):
        url = f"/api/devices/{self.mac}/ports/23/accept"
        # JSON olmayan istek (başka bir sitenin formu gibi) reddedilir
        self.assertEqual(self.client.post(url, data="accepted=1").status_code, 400)
        self.assertEqual(
            self.post_json("/api/devices/not-a-mac/ports/23/accept", {"accepted": True}).status_code, 400
        )
        self.assertEqual(
            self.post_json(f"/api/devices/{self.mac}/ports/70000/accept", {"accepted": True}).status_code, 400
        )
        self.assertEqual(
            self.post_json("/api/devices/aa:bb:cc:dd:ee:99/ports/23/accept", {"accepted": True}).status_code, 404
        )

    def test_unexpected_host_header_is_rejected(self):
        self.assertEqual(self.client.get("/", headers={"Host": "evil.example"}).status_code, 400)
        self.assertEqual(self.client.get("/api/devices", headers={"Host": "evil.example:5000"}).status_code, 400)
        self.assertEqual(self.client.get("/", headers={"Host": "127.0.0.1:5000"}).status_code, 200)

    def test_security_headers_and_nonce(self):
        response = self.client.get("/")
        csp = response.headers["Content-Security-Policy"]
        self.assertIn("script-src 'nonce-", csp)
        self.assertNotIn("script-src 'unsafe-inline'", csp)
        nonce = csp.split("'nonce-")[1].split("'")[0]
        self.assertIn(f'nonce="{nonce}"', response.get_data(as_text=True))
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")

    def test_defense_guide(self):
        guide = self.client.get("/api/defense-guide").get_json()
        self.assertTrue(guide["checklist"])
        self.assertTrue(guide["unknown_device_playbook"]["steps"])


if __name__ == "__main__":
    unittest.main()
