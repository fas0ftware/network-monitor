"""Tests for v2: event log, delete, CSV export, security hardening, demo data."""
import csv
import io
import unittest
from datetime import datetime, timedelta
from unittest import mock

import app as app_module
import db
import demo
from tests.helpers import TempDatabaseTestCase

MAC = "aa:bb:cc:dd:ee:ff"
DEV = {"ip": "192.168.1.10", "mac": MAC, "vendor": "Vendor"}


def kinds():
    return [e["kind"] for e in reversed(db.get_events(100))]


class EventLogTests(TempDatabaseTestCase):
    def test_new_device_and_ip_change_events(self):
        db.save_device(DEV)
        db.save_device({**DEV, "ip": "192.168.1.11"})
        db.save_device({**DEV, "ip": "192.168.1.11"})
        self.assertEqual(kinds(), [db.NEW_DEVICE, db.IP_CHANGED])
        self.assertEqual(db.get_events(1)[0]["detail"], "192.168.1.10 → 192.168.1.11")

    def test_back_online_after_timeout(self):
        db.save_device(DEV)
        old = (datetime.now() - timedelta(hours=5)).isoformat(timespec="seconds")
        with db.get_connection() as conn:
            conn.execute("UPDATE devices SET last_seen = ?", (old,))
        db.save_device(DEV)
        self.assertEqual(kinds()[-1], db.BACK_ONLINE)
        self.assertEqual(db.get_events(1)[0]["detail"], "after 5 h")

    def test_port_events_skip_the_baseline(self):
        db.save_device(DEV)
        db.save_ports(MAC, [(22, "ssh")], ip=DEV["ip"], log=False)       # baseline
        db.save_ports(MAC, [(22, "ssh"), (23, "telnet")], ip=DEV["ip"])  # opened
        db.save_ports(MAC, [(23, "telnet")], ip=DEV["ip"])               # 22 closed
        self.assertEqual(kinds(), [db.NEW_DEVICE, db.PORT_OPENED, db.PORT_CLOSED])
        details = [e["detail"] for e in db.get_events(2)]
        self.assertEqual(details, ["22/ssh", "23/telnet"])

    def test_events_filter_by_mac_and_carry_names(self):
        db.save_device(DEV)
        db.save_device({**DEV, "mac": "11:22:33:44:55:66"})
        db.update_device(MAC, "Laptop", True)
        events = db.get_events(10, mac=MAC)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["name"], "Laptop")

    def test_prune_keeps_newest(self):
        for i in range(30):
            db.log_event(db.PORT_OPENED, MAC, "x", str(i))
        db.prune_events(keep=10)
        events = db.get_events(100)
        self.assertEqual(len(events), 10)
        self.assertEqual(events[0]["detail"], "29")

    def test_delete_device_removes_ports_and_logs(self):
        db.save_device(DEV)
        db.save_ports(MAC, [(22, "ssh")])
        self.assertTrue(db.delete_device(MAC))
        self.assertFalse(db.delete_device(MAC))
        self.assertEqual(db.count_devices(), 0)
        self.assertEqual(db.get_all_ports(), {})
        self.assertEqual(kinds()[-1], db.DEVICE_REMOVED)
        self.assertTrue(db.save_device(DEV))  # comes back as new


class ApiV2Tests(TempDatabaseTestCase):
    def setUp(self):
        super().setUp()
        self.app = app_module.create_app()
        self.client = self.app.test_client()
        db.save_device(DEV)

    def test_events_endpoint(self):
        events = self.client.get("/api/events?limit=5").get_json()
        self.assertEqual(events[0]["kind"], db.NEW_DEVICE)
        self.assertEqual(self.client.get("/api/events?limit=abc").status_code, 400)
        self.assertEqual(self.client.get("/api/events?mac=nope").status_code, 400)
        self.assertEqual(len(self.client.get(f"/api/events?mac={MAC.upper()}").get_json()), 1)

    def test_delete_endpoint(self):
        self.assertEqual(self.client.delete("/api/devices/bad").status_code, 400)
        self.assertEqual(self.client.delete(f"/api/devices/{MAC}").status_code, 200)
        self.assertEqual(self.client.delete(f"/api/devices/{MAC}").status_code, 404)

    def test_csv_export_and_formula_injection_guard(self):
        db.update_device(MAC, "=HYPERLINK(\"http://evil\")", True)
        response = self.client.get("/api/devices.csv")
        self.assertEqual(response.mimetype, "text/csv")
        rows = list(csv.reader(io.StringIO(response.get_data(as_text=True))))
        self.assertEqual(rows[0][:3], ["name", "ip", "mac"])
        self.assertTrue(rows[1][0].startswith("'="))

    def test_security_headers(self):
        response = self.client.get("/")
        csp = response.headers["Content-Security-Policy"]
        self.assertIn("script-src 'self'", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(self.client.get("/api/devices").headers["Cache-Control"], "no-store")

    def test_dns_rebinding_host_is_rejected(self):
        response = self.client.get("/api/devices", headers={"Host": "attacker.example:5000"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.client.get("/api/devices", headers={"Host": "127.0.0.1:5000"}).status_code, 200)

    def test_cross_origin_writes_are_refused(self):
        body = {"name": "x", "trusted": True}
        evil = self.client.post(f"/api/devices/{MAC}", json=body, headers={"Origin": "http://evil.example"})
        self.assertEqual(evil.status_code, 403)
        same = self.client.post(f"/api/devices/{MAC}", json=body, headers={"Origin": "http://localhost"})
        self.assertEqual(same.status_code, 200)
        self.assertEqual(self.client.delete(f"/api/devices/{MAC}", headers={"Origin": "http://evil.example"}).status_code, 403)

    def test_oversized_body_is_rejected(self):
        response = self.client.post(f"/api/devices/{MAC}", data="x" * 20000, content_type="application/json")
        self.assertEqual(response.status_code, 413)

    def test_health(self):
        self.assertTrue(self.client.get("/api/health").get_json()["ok"])


class TokenTests(TempDatabaseTestCase):
    TOKEN = "s3cret-token-0123456789"

    def setUp(self):
        super().setUp()
        self.client = app_module.create_app(token=self.TOKEN).test_client()

    def test_api_requires_token(self):
        self.assertEqual(self.client.get("/api/devices").status_code, 401)
        ok = self.client.get("/api/devices", headers={"Authorization": f"Bearer {self.TOKEN}"})
        self.assertEqual(ok.status_code, 200)
        bad = self.client.get("/api/devices", headers={"Authorization": "Bearer wrong"})
        self.assertEqual(bad.status_code, 401)

    def test_token_link_sets_httponly_cookie_and_hides_token(self):
        response = self.client.get(f"/?token={self.TOKEN}&mask=1")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/?mask=1")
        cookie = response.headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.assertEqual(self.client.get("/api/devices").status_code, 200)  # cookie now sent

    def test_wrong_token_link_sets_no_cookie(self):
        response = self.client.get("/?token=nope")
        self.assertNotIn("Set-Cookie", response.headers)
        self.assertIn(b"protected", self.client.get("/").data)


class ServeTests(unittest.TestCase):
    def test_lan_mode_requires_long_token(self):
        with mock.patch.dict(app_module.os.environ, {"NETMON_TOKEN": "short"}), \
                mock.patch("sys.stderr", io.StringIO()) as err:
            self.assertEqual(app_module.main(["--host", "0.0.0.0"]), 2)
        self.assertIn("NETMON_TOKEN", err.getvalue())


class DemoTests(TempDatabaseTestCase):
    def test_demo_seed(self):
        demo.seed()
        devices = app_module.get_devices()
        self.assertEqual(len(devices), len(demo.DEVICES))
        self.assertTrue(any(not d["online"] for d in devices))
        self.assertTrue(any(p["risky"] for d in devices for p in d["ports"]))
        self.assertTrue(all(d["ip"].startswith("192.168.") for d in devices))
        self.assertGreaterEqual(len(db.get_events(100)), len(demo.DEVICES))


if __name__ == "__main__":
    unittest.main()
