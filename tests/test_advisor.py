"""Tests for 2.1: the security advisor, the score, acknowledged ports and the defence guide."""
import math
import re
import unittest

import advisor
import app as app_module
import db
import defense_guide
import portscan
from tests.helpers import TempDatabaseTestCase

MAC = "aa:bb:cc:dd:ee:ff"
DEV = {"ip": "192.168.1.10", "mac": MAC, "vendor": "Vendor"}


def device(ports, trusted=True, mac=MAC, ip="192.168.1.10"):
    return {"mac": mac, "ip": ip, "name": "", "trusted": trusted, "ports": [
        {"port": p, "service": "x", **advisor.port_info(p), "accepted": accepted} for p, accepted in ports]}


class KnowledgeBaseTests(unittest.TestCase):
    def test_every_scanned_port_has_complete_advice(self):
        self.assertEqual(portscan.COMMON_PORTS, sorted(advisor.ENTRIES))
        for port in portscan.COMMON_PORTS:
            with self.subTest(port=port):
                a = advisor.get_advice(port)
                self.assertIn(a["risk"], advisor.RISK_LEVELS)
                self.assertTrue(a["name"] and a["what"] and a["why"] and a["fix"] and a["verify"])
                for group in a["fix"]:
                    self.assertTrue(group["where"] and group["steps"])

    def test_placeholders_are_only_the_known_ones(self):
        for port in list(advisor.ENTRIES) + [12345]:
            a = advisor.get_advice(port)
            text = " ".join([a["what"], a["why"]] + [s for g in a["fix"] for s in g["steps"]] + a["verify"])
            self.assertEqual(set(re.findall(r"\{(\w+)\}", text)) - {"ip", "port", "subnet"}, set(), port)

    def test_no_turkish_left_in_the_english_ui(self):
        everything = repr(advisor.ENTRIES) + repr(advisor.VERIFY_STEPS) + repr(defense_guide.get_guide())
        self.assertFalse(re.search(r"[çğışöüÇĞİŞÖÜ]", everything))

    def test_risky_ports_follow_the_risk_levels(self):
        self.assertTrue({21, 23, 445, 3389, 5900} <= advisor.RISKY_PORTS)  # the 2.0 list is kept
        self.assertIn(2375, advisor.RISKY_PORTS)  # Docker API: critical
        self.assertIn(5555, advisor.RISKY_PORTS)  # Android ADB: critical
        self.assertNotIn(22, advisor.RISKY_PORTS)
        self.assertNotIn(62078, advisor.RISKY_PORTS)
        self.assertIs(portscan.RISKY_PORTS, advisor.RISKY_PORTS)

    def test_unknown_port_gets_generic_advice_with_firewall_step(self):
        a = advisor.get_advice(12345, "mystery")
        self.assertEqual((a["risk"], a["name"]), ("medium", "Port 12345 (mystery)"))
        self.assertIn("ufw deny 12345/tcp", " ".join(a["fix"][-1]["steps"]))

    def test_firewall_step_only_where_it_makes_sense(self):
        self.assertIn("firewall", advisor.get_advice(23)["fix"][-1]["where"])
        self.assertNotIn("firewall", advisor.get_advice(9100)["fix"][-1]["where"])  # printers have none


class ScoreTests(unittest.TestCase):
    def test_clean_network_scores_high(self):
        self.assertEqual(advisor.build_summary([device([(62078, False)])])["score"], 100)
        s = advisor.build_summary([device([(443, False), (62078, False)])])
        self.assertEqual((s["score"], s["label"], s["top_actions"]), (98, "Strong", []))

    def test_penalties_and_actions_sorted_by_risk(self):
        s = advisor.build_summary([device([(22, False), (23, False), (445, False)])])
        self.assertEqual(s["penalty_points"], 6 + 25 + 14)
        self.assertEqual(round(100 * math.exp(-45 / 80)), 57)
        self.assertEqual(s["score"], 39)  # 57 from the points, capped by the open Telnet
        self.assertEqual([a["port"] for a in s["top_actions"]], [23, 445, 22])
        self.assertEqual(s["counts"]["critical"], 1)

    def test_one_open_risky_port_caps_the_score(self):
        self.assertEqual(advisor.build_summary([device([(23, False)])])["score"], 39)    # alone: 73
        self.assertEqual(advisor.build_summary([device([(3389, False)])])["score"], 69)  # alone: 84
        self.assertEqual(advisor.build_summary([device([(22, False)])])["label"], "Strong")

    def test_score_keeps_moving_on_a_bad_network(self):
        bad = [device([(p, False) for p in (23, 2323, 2375, 5555, 445, 3389)], trusted=False)]
        better = [device([(p, False) for p in (23, 445, 3389)], trusted=False)]
        self.assertLess(advisor.build_summary(bad)["score"], advisor.build_summary(better)["score"])
        self.assertGreater(advisor.build_summary(bad)["score"], 0)

    def test_accepted_ports_do_not_count(self):
        s = advisor.build_summary([device([(23, True)])])
        self.assertEqual((s["score"], s["top_actions"]), (100, []))

    def test_untrusted_devices_cost_points_up_to_a_cap(self):
        devs = [device([], trusted=False, mac=f"aa:bb:cc:dd:ee:{i:02x}") for i in range(10)]
        self.assertEqual(advisor.build_summary(devs)["penalty_points"], advisor.MAX_UNTRUSTED_PENALTY)

    def test_top_three_only(self):
        s = advisor.build_summary([device([(p, False) for p in (23, 2323, 2375, 5555, 445)], trusted=False)])
        self.assertEqual((s["label"], len(s["top_actions"])), ("At risk", 3))


class AcceptedPortStorageTests(TempDatabaseTestCase):
    def test_accept_only_open_ports_and_undo(self):
        db.save_device(DEV)
        db.save_ports(MAC, [(22, "ssh")], ip=DEV["ip"], log=False)
        self.assertFalse(db.set_port_accepted(MAC, 23, True))
        self.assertTrue(db.set_port_accepted(MAC, 22, True))
        self.assertEqual(db.get_accepted_ports(), {(MAC, 22)})
        self.assertTrue(db.set_port_accepted(MAC, 22, False))
        self.assertEqual(db.get_accepted_ports(), set())

    def test_forgetting_a_device_forgets_its_acknowledgements(self):
        db.save_device(DEV)
        db.save_ports(MAC, [(22, "ssh")], ip=DEV["ip"], log=False)
        db.set_port_accepted(MAC, 22, True)
        db.delete_device(MAC)
        self.assertEqual(db.get_accepted_ports(), set())

    def test_create_tables_upgrades_a_2_0_database(self):
        with db.get_connection() as conn:
            conn.execute("DROP TABLE accepted_ports")
        db.create_tables()
        self.assertEqual(db.get_accepted_ports(), set())


class AdvisorApiTests(TempDatabaseTestCase):
    def setUp(self):
        super().setUp()
        self.client = app_module.create_app().test_client()
        db.save_device(DEV)
        db.save_ports(MAC, [(22, "ssh"), (23, "telnet")], ip=DEV["ip"], log=False)

    def test_devices_carry_risk_and_acknowledgement(self):
        ports = {p["port"]: p for p in self.client.get("/api/devices").get_json()[0]["ports"]}
        self.assertEqual((ports[23]["risk"], ports[23]["risky"], ports[23]["name"]), ("critical", True, "Telnet"))
        self.assertEqual((ports[22]["risk"], ports[22]["risky"], ports[22]["accepted"]), ("medium", False, False))

    def test_summary(self):
        s = self.client.get("/api/summary").get_json()
        self.assertEqual(s["penalty_points"], 6 + 25 + 4)  # SSH, Telnet, one untrusted device
        self.assertEqual(s["top_actions"][0]["port"], 23)

    def test_accept_roundtrip_changes_the_score(self):
        r = self.client.post(f"/api/devices/{MAC}/ports/22/accept", json={"accepted": True})
        self.assertEqual(r.status_code, 200)
        self.assertTrue([p for p in self.client.get("/api/devices").get_json()[0]["ports"] if p["port"] == 22][0]["accepted"])
        self.assertEqual(self.client.get("/api/summary").get_json()["penalty_points"], 25 + 4)
        self.client.post(f"/api/devices/{MAC}/ports/22/accept", json={"accepted": False})
        self.assertEqual(self.client.get("/api/summary").get_json()["penalty_points"], 6 + 25 + 4)

    def test_accept_validation(self):
        url = f"/api/devices/{MAC}/ports/22/accept"
        self.assertEqual(self.client.post(url, json={"accepted": "true"}).status_code, 400)
        self.assertEqual(self.client.post(url, json=["x"]).status_code, 400)
        self.assertEqual(self.client.post(f"/api/devices/{MAC}/ports/80/accept", json={"accepted": True}).status_code, 404)
        self.assertEqual(self.client.post("/api/devices/nope/ports/22/accept", json={"accepted": True}).status_code, 400)
        self.assertEqual(self.client.post(f"/api/devices/{MAC}/ports/70000/accept", json={"accepted": True}).status_code, 400)
        r = self.client.post(url, json={"accepted": True}, headers={"Origin": "http://evil.example"})
        self.assertEqual(r.status_code, 403)

    def test_advice_and_guide(self):
        a = self.client.get("/api/advice/23").get_json()
        self.assertEqual((a["port"], a["risk"]), (23, "critical"))
        self.assertEqual(self.client.get("/api/advice/0").status_code, 400)
        unknown = self.client.get("/api/advice/4444?service=" + "x" * 500).get_json()
        self.assertLessEqual(len(unknown["name"]), 60)
        guide = self.client.get("/api/defense-guide").get_json()
        ids = [i["id"] for s in guide["checklist"] for i in s["items"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(guide["unknown_device_playbook"]["steps"])

    def test_port_events_carry_their_risk(self):
        db.save_ports(MAC, [(22, "ssh"), (23, "telnet"), (5555, "adb")], ip=DEV["ip"])
        events = self.client.get("/api/events").get_json()
        self.assertEqual(events[0]["risk"], "critical")

    def test_new_endpoints_need_the_token(self):
        client = app_module.create_app(token="s" * 20).test_client()
        for path in ("/api/summary", "/api/advice/22", "/api/defense-guide"):
            self.assertEqual(client.get(path).status_code, 401, path)
        self.assertEqual(client.post(f"/api/devices/{MAC}/ports/22/accept", json={"accepted": True}).status_code, 401)


if __name__ == "__main__":
    unittest.main()
