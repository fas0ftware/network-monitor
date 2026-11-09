import re
import unittest

from advisor import (
    ENTRIES,
    MAX_UNTRUSTED_PENALTY,
    RISK_LEVELS,
    RISK_PENALTY,
    UNTRUSTED_PENALTY,
    build_summary,
    get_advice,
    highest_risk,
    is_risky,
    port_info,
)
from defense_guide import CHECKLIST, get_guide
from portscan import COMMON_PORTS

ALLOWED_PLACEHOLDERS = {"{ip}", "{port}", "{subnet}"}


def make_device(mac, trusted, ports):
    """ports: [(port, accepted), ...]"""
    return {
        "mac": mac,
        "ip": "192.168.1.10",
        "name": "",
        "trusted": trusted,
        "ports": [
            {"port": p, "name": port_info(p)["name"], "risk": port_info(p)["risk"], "accepted": accepted}
            for p, accepted in ports
        ],
    }


class KnowledgeBaseTests(unittest.TestCase):
    def test_every_scanned_port_has_advice(self):
        missing = [p for p in COMMON_PORTS if p not in ENTRIES]
        self.assertEqual(missing, [], f"Taranan ama bilgi tabanında olmayan portlar: {missing}")

    def test_entries_are_complete(self):
        for port, entry in ENTRIES.items():
            with self.subTest(port=port):
                self.assertIn(entry["risk"], RISK_LEVELS)
                for field in ("name", "what", "why"):
                    self.assertTrue(entry[field].strip(), f"{port}: {field} boş")
                self.assertTrue(entry["fix"], f"{port}: kapatma adımı yok")
                for group in entry["fix"]:
                    self.assertTrue(group["where"].strip())
                    self.assertTrue(group["steps"])

    def test_only_known_placeholders_are_used(self):
        for port in list(ENTRIES) + [99999]:
            advice = get_advice(port)
            strings = [advice["what"], advice["why"], *advice["verify"]]
            for group in advice["fix"]:
                strings.extend(group["steps"])
            for text in strings:
                for token in re.findall(r"\{[^}\s]*\}", text):
                    # Yapılandırma örneklerindeki süslü parantezler (ör. "PID eq") yer tutucu değildir
                    self.assertIn(token, ALLOWED_PLACEHOLDERS, f"{port}: bilinmeyen yer tutucu {token}")

    def test_critical_ports(self):
        for port in (23, 2323, 2375, 5555):
            self.assertEqual(port_info(port)["risk"], "critical")

    def test_unknown_port_gets_generic_advice(self):
        advice = get_advice(54321, "foo")
        self.assertEqual(advice["risk"], "medium")
        self.assertIn("54321", advice["name"])
        commands = [s for g in advice["fix"] for s in g["steps"] if s.startswith("$ ")]
        self.assertTrue(any("{port}" in c for c in commands))

    def test_firewall_group_only_where_it_makes_sense(self):
        self.assertTrue(any("güvenlik duvarıyla" in g["where"] for g in get_advice(23)["fix"]))
        self.assertFalse(any("güvenlik duvarıyla" in g["where"] for g in get_advice(62078)["fix"]))

    def test_is_risky(self):
        self.assertTrue(is_risky(23))
        self.assertTrue(is_risky(445))
        self.assertFalse(is_risky(443))
        self.assertFalse(is_risky(62078))

    def test_highest_risk(self):
        self.assertEqual(highest_risk([]), "none")
        self.assertEqual(highest_risk(["info"]), "none")
        self.assertEqual(highest_risk(["low", "high", "medium"]), "high")


class SummaryTests(unittest.TestCase):
    def test_empty_network_is_perfect(self):
        summary = build_summary([])
        self.assertEqual(summary["score"], 100)
        self.assertEqual(summary["top_actions"], [])

    def test_score_arithmetic(self):
        devices = [
            make_device("aa:aa:aa:aa:aa:01", True, [(23, False), (445, False)]),   # critical + high
            make_device("aa:aa:aa:aa:aa:02", False, [(80, False), (443, False)]),  # medium + low, güvenilmez
        ]
        expected = 100 - RISK_PENALTY["critical"] - RISK_PENALTY["high"] - RISK_PENALTY["medium"] - RISK_PENALTY["low"] - UNTRUSTED_PENALTY
        self.assertEqual(build_summary(devices)["score"], expected)

    def test_accepted_ports_do_not_count(self):
        devices = [make_device("aa:aa:aa:aa:aa:01", True, [(23, True)])]
        summary = build_summary(devices)
        self.assertEqual(summary["score"], 100)
        self.assertEqual(summary["counts"]["critical"], 0)
        self.assertEqual(summary["top_actions"], [])

    def test_untrusted_penalty_is_capped(self):
        devices = [make_device(f"aa:aa:aa:aa:aa:{i:02x}", False, []) for i in range(30)]
        self.assertEqual(build_summary(devices)["score"], 100 - MAX_UNTRUSTED_PENALTY)

    def test_score_never_below_zero(self):
        devices = [make_device("aa:aa:aa:aa:aa:01", False, [(23, False), (2375, False), (5555, False), (445, False), (3389, False)])]
        self.assertEqual(build_summary(devices)["score"], 0)

    def test_top_actions_sorted_by_risk(self):
        devices = [make_device("aa:aa:aa:aa:aa:01", True, [(80, False), (445, False), (23, False), (443, False), (22, False)])]
        actions = build_summary(devices)["top_actions"]
        self.assertEqual([a["port"] for a in actions], [23, 445, 22])
        self.assertTrue(all(a["risk"] != "low" for a in actions))


class GuideTests(unittest.TestCase):
    def test_checklist_ids_are_unique(self):
        ids = [item["id"] for group in CHECKLIST for item in group["items"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_guide_has_playbook(self):
        guide = get_guide()
        self.assertTrue(guide["unknown_device_playbook"]["steps"])


if __name__ == "__main__":
    unittest.main()
