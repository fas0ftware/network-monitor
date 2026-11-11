import io
import json
import unittest
from contextlib import redirect_stdout
from unittest import mock

import alert


class SendNotificationTests(unittest.TestCase):
    def test_prints_and_survives_missing_notify_send(self):
        def boom(*a, **k):
            raise FileNotFoundError("notify-send")

        out = io.StringIO()
        with mock.patch.dict(alert.os.environ, clear=False) as env, \
                mock.patch.object(alert.subprocess, "run", boom), \
                mock.patch.object(alert.shutil, "which", lambda name: "/usr/bin/" + name), \
                redirect_stdout(out):
            env.pop("SUDO_USER", None)
            alert.send_notification("Başlık", "Mesaj")

        self.assertIn("[ALERT] Başlık: Mesaj", out.getvalue())
        self.assertIn("could not be sent", out.getvalue())

    def test_uses_sudo_user_session(self):
        commands = []
        with mock.patch.dict(alert.os.environ, {"SUDO_USER": "z"}), \
                mock.patch.object(alert.os, "geteuid", lambda: 0), \
                mock.patch.object(alert.subprocess, "check_output", lambda *a, **k: "1000\n"), \
                mock.patch.object(alert.subprocess, "run", lambda cmd, **k: commands.append(cmd)), \
                mock.patch.object(alert.shutil, "which", lambda name: "/usr/bin/" + name), \
                redirect_stdout(io.StringIO()):
            alert.send_notification("T", "M")

        cmd = commands[0]
        self.assertEqual(cmd[:3], ["sudo", "-u", "z"])
        self.assertIn("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus", cmd)
        # "--" stops a vendor/title starting with "-" from being read as an option
        self.assertEqual(cmd[-3:], ["--", "T", "M"])

    def test_no_notify_send_installed_is_fine(self):
        with mock.patch.object(alert.shutil, "which", lambda name: None), \
                mock.patch.object(alert.subprocess, "run", side_effect=AssertionError("must not run")), \
                redirect_stdout(io.StringIO()):
            alert.send_desktop("T", "M")


class PushTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        patcher = mock.patch.object(alert, "_post",
                                    lambda url, data, ctype, headers=None: self.calls.append((url, data, ctype, headers)))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_nothing_configured_sends_nothing(self):
        self.assertEqual(alert.send_push("T", "M", env={}), 0)
        self.assertEqual(self.calls, [])

    def test_ntfy_and_webhook(self):
        env = {"NETMON_NTFY_URL": "https://ntfy.sh/topic", "NETMON_WEBHOOK_URL": "https://discord.com/api/webhooks/x"}
        self.assertEqual(alert.send_push("New device ✓", "192.168.1.5 - Apple", env=env), 2)
        ntfy, hook = self.calls
        self.assertEqual(ntfy[1], "192.168.1.5 - Apple".encode())
        self.assertEqual(ntfy[3]["Title"], "New device ")  # non latin-1 stripped from header
        body = json.loads(hook[1])
        self.assertIn("192.168.1.5", body["content"]) and self.assertEqual(body["text"], body["content"])

    def test_bad_urls_are_ignored(self):
        for url in ("file:///etc/passwd", "ftp://x/y", "not a url", "https://"):
            with self.subTest(url=url):
                self.assertEqual(alert.send_push("T", "M", env={"NETMON_WEBHOOK_URL": url}), 0)
        self.assertEqual(self.calls, [])

    def test_failure_is_reported_not_raised(self):
        def boom(*a, **k):
            raise OSError("down")
        out = io.StringIO()
        with mock.patch.object(alert, "_post", boom), redirect_stdout(out):
            self.assertEqual(alert.send_push("T", "M", env={"NETMON_NTFY_URL": "https://ntfy.sh/t"}), 0)
        self.assertIn("ntfy notification failed: OSError", out.getvalue())


if __name__ == "__main__":
    unittest.main()
