import io
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
                redirect_stdout(io.StringIO()):
            alert.send_notification("T", "M")

        cmd = commands[0]
        self.assertEqual(cmd[:3], ["sudo", "-u", "z"])
        self.assertIn("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus", cmd)


if __name__ == "__main__":
    unittest.main()
