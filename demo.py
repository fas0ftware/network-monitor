"""Fill the current database with realistic sample devices (for screenshots and trying the UI).

All addresses are private (RFC 1918) and the MACs use locally-administered or
documentation-style prefixes; nothing here describes a real network."""

from datetime import datetime, timedelta

import db

DEVICES = [
    # mac, ip, vendor, name, trusted, minutes since last seen, ports
    ("3c:84:6a:12:a4:01", "192.168.1.1", "TP-LINK TECHNOLOGIES", "Router", True, 0, [(53, "domain"), (80, "http"), (443, "https")]),
    ("a4:83:e7:5b:20:11", "192.168.1.20", "Apple, Inc.", "Work laptop", True, 0, [(5000, "commplex-main")]),
    ("f0:18:98:44:3e:7a", "192.168.1.21", "Apple, Inc.", "iPhone", True, 1, [(62078, "iphone-sync")]),
    ("dc:a6:32:9c:01:5e", "192.168.1.30", "Raspberry Pi Trading Ltd", "Pi-hole", True, 0, [(22, "ssh"), (53, "domain"), (80, "http")]),
    ("00:17:88:6b:2f:90", "192.168.1.40", "Philips Lighting BV", "Hue Bridge", True, 0, [(80, "http"), (443, "https")]),
    ("b8:27:eb:00:fe:33", "192.168.1.41", "Raspberry Pi Foundation", "Old camera Pi", False, 0, [(22, "ssh"), (23, "telnet"), (554, "rtsp")]),
    ("30:05:5c:7a:91:02", "192.168.1.50", "Brother Industries", "Printer", True, 2, [(80, "http"), (9100, "jetdirect")]),
    ("70:85:c2:d1:44:aa", "192.168.1.60", "ASRock Incorporation", "Desktop PC", True, 0, [(139, "netbios-ssn"), (445, "microsoft-ds"), (3389, "ms-wbt-server")]),
    ("44:65:0d:3c:7e:18", "192.168.1.70", "Amazon Technologies Inc.", "Echo Dot", True, 4, []),
    ("5c:aa:fd:20:13:9b", "192.168.1.71", "Sonos, Inc.", "Living room speaker", True, 48 * 60, []),
    ("9a:1f:44:c2:0b:7d", "192.168.1.88", "Private (randomized MAC)", "", False, 0, [(8080, "http-alt")]),
    ("c8:3a:6b:51:0e:42", "192.168.1.90", "Shenzhen Tv-box Co.", "TV box", False, 3, [(5555, "adb")]),
]

# Ports the owner has acknowledged ("I know about this"): the Pi-hole's SSH is on purpose.
ACCEPTED = [("dc:a6:32:9c:01:5e", 22)]


def seed(now=None):
    now = now or datetime.now()
    db.create_tables()
    with db.get_connection() as conn:
        for i, (mac, ip, vendor, name, trusted, ago, ports) in enumerate(DEVICES):
            first = (now - timedelta(days=30 - i * 2, hours=i)).isoformat(timespec="seconds")
            last = (now - timedelta(minutes=ago)).isoformat(timespec="seconds")
            conn.execute("INSERT OR REPLACE INTO devices VALUES (?, ?, ?, ?, ?, ?, ?)",
                         (mac, ip, vendor, first, last, name, int(trusted)))
            for port, service in ports:
                conn.execute("INSERT OR REPLACE INTO ports VALUES (?, ?, ?, ?, ?)", (mac, port, service, first, last))
            db._log(conn, db.NEW_DEVICE, mac, ip, vendor, first)

        events = [
            (240, db.IP_CHANGED, "f0:18:98:44:3e:7a", "192.168.1.21", "192.168.1.14 → 192.168.1.21"),
            (180, db.PORT_CLOSED, "70:85:c2:d1:44:aa", "192.168.1.60", "5900/vnc"),
            (95, db.BACK_ONLINE, "44:65:0d:3c:7e:18", "192.168.1.70", "after 9 h"),
            (42, db.PORT_OPENED, "b8:27:eb:00:fe:33", "192.168.1.41", "23/telnet"),
            (12, db.NEW_DEVICE, "9a:1f:44:c2:0b:7d", "192.168.1.88", "Private (randomized MAC)"),
            (6, db.PORT_OPENED, "9a:1f:44:c2:0b:7d", "192.168.1.88", "8080/http-alt"),
        ]
        for mac, port in ACCEPTED:
            conn.execute("INSERT OR REPLACE INTO accepted_ports VALUES (?, ?, ?)", (mac, port, now.isoformat(timespec="seconds")))
        conn.execute("DELETE FROM events WHERE mac = ? AND kind = ?", ("9a:1f:44:c2:0b:7d", db.NEW_DEVICE))
        for ago, kind, mac, ip, detail in events:
            db._log(conn, kind, mac, ip, detail, (now - timedelta(minutes=ago)).isoformat(timespec="seconds"))
