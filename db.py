import sqlite3
from datetime import datetime

DB_NAME = "devices.db"


def get_connection():
    return sqlite3.connect(DB_NAME)


def create_tables():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                mac        TEXT PRIMARY KEY,
                ip         TEXT,
                vendor     TEXT,
                first_seen TEXT,
                last_seen  TEXT,
                name       TEXT DEFAULT '',
                trusted    INTEGER DEFAULT 0
            )
        """)
        # Eski veritabanında bu kolonlar yoksa ekle
        columns = [row[1] for row in conn.execute("PRAGMA table_info(devices)")]
        if "name" not in columns:
            conn.execute("ALTER TABLE devices ADD COLUMN name TEXT DEFAULT ''")
        if "trusted" not in columns:
            conn.execute("ALTER TABLE devices ADD COLUMN trusted INTEGER DEFAULT 0")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS ports (
                mac        TEXT,
                port       INTEGER,
                service    TEXT,
                first_seen TEXT,
                last_seen  TEXT,
                PRIMARY KEY (mac, port)
            )
        """)


def save_device(device):
    """Cihaz yeniyse True, daha önce görülmüşse False döner."""
    now = datetime.now().isoformat(timespec="seconds")

    with get_connection() as conn:
        exists = conn.execute(
            "SELECT 1 FROM devices WHERE mac = ?", (device["mac"],)
        ).fetchone()

        if exists:
            conn.execute(
                "UPDATE devices SET ip = ?, vendor = ?, last_seen = ? WHERE mac = ?",
                (device["ip"], device["vendor"], now, device["mac"]),
            )
            return False

        conn.execute(
            "INSERT INTO devices (mac, ip, vendor, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?)",
            (device["mac"], device["ip"], device["vendor"], now, now),
        )
        return True


def update_device(mac, name, trusted):
    with get_connection() as conn:
        conn.execute(
            "UPDATE devices SET name = ?, trusted = ? WHERE mac = ?",
            (name, 1 if trusted else 0, mac),
        )


def count_devices():
    with get_connection() as conn:
        return conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]


def save_ports(mac, open_ports):
    """open_ports: [(port, service), ...]
    Yeni açılan portların listesini döner. Kapanan portlar silinir."""
    now = datetime.now().isoformat(timespec="seconds")
    new_ports = []

    with get_connection() as conn:
        known = {row[0] for row in conn.execute(
            "SELECT port FROM ports WHERE mac = ?", (mac,)
        )}

        for port, service in open_ports:
            if port in known:
                conn.execute(
                    "UPDATE ports SET service = ?, last_seen = ? WHERE mac = ? AND port = ?",
                    (service, now, mac, port),
                )
            else:
                conn.execute(
                    "INSERT INTO ports (mac, port, service, first_seen, last_seen) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (mac, port, service, now, now),
                )
                new_ports.append(port)

        current = {port for port, _ in open_ports}
        for port in known - current:
            conn.execute("DELETE FROM ports WHERE mac = ? AND port = ?", (mac, port))

    return new_ports


def get_all_ports():
    """{mac: [{"port": 22, "service": "ssh"}, ...]} döner."""
    result = {}
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT mac, port, service FROM ports ORDER BY port"
        ).fetchall()
    for mac, port, service in rows:
        result.setdefault(mac, []).append({"port": port, "service": service})
    return result