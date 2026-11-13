"""SQLite storage: devices, open ports and an event log."""

import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta

from config import ONLINE_TIMEOUT

DB_NAME = os.environ.get("NETMON_DB", "devices.db")

# Event kinds written to the log (shown on the dashboard timeline)
NEW_DEVICE = "new_device"
IP_CHANGED = "ip_changed"
BACK_ONLINE = "back_online"
PORT_OPENED = "port_opened"
PORT_CLOSED = "port_closed"
DEVICE_REMOVED = "device_removed"
EVENT_KINDS = (NEW_DEVICE, IP_CHANGED, BACK_ONLINE, PORT_OPENED, PORT_CLOSED, DEVICE_REMOVED)

MAX_EVENTS = 5000  # older events are pruned so the file never grows without bound


def now_iso():
    return datetime.now().isoformat(timespec="seconds")


@contextmanager
def get_connection():
    """Open the database, commit on success, roll back on error, always close.

    (sqlite3's own `with` only commits; it never closes the connection.)
    """
    conn = sqlite3.connect(DB_NAME, timeout=10)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def create_tables():
    with get_connection() as conn:
        # WAL: the dashboard can read while the scanner writes
        conn.execute("PRAGMA journal_mode=WAL")

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
        # Migrate databases created by v1.0
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
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id     INTEGER PRIMARY KEY AUTOINCREMENT,
                ts     TEXT NOT NULL,
                kind   TEXT NOT NULL,
                mac    TEXT,
                ip     TEXT,
                detail TEXT DEFAULT ''
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS events_ts ON events (ts)")
        # Ports the owner acknowledged ("I know about this"): they stay listed but stop
        # counting against the security score. Kept per device, so the same port on
        # another device still counts.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS accepted_ports (
                mac         TEXT,
                port        INTEGER,
                accepted_at TEXT,
                PRIMARY KEY (mac, port)
            )
        """)


def _log(conn, kind, mac, ip, detail="", ts=None):
    conn.execute("INSERT INTO events (ts, kind, mac, ip, detail) VALUES (?, ?, ?, ?, ?)",
                 (ts or now_iso(), kind, mac, ip, detail))


def log_event(kind, mac, ip, detail=""):
    with get_connection() as conn:
        _log(conn, kind, mac, ip, detail)


def save_device(device):
    """Insert or update a device. Returns True if the MAC was never seen before.

    Also logs NEW_DEVICE, IP_CHANGED and BACK_ONLINE events."""
    now = datetime.now()
    stamp = now.isoformat(timespec="seconds")

    with get_connection() as conn:
        row = conn.execute("SELECT ip, last_seen FROM devices WHERE mac = ?", (device["mac"],)).fetchone()

        if row:
            old_ip, last_seen = row
            if old_ip != device["ip"]:
                _log(conn, IP_CHANGED, device["mac"], device["ip"], f"{old_ip} → {device['ip']}", stamp)
            try:
                away = now - datetime.fromisoformat(last_seen)
            except (TypeError, ValueError):
                away = timedelta(0)
            if away > ONLINE_TIMEOUT:
                _log(conn, BACK_ONLINE, device["mac"], device["ip"], f"after {_human(away)}", stamp)
            conn.execute(
                "UPDATE devices SET ip = ?, vendor = ?, last_seen = ? WHERE mac = ?",
                (device["ip"], device["vendor"], stamp, device["mac"]),
            )
            return False

        conn.execute(
            "INSERT INTO devices (mac, ip, vendor, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
            (device["mac"], device["ip"], device["vendor"], stamp, stamp),
        )
        _log(conn, NEW_DEVICE, device["mac"], device["ip"], device["vendor"], stamp)
        return True


def _human(delta):
    minutes = int(delta.total_seconds() // 60)
    if minutes < 60:
        return f"{minutes} min"
    hours = minutes // 60
    return f"{hours} h" if hours < 48 else f"{hours // 24} days"


def update_device(mac, name, trusted):
    """Save a friendly name and the trusted flag. False if the device is unknown."""
    with get_connection() as conn:
        cursor = conn.execute(
            "UPDATE devices SET name = ?, trusted = ? WHERE mac = ?",
            (name, 1 if trusted else 0, mac),
        )
        return cursor.rowcount > 0


def delete_device(mac):
    """Forget a device and its ports (it will be reported as new if it returns)."""
    with get_connection() as conn:
        row = conn.execute("SELECT ip FROM devices WHERE mac = ?", (mac,)).fetchone()
        if not row:
            return False
        conn.execute("DELETE FROM ports WHERE mac = ?", (mac,))
        conn.execute("DELETE FROM accepted_ports WHERE mac = ?", (mac,))
        conn.execute("DELETE FROM devices WHERE mac = ?", (mac,))
        _log(conn, DEVICE_REMOVED, mac, row[0], "removed from the dashboard")
        return True


def count_devices():
    with get_connection() as conn:
        return conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]


def save_ports(mac, open_ports, ip=None, log=True):
    """open_ports: [(port, service), ...]

    Returns the list of newly opened ports. Closed ports are deleted. With
    log=True, PORT_OPENED / PORT_CLOSED events are written (pass log=False for
    the silent baseline scan)."""
    now = now_iso()
    new_ports = []

    with get_connection() as conn:
        known = {row[0]: row[1] for row in conn.execute(
            "SELECT port, service FROM ports WHERE mac = ?", (mac,)
        )}

        for port, service in open_ports:
            if port in known:
                conn.execute(
                    "UPDATE ports SET service = ?, last_seen = ? WHERE mac = ? AND port = ?",
                    (service, now, mac, port),
                )
            else:
                conn.execute(
                    "INSERT INTO ports (mac, port, service, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
                    (mac, port, service, now, now),
                )
                new_ports.append(port)
                if log and known:  # a device's very first port list is not "news"
                    _log(conn, PORT_OPENED, mac, ip, f"{port}/{service}", now)

        current = {port for port, _ in open_ports}
        for port in set(known) - current:
            conn.execute("DELETE FROM ports WHERE mac = ? AND port = ?", (mac, port))
            if log:
                _log(conn, PORT_CLOSED, mac, ip, f"{port}/{known[port]}", now)

    return new_ports


def get_all_ports():
    """{mac: [{"port": 22, "service": "ssh"}, ...]}"""
    result = {}
    with get_connection() as conn:
        rows = conn.execute("SELECT mac, port, service FROM ports ORDER BY port").fetchall()
    for mac, port, service in rows:
        result.setdefault(mac, []).append({"port": port, "service": service})
    return result


def set_port_accepted(mac, port, accepted):
    """Acknowledge (or stop acknowledging) an open port. False if the device does not have it open."""
    with get_connection() as conn:
        if accepted:
            if not conn.execute("SELECT 1 FROM ports WHERE mac = ? AND port = ?", (mac, port)).fetchone():
                return False
            conn.execute("INSERT OR REPLACE INTO accepted_ports (mac, port, accepted_at) VALUES (?, ?, ?)",
                         (mac, port, now_iso()))
        else:
            conn.execute("DELETE FROM accepted_ports WHERE mac = ? AND port = ?", (mac, port))
        return True


def get_accepted_ports():
    """{(mac, port), ...}"""
    with get_connection() as conn:
        return {(mac, port) for mac, port in conn.execute("SELECT mac, port FROM accepted_ports")}


def get_events(limit=100, mac=None):
    """Newest first. Each event: {id, ts, kind, mac, ip, detail, name}."""
    limit = max(1, min(int(limit), 1000))
    query = ("SELECT e.id, e.ts, e.kind, e.mac, e.ip, e.detail, COALESCE(d.name, '') "
             "FROM events e LEFT JOIN devices d ON d.mac = e.mac")
    params = []
    if mac:
        query += " WHERE e.mac = ?"
        params.append(mac)
    query += " ORDER BY e.id DESC LIMIT ?"
    params.append(limit)
    with get_connection() as conn:
        rows = conn.execute(query, params).fetchall()
    keys = ("id", "ts", "kind", "mac", "ip", "detail", "name")
    return [dict(zip(keys, row)) for row in rows]


def prune_events(keep=MAX_EVENTS):
    with get_connection() as conn:
        conn.execute("DELETE FROM events WHERE id <= (SELECT MAX(id) FROM events) - ?", (keep,))
