import sqlite3
from datetime import datetime

DB_ADI = "devices.db"


def baglan():
    return sqlite3.connect(DB_ADI)


def tablo_olustur():
    with baglan() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                mac        TEXT PRIMARY KEY,
                ip         TEXT,
                vendor     TEXT,
                first_seen TEXT,
                last_seen  TEXT
            )
        """)


def cihaz_kaydet(device):
    """Cihaz yeniyse True, daha önce görülmüşse False döner."""
    simdi = datetime.now().isoformat(timespec="seconds")

    with baglan() as conn:
        var_mi = conn.execute(
            "SELECT 1 FROM devices WHERE mac = ?", (device["mac"],)
        ).fetchone()

        if var_mi:
            conn.execute(
                "UPDATE devices SET ip = ?, vendor = ?, last_seen = ? WHERE mac = ?",
                (device["ip"], device["vendor"], simdi, device["mac"]),
            )
            return False

        conn.execute(
            "INSERT INTO devices (mac, ip, vendor, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?)",
            (device["mac"], device["ip"], device["vendor"], simdi, simdi),
        )
        return True