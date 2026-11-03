from datetime import datetime, timedelta

from flask import Flask, jsonify, render_template, request

from db import get_all_ports, get_connection, update_device

app = Flask(__name__)

# Tarama 60 saniyede bir yapılıyor, 3 dakikadır görünmeyen cihaz çevrimdışı sayılır
ONLINE_TIMEOUT = timedelta(minutes=3)


def get_devices():
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT mac, ip, vendor, first_seen, last_seen, name, trusted "
            "FROM devices ORDER BY last_seen DESC"
        ).fetchall()

    all_ports = get_all_ports()
    now = datetime.now()
    result = []
    for mac, ip, vendor, first, last, name, trusted in rows:
        online = now - datetime.fromisoformat(last) <= ONLINE_TIMEOUT
        result.append({
            "mac": mac,
            "ip": ip,
            "vendor": vendor,
            "first_seen": first,
            "last_seen": last,
            "online": online,
            "name": name or "",
            "trusted": bool(trusted),
            "ports": all_ports.get(mac, []),
        })
    return result


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/devices")
def api_devices():
    return jsonify(get_devices())


@app.route("/api/devices/<mac>", methods=["POST"])
def api_update_device(mac):
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()[:50]
    trusted = bool(data.get("trusted", False))
    update_device(mac, name, trusted)
    return jsonify({"ok": True})


if __name__ == "__main__":
    # 127.0.0.1: panel sadece bu bilgisayardan açılır, ağdaki diğer cihazlar göremez
    app.run(host="127.0.0.1", port=5000, debug=False)