import re
import secrets
from datetime import datetime, timedelta

from flask import Flask, abort, g, jsonify, render_template, request

from advisor import build_summary, get_advice, highest_risk, port_info
from db import (
    create_tables,
    get_accepted_ports,
    get_all_ports,
    get_connection,
    set_port_accepted,
    update_device,
)
from defense_guide import get_guide

app = Flask(__name__)

# Tarama 60 saniyede bir yapılıyor, 3 dakikadır görünmeyen cihaz çevrimdışı sayılır
ONLINE_TIMEOUT = timedelta(minutes=3)

# Panel sadece bu adreslerle açılır. Başka bir Host başlığı (ör. saldırgan bir sitenin
# kendi alan adını 127.0.0.1'e yönlendirmesi, "DNS rebinding") reddedilir.
ALLOWED_HOSTS = {"127.0.0.1", "localhost"}

MAC_PATTERN = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")


@app.before_request
def check_host_and_nonce():
    if request.host.split(":")[0] not in ALLOWED_HOSTS:
        abort(400)
    g.csp_nonce = secrets.token_urlsafe(16)


@app.after_request
def add_security_headers(response):
    nonce = getattr(g, "csp_nonce", "")
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; "
        f"script-src 'nonce-{nonce}'; "
        "style-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


def get_devices():
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT mac, ip, vendor, first_seen, last_seen, name, trusted "
            "FROM devices ORDER BY last_seen DESC"
        ).fetchall()

    all_ports = get_all_ports()
    accepted = get_accepted_ports()
    now = datetime.now()
    result = []
    for mac, ip, vendor, first, last, name, trusted in rows:
        online = now - datetime.fromisoformat(last) <= ONLINE_TIMEOUT

        ports = []
        for p in all_ports.get(mac, []):
            info = port_info(p["port"], p["service"])
            ports.append({
                "port": p["port"],
                "service": p["service"],
                "name": info["name"],
                "risk": info["risk"],
                "accepted": (mac, p["port"]) in accepted,
            })

        open_risks = [p["risk"] for p in ports if not p["accepted"]]
        result.append({
            "mac": mac,
            "ip": ip,
            "vendor": vendor,
            "first_seen": first,
            "last_seen": last,
            "online": online,
            "name": name or "",
            "trusted": bool(trusted),
            "ports": ports,
            "risk": highest_risk(open_risks),
        })
    return result


@app.route("/")
def index():
    return render_template("index.html", nonce=g.csp_nonce)


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


@app.route("/api/summary")
def api_summary():
    return jsonify(build_summary(get_devices()))


@app.route("/api/advice/<int:port>")
def api_advice(port):
    if not 1 <= port <= 65535:
        abort(404)
    service = request.args.get("service", "unknown")[:30]
    return jsonify(get_advice(port, service))


@app.route("/api/defense-guide")
def api_defense_guide():
    return jsonify(get_guide())


@app.route("/api/devices/<mac>/ports/<int:port>/accept", methods=["POST"])
def api_accept_port(mac, port):
    # JSON zorunlu: başka bir sitenin formu bu adrese gizlice POST atamasın
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not MAC_PATTERN.match(mac) or not 1 <= port <= 65535:
        abort(400)
    if not set_port_accepted(mac, port, bool(data.get("accepted", True))):
        abort(404)
    return jsonify({"ok": True})


if __name__ == "__main__":
    create_tables()
    # 127.0.0.1: panel sadece bu bilgisayardan açılır, ağdaki diğer cihazlar göremez
    app.run(host="127.0.0.1", port=5000, debug=False)
