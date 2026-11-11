"""Flask dashboard and JSON API for the home network monitor."""

import argparse
import csv
import hmac
import io
import os
import re
import sys
from datetime import datetime
from urllib.parse import urlencode

from flask import Flask, Response, jsonify, redirect, render_template, request

import db
from config import DEFAULT_HOST, DEFAULT_PORT, ONLINE_TIMEOUT, __version__, env, is_loopback_host
from portscan import RISKY_PORTS

MAC_PATTERN = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
TOKEN_COOKIE = "netmon_token"  # cookie name, not a secret  # nosec B105


def create_app(token=None, trusted_hosts=None):
    """Build the Flask app.

    token: if set, every API call needs it (cookie set by opening /?token=..., or
           an `Authorization: Bearer` header). Required when serving on the LAN.
    trusted_hosts: allowed Host headers; protects the localhost dashboard against
           DNS-rebinding attacks from malicious web pages.
    """
    app = Flask(__name__)
    app.config["TRUSTED_HOSTS"] = trusted_hosts or ["localhost", "127.0.0.1", "[::1]"]
    app.config["NETMON_TOKEN"] = token or ""
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

    def authorized():
        expected = app.config["NETMON_TOKEN"]
        if not expected:
            return True
        given = request.cookies.get(TOKEN_COOKIE, "")
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            given = auth[7:]
        return hmac.compare_digest(given.encode(), expected.encode())

    @app.before_request
    def guard():
        if request.path.startswith("/api/") and not authorized():
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        if request.method in ("POST", "DELETE") and request.path.startswith("/api/"):
            # Browsers always send Origin on cross-site POST/DELETE; reject other origins (CSRF).
            origin = request.headers.get("Origin")
            if origin and origin.rstrip("/") != request.host_url.rstrip("/"):
                return jsonify({"ok": False, "error": "cross-origin request refused"}), 403
        return None

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.route("/")
    def index():
        expected = app.config["NETMON_TOKEN"]
        given = request.args.get("token")
        if expected and given is not None:
            # Swap the token in the URL for an HttpOnly cookie, then drop it from the address bar
            keep = {k: v for k, v in request.args.items() if k == "mask"}
            response = redirect("/" + ("?" + urlencode(keep) if keep else ""))
            if hmac.compare_digest(given.encode(), expected.encode()):
                response.set_cookie(TOKEN_COOKIE, given, httponly=True, samesite="Strict",
                                    secure=request.is_secure, max_age=30 * 24 * 3600)
            return response
        return render_template("index.html", version=__version__,
                               locked=bool(expected) and not authorized())

    @app.route("/api/devices")
    def api_devices():
        return jsonify(get_devices())

    @app.route("/api/devices.csv")
    def api_devices_csv():
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(["name", "ip", "mac", "vendor", "trusted", "online", "open_ports",
                         "first_seen", "last_seen"])
        for d in get_devices():
            writer.writerow([_csv_safe(d["name"]), d["ip"], d["mac"], _csv_safe(d["vendor"]),
                             d["trusted"], d["online"],
                             " ".join(f"{p['port']}/{p['service']}" for p in d["ports"]),
                             d["first_seen"], d["last_seen"]])
        return Response(out.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=devices.csv"})

    @app.route("/api/events")
    def api_events():
        try:
            limit = int(request.args.get("limit", 100))
        except ValueError:
            return jsonify({"ok": False, "error": "limit must be a number"}), 400
        mac = request.args.get("mac")
        if mac is not None:
            mac = mac.lower()
            if not MAC_PATTERN.match(mac):
                return jsonify({"ok": False, "error": "invalid MAC address"}), 400
        return jsonify(db.get_events(limit, mac))

    @app.route("/api/devices/<mac>", methods=["POST"])
    def api_update_device(mac):
        mac = mac.lower()
        if not MAC_PATTERN.match(mac):
            return jsonify({"ok": False, "error": "invalid MAC address"}), 400

        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"ok": False, "error": "JSON body required"}), 400

        name = data.get("name", "")
        trusted = data.get("trusted", False)
        if not isinstance(name, str) or not isinstance(trusted, bool):
            return jsonify({"ok": False, "error": "name must be text, trusted true or false"}), 400

        if not db.update_device(mac, name.strip()[:50], trusted):
            return jsonify({"ok": False, "error": "unknown device"}), 404
        return jsonify({"ok": True})

    @app.route("/api/devices/<mac>", methods=["DELETE"])
    def api_delete_device(mac):
        mac = mac.lower()
        if not MAC_PATTERN.match(mac):
            return jsonify({"ok": False, "error": "invalid MAC address"}), 400
        if not db.delete_device(mac):
            return jsonify({"ok": False, "error": "unknown device"}), 404
        return jsonify({"ok": True})

    @app.route("/api/health")
    def api_health():
        return jsonify({"ok": True, "version": __version__})

    return app


def _csv_safe(value):
    """Stop spreadsheet formula injection (a device name like '=HYPERLINK(...)')."""
    text = str(value or "")
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def get_devices():
    with db.get_connection() as conn:
        rows = conn.execute(
            "SELECT mac, ip, vendor, first_seen, last_seen, name, trusted "
            "FROM devices ORDER BY last_seen DESC"
        ).fetchall()

    all_ports = db.get_all_ports()
    now = datetime.now()
    result = []
    for mac, ip, vendor, first, last, name, trusted in rows:
        online = now - datetime.fromisoformat(last) <= ONLINE_TIMEOUT
        ports = [{**entry, "risky": entry["port"] in RISKY_PORTS} for entry in all_ports.get(mac, [])]
        result.append({
            "mac": mac, "ip": ip, "vendor": vendor, "first_seen": first, "last_seen": last,
            "online": online, "name": name or "", "trusted": bool(trusted), "ports": ports,
        })
    return result


# Default instance (used by `flask run` and by the tests)
app = create_app(token=env("NETMON_TOKEN") or None)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Home network monitor dashboard.")
    parser.add_argument("--host", default=env("NETMON_HOST", DEFAULT_HOST),
                        help="address to listen on (default 127.0.0.1 = this computer only)")
    parser.add_argument("--port", type=int, default=int(env("NETMON_PORT", str(DEFAULT_PORT))))
    parser.add_argument("--demo", action="store_true",
                        help="serve a throw-away database filled with sample devices")
    args = parser.parse_args(argv)

    token = env("NETMON_TOKEN")
    hosts = ["localhost", "127.0.0.1", "[::1]"]
    if not is_loopback_host(args.host):
        if len(token) < 16:
            print("Refusing to listen on the network without NETMON_TOKEN (at least 16 characters).\n"
                  "Generate one with:  python -c \"import secrets; print(secrets.token_urlsafe(24))\"",
                  file=sys.stderr)
            return 2
        hosts = None  # LAN access: any Host header, the token protects the API
    if args.demo:
        import tempfile

        import demo
        db.DB_NAME = os.path.join(tempfile.mkdtemp(prefix="netmon-demo-"), "demo.db")
        demo.seed()
        print(f"Demo database: {db.DB_NAME}")
    else:
        db.create_tables()

    application = create_app(token=token or None, trusted_hosts=hosts)
    if hosts is None:
        application.config["TRUSTED_HOSTS"] = None
    print(f"Dashboard: http://{'localhost' if is_loopback_host(args.host) else args.host}:{args.port}/")
    application.run(host=args.host, port=args.port, debug=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
