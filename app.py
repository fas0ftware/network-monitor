from datetime import datetime, timedelta

from flask import Flask, jsonify, render_template

from db import baglan

app = Flask(__name__)

# Tarama 60 saniyede bir yapılıyor, 3 dakikadır görünmeyen cihaz çevrimdışı sayılır
CEVRIMICI_SURE = timedelta(minutes=3)


def cihazlari_getir():
    with baglan() as conn:
        satirlar = conn.execute(
            "SELECT mac, ip, vendor, first_seen, last_seen "
            "FROM devices ORDER BY last_seen DESC"
        ).fetchall()

    simdi = datetime.now()
    sonuc = []
    for mac, ip, vendor, ilk, son in satirlar:
        cevrimici = simdi - datetime.fromisoformat(son) <= CEVRIMICI_SURE
        sonuc.append({
            "mac": mac,
            "ip": ip,
            "vendor": vendor,
            "first_seen": ilk,
            "last_seen": son,
            "online": cevrimici,
        })
    return sonuc


@app.route("/")
def anasayfa():
    return render_template("index.html")


@app.route("/api/devices")
def api_devices():
    return jsonify(cihazlari_getir())


if __name__ == "__main__":
    # 127.0.0.1: panel sadece bu bilgisayardan açılır, ağdaki diğer cihazlar göremez
    app.run(host="127.0.0.1", port=5000, debug=False)