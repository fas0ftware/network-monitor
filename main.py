import time

from alert import send_notification
from db import count_devices, create_tables, save_device, save_ports
from portscan import scan_ports
from scanner import scan

IP_RANGE = "192.168.1.6/24"
SCAN_INTERVAL = 60  # iki tarama arası saniye
PORT_RESCAN_INTERVAL = 30 * 60  # aynı cihazın portları en fazla bu sıklıkla taranır
RISKY_PORTS = {21, 23, 445, 3389, 5900}  # FTP, Telnet, SMB, RDP, VNC

# MAC -> en son port taramasının zamanı (program çalıştığı sürece tutulur)
last_port_scan = {}


def scan_device_ports(device, silent):
    mac = device["mac"]
    # Bu çalışmadaki ilk tarama "referans" olur, uyarı sadece sonraki taramalarda verilir
    has_baseline = mac in last_port_scan

    open_ports = scan_ports(device["ip"])
    new_ports = save_ports(mac, open_ports)
    last_port_scan[mac] = time.monotonic()

    if silent or not has_baseline:
        return

    services = dict(open_ports)
    for port in new_ports:
        risky = " (riskli!)" if port in RISKY_PORTS else ""
        text = f"{device['ip']} cihazında yeni açık port: {port}/{services[port]}{risky}"
        print(f"  YENİ PORT: {text}")
        send_notification("Ağda yeni açık port!", text)


def run_round(silent):
    for device in scan(IP_RANGE):
        is_new = save_device(device)
        if is_new:
            print(f"  YENİ: {device['ip']:<16} {device['mac']:<19} {device['vendor']}")
            if not silent:
                send_notification(
                    "Ağda yeni cihaz!",
                    f"{device['ip']} - {device['vendor']} ({device['mac']})",
                )

        last = last_port_scan.get(device["mac"])
        due = last is None or time.monotonic() - last >= PORT_RESCAN_INTERVAL
        if due:
            scan_device_ports(device, silent)


if __name__ == "__main__":
    create_tables()
    first_run = count_devices() == 0

    if first_run:
        print("Veritabanı boş: ilk tur sessiz, cihazlar 'bilinen' olarak kaydedilecek.")
    print(f"{IP_RANGE} her {SCAN_INTERVAL} saniyede bir taranacak. Durdurmak için Ctrl+C.")

    try:
        while True:
            print(f"[{time.strftime('%H:%M:%S')}] taranıyor...")
            run_round(silent=first_run)
            first_run = False
            time.sleep(SCAN_INTERVAL)
    except KeyboardInterrupt:
        print("\nDurduruldu.")