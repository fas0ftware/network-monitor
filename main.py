import argparse
import os
import sys
import time

from alert import send_notification
from config import (
    DEFAULT_IP_RANGE,
    PORT_RESCAN_INTERVAL,
    SCAN_INTERVAL,
    normalize_ip_range,
)
from db import count_devices, create_tables, save_device, save_ports
from portscan import RISKY_PORTS, scan_ports
from scanner import scan

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


def run_round(ip_range, silent):
    for device in scan(ip_range):
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


def build_parser():
    parser = argparse.ArgumentParser(description="Ev ağı izleyici: ARP + port taraması.")
    parser.add_argument(
        "-r", "--range",
        default=os.environ.get("NETMON_IP_RANGE", DEFAULT_IP_RANGE),
        help=f"taranacak alt ağ (varsayılan: {DEFAULT_IP_RANGE}, ya da NETMON_IP_RANGE)",
    )
    parser.add_argument(
        "-i", "--interval", type=int, default=SCAN_INTERVAL,
        help=f"iki tarama arası saniye (varsayılan: {SCAN_INTERVAL})",
    )
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)

    try:
        ip_range = normalize_ip_range(args.range)
    except ValueError as error:
        print(f"Hata: {error}", file=sys.stderr)
        return 2
    if args.interval < 5:
        print("Hata: tarama aralığı en az 5 saniye olmalı.", file=sys.stderr)
        return 2

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print(
            "Hata: ARP taraması root yetkisi ister. Şöyle çalıştır:\n"
            "  sudo venv/bin/python main.py",
            file=sys.stderr,
        )
        return 1

    create_tables()
    first_run = count_devices() == 0

    if first_run:
        print("Veritabanı boş: ilk tur sessiz, cihazlar 'bilinen' olarak kaydedilecek.")
    print(f"{ip_range} her {args.interval} saniyede bir taranacak. Durdurmak için Ctrl+C.")

    try:
        while True:
            print(f"[{time.strftime('%H:%M:%S')}] taranıyor...")
            try:
                run_round(ip_range, silent=first_run)
                first_run = False
            except Exception as error:  # geçici ağ hatası programı kapatmasın
                print(f"  Tarama başarısız, sonraki turda tekrar denenecek: {error}")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nDurduruldu.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
