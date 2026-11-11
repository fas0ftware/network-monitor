"""Network scanner loop: ARP discovery, port checks, alerts."""

import argparse
import os
import sys
import time

from alert import send_notification
from config import (
    DEFAULT_IP_RANGE,
    PORT_RESCAN_INTERVAL,
    SCAN_INTERVAL,
    __version__,
    normalize_ip_range,
)
from db import count_devices, create_tables, prune_events, save_device, save_ports
from portscan import RISKY_PORTS, scan_ports
from scanner import scan

# MAC -> time of the last port scan (kept while the program runs)
last_port_scan = {}


def scan_device_ports(device, silent):
    mac = device["mac"]
    # The first port scan of a device in this run is the baseline; alerts start from the second.
    has_baseline = mac in last_port_scan

    open_ports = scan_ports(device["ip"])
    new_ports = save_ports(mac, open_ports, ip=device["ip"], log=has_baseline)
    last_port_scan[mac] = time.monotonic()

    if silent or not has_baseline:
        return

    services = dict(open_ports)
    for port in new_ports:
        risky = " (risky!)" if port in RISKY_PORTS else ""
        text = f"{device['ip']} opened port {port}/{services[port]}{risky}"
        print(f"  NEW PORT: {text}")
        send_notification("New open port on your network", text)


def run_round(ip_range, silent):
    devices = scan(ip_range)
    for device in devices:
        is_new = save_device(device)
        if is_new:
            print(f"  NEW: {device['ip']:<16} {device['mac']:<19} {device['vendor']}")
            if not silent:
                send_notification(
                    "New device on your network",
                    f"{device['ip']} - {device['vendor']} ({device['mac']})",
                )

        last = last_port_scan.get(device["mac"])
        due = last is None or time.monotonic() - last >= PORT_RESCAN_INTERVAL
        if due:
            scan_device_ports(device, silent)
    prune_events()
    return len(devices)


def build_parser():
    parser = argparse.ArgumentParser(description="Home network monitor: ARP discovery + port checks.")
    parser.add_argument(
        "-r", "--range",
        default=os.environ.get("NETMON_IP_RANGE", DEFAULT_IP_RANGE),
        help=f"subnet to scan (default: {DEFAULT_IP_RANGE}, or NETMON_IP_RANGE)",
    )
    parser.add_argument(
        "-i", "--interval", type=int, default=SCAN_INTERVAL,
        help=f"seconds between scans (default: {SCAN_INTERVAL})",
    )
    parser.add_argument("--once", action="store_true", help="scan one round and exit")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)

    try:
        ip_range = normalize_ip_range(args.range)
    except ValueError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    if args.interval < 5:
        print("Error: the scan interval must be at least 5 seconds.", file=sys.stderr)
        return 2

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print(
            "Error: ARP scanning needs root. Run it like this:\n"
            "  sudo venv/bin/python main.py",
            file=sys.stderr,
        )
        return 1

    create_tables()
    first_run = count_devices() == 0

    if first_run:
        print("Empty database: the first round is silent, current devices are stored as known.")
    print(f"Scanning {ip_range} every {args.interval} seconds. Press Ctrl+C to stop.")

    try:
        while True:
            print(f"[{time.strftime('%H:%M:%S')}] scanning...")
            try:
                found = run_round(ip_range, silent=first_run)
                print(f"  {found} device(s) answered")
                first_run = False
            except Exception as error:  # a temporary network error must not stop the monitor
                print(f"  Scan failed, retrying next round: {error}")
            if args.once:
                return 0
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
