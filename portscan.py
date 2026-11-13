import socket
from concurrent.futures import ThreadPoolExecutor

import advisor

# Common home-network ports; scanning all 65535 would be slow and pointless.
# Every port here has an entry in advisor.py (what it is, the risk, how to close it).
COMMON_PORTS = sorted(advisor.ENTRIES)

# High and critical ports (flagged in alerts and on the dashboard); kept here for older imports.
RISKY_PORTS = advisor.RISKY_PORTS


def is_port_open(ip, port, timeout=0.5):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((ip, port)) == 0


def get_service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def scan_ports(ip, ports=COMMON_PORTS, timeout=0.5, workers=50):
    """Return the open ports as [(port, service), ...]."""
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(lambda p: is_port_open(ip, p, timeout), ports)
    return [(p, get_service_name(p)) for p, is_open in zip(ports, results) if is_open]