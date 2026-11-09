import socket
from concurrent.futures import ThreadPoolExecutor

# Ev ağında işe yarayan yaygın portlar; 65535 portun hepsini taramak gereksiz ve yavaş.
# Her portun açıklaması ve kapatma rehberi advisor.py içinde.
COMMON_PORTS = [
    21, 22, 23, 53, 80, 111, 139, 443, 445, 554, 631, 1883,
    2049, 2323, 2375, 3306, 3389, 5000, 5353, 5432, 5555, 5900,
    6379, 8000, 8080, 8443, 9100, 27017, 62078,
]


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
    """Açık portları [(port, service), ...] olarak döner."""
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(lambda p: is_port_open(ip, p, timeout), ports)
    return [(p, get_service_name(p)) for p, is_open in zip(ports, results) if is_open]