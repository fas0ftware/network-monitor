import socket
from concurrent.futures import ThreadPoolExecutor

# Ev ağında işe yarayan yaygın portlar; 65535 portun hepsini taramak gereksiz ve yavaş
COMMON_PORTS = [
    21, 22, 23, 53, 80, 139, 443, 445, 554, 1883,
    3389, 5000, 5353, 5900, 8000, 8080, 8443, 9100, 62078,
]

# Riskli sayılan servisler: FTP, Telnet, SMB, RDP, VNC (uyarılarda ve panelde işaretlenir)
RISKY_PORTS = {21, 23, 445, 3389, 5900}


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