"""Shared settings and input checks (no heavy dependencies, easy to test)."""

import ipaddress
import os
from datetime import timedelta

__version__ = "2.0.0"

DEFAULT_IP_RANGE = "192.168.1.0/24"
SCAN_INTERVAL = 60               # seconds between two network scans
PORT_RESCAN_INTERVAL = 30 * 60   # a device's ports are rescanned at most this often

# The scan runs every 60 s, so a device unseen for 3 minutes counts as offline.
ONLINE_TIMEOUT = timedelta(minutes=3)

# /20 = 4096 addresses: plenty for a home network, and it stops an accidental huge scan.
MIN_PREFIX_LENGTH = 20

# Dashboard
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000


def normalize_ip_range(value):
    """Validate a subnet and return it in canonical form.

    "192.168.1.6/24" becomes "192.168.1.0/24". Raises ValueError for anything
    that is not an IPv4 network of a sensible size.
    """
    try:
        network = ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        raise ValueError(f"'{value}' is not a valid network, use a form like 192.168.1.0/24")

    if network.version != 4:
        raise ValueError("Only IPv4 networks can be scanned (ARP is IPv4 only).")
    if network.prefixlen < MIN_PREFIX_LENGTH:
        raise ValueError(
            f"{network} is too large; use /{MIN_PREFIX_LENGTH} or a smaller network."
        )
    return str(network)


def is_loopback_host(host):
    if host in ("localhost", ""):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def env(name, default=""):
    return os.environ.get(name, default).strip()
