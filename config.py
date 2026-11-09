"""Shared settings and input checks (no heavy dependencies, easy to test)."""

import ipaddress

DEFAULT_IP_RANGE = "192.168.1.0/24"
SCAN_INTERVAL = 60  # iki tarama arası saniye
PORT_RESCAN_INTERVAL = 30 * 60  # aynı cihazın portları en fazla bu sıklıkla taranır

# /20 = 4096 adres. Ev ağı için fazlasıyla yeter, yanlışlıkla dev bir aralık taranmasın.
MIN_PREFIX_LENGTH = 20


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
