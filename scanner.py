from scapy.all import ARP, Ether, srp, conf


def is_randomized(mac):
    """Locally administered MAC (bit 1 of the first byte): phones' private Wi-Fi addresses."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0b10)
    except (ValueError, IndexError):
        return False


def find_vendor(mac):
    if is_randomized(mac):
        return "Private (randomized MAC)"
    # Look the MAC prefix up in Scapy's bundled manufacturer database
    try:
        name = conf.manufdb._get_manuf(mac)
    except Exception:  # missing or broken manufacturer database
        return "Unknown"
    return name if name and name != mac else "Unknown"


def scan(ip_range, retries=3):
    found = {}

    # Merge several passes so devices that are asleep are less likely to be missed
    for _ in range(retries):
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
        answered, _unanswered = srp(packet, timeout=4, verbose=False)

        for _sent, received in answered:
            found[received.psrc] = received.hwsrc

    devices = []
    for ip, mac in found.items():
        devices.append({"ip": ip, "mac": mac, "vendor": find_vendor(mac)})
    return devices