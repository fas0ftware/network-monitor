from scapy.all import ARP, Ether, srp


def scan(ip_range):
    # Ağdaki herkese "bu IP kimde?" diye soran paket hazırla
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)

    # Paketi gönder, 2 saniye cevap bekle
    answered, _ = srp(packet, timeout=2, verbose=False)

    devices = []
    for sent, received in answered:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})
    return devices


if __name__ == "__main__":
    ip_range = "192.168.1.6/24"
    print(f"{ip_range} taranıyor...")

    for device in scan(ip_range):
        print(f"IP: {device['ip']:<16} MAC: {device['mac']}")