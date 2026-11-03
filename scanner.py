from scapy.all import ARP, Ether, srp, conf


def find_vendor(mac):
    # Scapy'nin içindeki üretici veritabanından MAC'e bakar
    try:
        name = conf.manufdb._get_manuf(mac)
        if name and name != mac:
            return name
    except Exception:
        pass
    return "Bilinmiyor"


def scan(ip_range, retries=3):
    found = {}

    # Birkaç kez tarayıp sonuçları birleştiriyoruz, uyuyan cihazlar kaçmasın
    for _ in range(retries):
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
        answered, _unanswered = srp(packet, timeout=4, verbose=False)

        for _sent, received in answered:
            found[received.psrc] = received.hwsrc

    devices = []
    for ip, mac in found.items():
        devices.append({"ip": ip, "mac": mac, "vendor": find_vendor(mac)})
    return devices