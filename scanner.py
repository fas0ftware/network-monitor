from scapy.all import ARP, Ether, srp, conf


def vendor_bul(mac):
    # Scapy'nin içindeki üretici veritabanından MAC'e bakar
    try:
        ad = conf.manufdb._get_manuf(mac)
        if ad and ad != mac:
            return ad
    except Exception:
        pass
    return "Bilinmiyor"


def scan(ip_range, deneme=3):
    bulunan = {}

    # Birkaç kez tarayıp sonuçları birleştiriyoruz, uyuyan cihazlar kaçmasın
    for _ in range(deneme):
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
        answered, _ = srp(packet, timeout=4, verbose=False)

        for sent, received in answered:
            bulunan[received.psrc] = received.hwsrc

    devices = []
    for ip, mac in bulunan.items():
        devices.append({"ip": ip, "mac": mac, "vendor": vendor_bul(mac)})
    return devices