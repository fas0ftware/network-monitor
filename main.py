from scanner import scan
from db import tablo_olustur, cihaz_kaydet

IP_RANGE = "192.168.1.0/24"

if __name__ == "__main__":
    tablo_olustur()
    print(f"{IP_RANGE} taranıyor...")

    for device in scan(IP_RANGE):
        yeni = cihaz_kaydet(device)
        durum = "YENİ CİHAZ" if yeni else "bilinen"
        print(f"[{durum:<10}] {device['ip']:<16} {device['mac']:<19} {device['vendor']}")