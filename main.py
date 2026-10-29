import time

from alert import bildirim_gonder
from db import cihaz_kaydet, cihaz_sayisi, tablo_olustur
from scanner import scan

IP_RANGE = "192.168.1.6/24"
ARALIK = 60  # iki tarama arası saniye


def tur_at(sessiz):
    for device in scan(IP_RANGE):
        yeni = cihaz_kaydet(device)
        if yeni:
            print(f"  YENİ: {device['ip']:<16} {device['mac']:<19} {device['vendor']}")
            if not sessiz:
                bildirim_gonder(
                    "Ağda yeni cihaz!",
                    f"{device['ip']} - {device['vendor']} ({device['mac']})",
                )


if __name__ == "__main__":
    tablo_olustur()
    ilk_tur = cihaz_sayisi() == 0

    if ilk_tur:
        print("Veritabanı boş: ilk tur sessiz, cihazlar 'bilinen' olarak kaydedilecek.")
    print(f"{IP_RANGE} her {ARALIK} saniyede bir taranacak. Durdurmak için Ctrl+C.")

    try:
        while True:
            print(f"[{time.strftime('%H:%M:%S')}] taranıyor...")
            tur_at(sessiz=ilk_tur)
            ilk_tur = False
            time.sleep(ARALIK)
    except KeyboardInterrupt:
        print("\nDurduruldu.")