import os
import subprocess


def bildirim_gonder(baslik, mesaj):
    # Her durumda terminale yaz (\a bip sesi çıkarır)
    print(f"\a[UYARI] {baslik}: {mesaj}")

    # Masaüstü bildirimi
    kullanici = os.environ.get("SUDO_USER")
    try:
        if os.geteuid() == 0 and kullanici:
            # Script sudo ile çalışıyor, bildirimi senin oturumuna göndermeliyiz
            uid = subprocess.check_output(["id", "-u", kullanici], text=True).strip()
            komut = [
                "sudo", "-u", kullanici, "env",
                f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus",
                "notify-send", baslik, mesaj,
            ]
        else:
            komut = ["notify-send", baslik, mesaj]

        subprocess.run(komut, check=False, timeout=5)
    except Exception as hata:
        print(f"(Masaüstü bildirimi gönderilemedi: {hata})")