import os
import subprocess


def send_notification(title, message):
    # Her durumda terminale yaz (\a bip sesi çıkarır)
    print(f"\a[ALERT] {title}: {message}")

    # Masaüstü bildirimi
    sudo_user = os.environ.get("SUDO_USER")
    try:
        if os.geteuid() == 0 and sudo_user:
            # Script sudo ile çalışıyor, bildirimi senin oturumuna göndermeliyiz
            uid = subprocess.check_output(["id", "-u", sudo_user], text=True).strip()
            command = [
                "sudo", "-u", sudo_user, "env",
                f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus",
                "notify-send", title, message,
            ]
        else:
            command = ["notify-send", title, message]

        subprocess.run(command, check=False, timeout=5)
    except Exception as error:
        print(f"(Desktop notification could not be sent: {error})")