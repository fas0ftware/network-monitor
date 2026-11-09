"""Ağını savunma rehberi: kontrol listesi ve "tanımadığım cihaz" planı.

Paneldeki "Ağını Savun" sekmesi bu veriyi /api/defense-guide üzerinden okur.
Kontrol listesindeki her maddenin id'si sabit kalmalı: işaretler tarayıcıda bu id ile saklanıyor.
"""


def _item(item_id, text, detail):
    return {"id": item_id, "text": text, "detail": detail}


CHECKLIST = [
    {
        "id": "router",
        "title": "Router (ağının kapısı)",
        "items": [
            _item(
                "router-admin-password",
                "Router yönetim şifresini değiştir",
                "Varsayılan admin/admin ya da cihazın altındaki etiketteki şifre herkesin bildiği şifredir. "
                "Tarayıcıda genelde 192.168.1.1 veya 192.168.0.1 adresinden panele gir, Yönetim veya Sistem bölümünden şifreyi değiştir. "
                "En az 12 karakter, başka hiçbir yerde kullanmadığın bir şifre seç.",
            ),
            _item(
                "router-wifi-encryption",
                "Wi-Fi şifrelemesi WPA3 veya WPA2-AES olsun",
                "WEP ve WPA/TKIP dakikalar içinde kırılabilir. Kablosuz ayarlarında güvenlik modunu WPA3 ya da WPA2-PSK (AES/CCMP) yap. "
                "Parola olarak 4-5 rastgele kelimeden oluşan uzun bir cümle hem akılda kalır hem kırılması zordur.",
            ),
            _item(
                "router-wps",
                "WPS'i kapat",
                "WPS'in PIN yöntemi kaba kuvvetle kırılabiliyor (Reaver, Pixie Dust saldırıları). Kablosuz ayarlarında WPS seçeneğini bul ve kapat. "
                "Cihazları parolayla bağlamak zaten kolay.",
            ),
            _item(
                "router-remote-admin",
                "Uzaktan yönetimi (WAN'dan erişim) kapat",
                "Router panelinin internetten açılabilmesi gerekmez. Yönetim bölümünde 'Uzaktan Yönetim', 'Remote Management' ya da 'WAN'dan erişim' seçeneğini kapat. "
                "Eve dışarıdan bağlanman gerekiyorsa router'ı internete açmak yerine VPN kur.",
            ),
            _item(
                "router-upnp-forwarding",
                "UPnP'yi ve port yönlendirme (Port Forwarding) listesini kontrol et",
                "UPnP, cihazların router'da kendiliğinden port açmasına izin verir; zararlı yazılım da bunu kullanabilir. "
                "Port Forwarding listesinde tanımadığın bir kural varsa sil. UPnP'ye ihtiyacın yoksa kapat; bazı oyunlar ve uygulamalar için gerekebilir, bozulursa açıp neyi açtığına bak.",
            ),
            _item(
                "router-firmware",
                "Router firmware'ini güncelle",
                "Router'lar nadiren güncellenir ve sürekli açık bulunur, bu yüzden saldırganların favori hedefidir. "
                "Panelde 'Firmware Güncelleme' bölümünü kontrol et. Üretici artık güncelleme yayınlamıyorsa router'ı değiştirmeyi düşün.",
            ),
            _item(
                "router-dns",
                "DNS ayarlarını kontrol et",
                "WAN/İnternet ayarlarında yazan DNS adreslerine bak. Tanımadığın bir adres varsa DNS hijack saldırısı olabilir: "
                "saldırgan seni sahte sitelere yönlendirir. Router şifresini değiştir, firmware'i güncelle ve DNS'i otomatik ya da bildiğin güvenilir bir sunucuya geri al.",
            ),
            _item(
                "router-guest-network",
                "IoT cihazlar ve misafirler için ayrı (konuk) ağ kur",
                "Kamera, akıllı priz ve TV gibi cihazlar nadiren güncellenir. Ele geçirilirlerse bilgisayar ve telefonuna ulaşamasınlar diye onları konuk ağına al. "
                "Not: Bu araç aynı ağdaki cihazları tarar; 'cihaz izolasyonu' açık bir konuk ağındaki cihazları göremeyebilirsin.",
            ),
        ],
    },
    {
        "id": "devices",
        "title": "Cihazların",
        "items": [
            _item(
                "devices-updates",
                "Tüm cihazlarda otomatik güncellemeyi aç",
                "Telefon, bilgisayar, TV ve yazıcıda güncellemeler çoğunlukla kapanmış güvenlik açıklarını yamar. "
                "Otomatik güncelleme seçeneği varsa aç. Güncelleme alamayan eski cihazları ağdan çıkarmayı düşün.",
            ),
            _item(
                "devices-firewall",
                "Bilgisayarlarda güvenlik duvarı açık olsun",
                "Linux: 'sudo ufw enable' (SSH ile bağlıysan önce 'sudo ufw allow 22/tcp' ekle). "
                "Windows: Windows Güvenliği, Güvenlik Duvarı ve ağ koruması. macOS: Sistem Ayarları, Ağ, Güvenlik Duvarı. "
                "Güvenlik duvarı, dışarıdan gelen bağlantıları varsayılan olarak engeller.",
            ),
            _item(
                "devices-close-services",
                "Kullanmadığın servisleri kapat (SSH, SMB, Telnet, VNC, RDP...)",
                "Bir servis çalışmıyorsa saldırılamaz. Paneldeki Cihazlar sekmesinde açık portlara tıkla: "
                "her portun yan panelinde ne olduğu ve nasıl kapatılacağı adım adım yazıyor.",
            ),
            _item(
                "devices-passwords",
                "Varsayılan şifreleri değiştir, şifre yöneticisi ve 2 adımlı doğrulama kullan",
                "Her cihaz ve hesap için farklı, uzun bir şifre kullan. Bunları akılda tutmak yerine bir şifre yöneticisine yaz. "
                "Mümkün olan her hesapta 2 adımlı doğrulamayı aç.",
            ),
            _item(
                "devices-cameras",
                "Kamera ve akıllı ev cihazlarını kontrol et",
                "Kameranın yayınının şifresiz açılıp açılmadığına bak (554 portu için yan paneldeki testi yap). "
                "Kameraların varsayılan şifresini değiştir ve mümkünse konuk/IoT ağına al.",
            ),
        ],
    },
    {
        "id": "monitoring",
        "title": "İzleme (bu araçla)",
        "items": [
            _item(
                "monitoring-name-devices",
                "Paneldeki tüm cihazlara isim ver ve güvenilir olarak işaretle",
                "Hangi cihazın hangisi olduğunu bilmek, yabancıyı fark etmenin ilk şartı. "
                "Cihazlar sekmesinde isim yaz, 'Güvenilir' kutusunu işaretle ve Kaydet'e bas.",
            ),
            _item(
                "monitoring-no-unknown",
                "Tanımadığın cihaz kalmasın",
                "Turuncu çizgiyle işaretli (güvenilir olmayan) her cihazı tanı. "
                "Tanıyamıyorsan aşağıdaki 'Tanımadığım bir cihaz gördüm' planını izle.",
            ),
            _item(
                "monitoring-review-ports",
                "Kritik ve yüksek riskli portları kapat ya da 'biliyorum' olarak işaretle",
                "Kırmızı ve turuncu port çiplerine tıkla. Gerekli olmayanı kapat. Gerçekten kullandığın bir servisse (ör. kendi SSH sunucun) güvene aldıktan sonra yan panelden 'Bunu biliyorum, normal' işaretle; skorundan düşmez.",
            ),
            _item(
                "monitoring-routine",
                "Aracı sürekli çalıştır, haftada bir paneli kontrol et",
                "Saldırıların çoğu bir kerelik değil, zamanla ortaya çıkar: yeni cihaz, yeni açılan port. "
                "main.py'yi sürekli çalışır bırak ve haftada bir paneli aç.",
            ),
        ],
    },
]


UNKNOWN_DEVICE_PLAYBOOK = {
    "title": "Tanımadığım bir cihaz gördüm, ne yapmalıyım?",
    "intro": "Panik yapma: tanımadığın cihazların çoğu zararsızdır. Sırayla şunları dene.",
    "steps": [
        {
            "title": "Önce rastgele MAC ihtimaline bak",
            "text": "Modern telefonlar ve bilgisayarlar her Wi-Fi ağı için rastgele (özel) bir MAC adresi kullanır. Kendi telefonun yeni bir cihaz gibi görünebilir. "
                    "MAC adresinin ilk bölümündeki ikinci karakter 2, 6, A veya E ise bu rastgele atanmış bir adrestir ve üretici 'Bilinmiyor' çıkar. Bu tek başına kötü bir işaret değil.",
        },
        {
            "title": "Üreticiye ve IP adresine bak",
            "text": "Üretici bilgisi (Samsung, TP-Link, Apple...) evdeki bir cihazla eşleşiyor mu? Evde o markadan ne var düşün: TV, süpürge, priz, kamera, yazıcı, oyun konsolu.",
        },
        {
            "title": "Cihazları tek tek kapatarak bul",
            "text": "Evdeki cihazların Wi-Fi'ını sırayla kapat ya da bağlantısını kes ve panelde hangisinin 'Çevrimdışı' olduğuna bak. Tanımadığın cihaz çevrimdışı olduysa onu buldun.",
        },
        {
            "title": "Router'ın bağlı cihaz listesine bak",
            "text": "Router panelinde 'Bağlı Cihazlar' veya 'DHCP İstemcileri' bölümünde cihazın adı (hostname) yazabilir. Bu ad çoğu zaman ne olduğunu söyler.",
        },
        {
            "title": "Hâlâ tanıyamadıysan: ağına kimin girebildiğini kes",
            "text": "Önce Wi-Fi şifresini değiştir; bağlı olan her cihaz düşer ve sadece şifreyi bilenler tekrar bağlanabilir. WPS'in kapalı olduğunu kontrol et. "
                    "Router'da o MAC'i engelle (MAC filtreleme) de yardımcı olur ama tek başına yeterli değil, çünkü MAC adresi taklit edilebilir. Asıl koruma şifreyi değiştirmektir.",
        },
        {
            "title": "Sonra yeniden düzenle",
            "text": "Şifre değişince kendi cihazlarını yeniden bağla ve panelde güvenilir olarak işaretle. Router şifresini ve firmware'ini de bu sırada kontrol et.",
        },
    ],
}


def get_guide():
    return {"checklist": CHECKLIST, "unknown_device_playbook": UNKNOWN_DEVICE_PLAYBOOK}
