"""Güvenlik bilgi tabanı.

Her açık port için şunları söyler: bu port ne, neden riskli, nasıl kapatılır ya da
güvene alınır, kapandığı nasıl doğrulanır. Ayrıca ağın genel güvenlik skorunu hesaplar.

Adımlarda "$ " ile başlayan satırlar komuttur (panelde kopyalanabilir kutu olur).
Metinlerdeki {ip}, {port} ve {subnet} yer tutucularını panel, seçilen cihaza göre doldurur.
"""

RISK_LEVELS = ["info", "low", "medium", "high", "critical"]
RISK_RANK = {level: rank for rank, level in enumerate(RISK_LEVELS)}

# Skor 100'den başlar; onaylanmamış her açık port ve her güvenilmeyen cihaz puan düşürür
RISK_PENALTY = {"info": 0, "low": 2, "medium": 6, "high": 14, "critical": 25}
UNTRUSTED_PENALTY = 4
MAX_UNTRUSTED_PENALTY = 20

RISKY_LEVELS = {"high", "critical"}


def _group(where, *steps):
    return {"where": where, "steps": list(steps)}


def _entry(name, risk, what, why, fix, firewall=True):
    return {"name": name, "risk": risk, "what": what, "why": why, "fix": fix, "firewall": firewall}


def _telnet(port):
    return _entry(
        "Telnet", "critical",
        "Uzak cihaza komut satırıyla bağlanma protokolü. Eski router, kamera, yazıcı ve ucuz IoT cihazlarında sık görülür.",
        "Telnet her şeyi, kullanıcı adı ve şifre dahil, şifrelemeden düz metin olarak gönderir; aynı ağdaki biri dinleyerek şifreyi okuyabilir. "
        "Üstelik Telnet'li IoT cihazlar çoğu zaman varsayılan şifreyle gelir ve Mirai gibi botnet'lerin ilk hedefidir. Bu yüzden bu listedeki en tehlikeli portlardan biri.",
        [
            _group(
                "Router / kamera / IoT cihaz",
                "Cihazın yönetim panelini aç (genelde http://{ip}) ve Telnet'i kapat. Menü adı çoğunlukla Yönetim, Servisler veya Uzaktan Erişim altındadır.",
                "Kapatma seçeneği yoksa en son firmware'i yükle; yeni sürümlerde Telnet çoğu zaman kapalı gelir.",
                "Hiçbir şekilde kapatamıyorsan cihazı router'ın konuk/IoT ağına taşı ya da değiştir. Telnet'i kapatılamayan cihaz bakımsız demektir.",
                "Cihazın varsayılan şifresini hemen değiştir; Telnet kapanana kadar bu tek savunman.",
            ),
            _group(
                "Linux",
                "Telnet sunucusunu durdur ve açılışta başlamasını engelle:",
                "$ sudo systemctl disable --now telnet.socket",
                "xinetd veya inetd kullanıyorsan onu da kontrol et:",
                "$ sudo systemctl disable --now xinetd",
                "Uzaktan bağlanman gerekiyorsa Telnet yerine SSH kullan.",
            ),
            _group(
                "Windows",
                "Hizmetler uygulamasını aç (Win+R, sonra services.msc yaz), 'Telnet' hizmetini bul, Başlangıç türünü 'Devre dışı' yap ve durdur.",
            ),
        ],
    )


def _web_alt(port, name_hint):
    return _entry(
        name_hint, "medium",
        "Genellikle bir geliştirme sunucusu ya da alternatif web yönetim arayüzü: Python/Django/Flask sunucusu, bir proxy, NAS veya kamera paneli olabilir.",
        "Geliştirme sunucuları internete ya da yerel ağa açılmak için tasarlanmadı. 'python -m http.server' bulunduğu klasörün bütün dosyalarını herkese listeler; "
        "hata ayıklama (debug) modu açık bir Flask veya Django uygulaması ele geçirilebilir. Cihaz panelleriyse çoğu zaman varsayılan şifreyle durur.",
        [
            _group(
                "Önce ne olduğunu bul",
                "Tarayıcıda http://{ip}:{port} adresini aç ve ne çıktığına bak.",
                "Bu senin bilgisayarındaysa hangi programın açtığını bul:",
                "$ sudo ss -tulpn | grep :{port}",
            ),
            _group(
                "Kendi geliştirme sunucunsa",
                "Sunucuyu sadece kendi bilgisayarına bağla, ağdan erişilmesin:",
                "$ python3 -m http.server {port} --bind 127.0.0.1",
                "Flask uygulamasında host='127.0.0.1' kullan ve debug=False yap. Django'da 'python manage.py runserver 127.0.0.1:{port}' kullan.",
                "İşin bitince sunucuyu kapat (Ctrl+C).",
            ),
            _group(
                "Router / NAS / kamera paneliyse",
                "Varsayılan şifreyi değiştir, firmware'i güncelle.",
                "Panel için HTTPS seçeneği varsa onu kullan ve router'da uzaktan yönetimi kapat.",
            ),
        ],
    )


def _database(name, port, default_risk, why_extra, fix_groups):
    return _entry(
        name, default_risk,
        f"{name} veritabanı sunucusu. Uygulamaların verisini tutar; normalde sadece aynı bilgisayardaki uygulamalar bağlanmalıdır.",
        "Veritabanı ağa açıkken saldırgan parola dener, zayıf ya da boş şifreli hesaplara girer ve tüm veriyi okuyup silebilir. " + why_extra,
        fix_groups,
    )


ENTRIES = {
    21: _entry(
        "FTP", "high",
        "Dosya aktarım protokolü. NAS, router USB paylaşımı, kamera ve eski sunucularda görülür.",
        "FTP kullanıcı adı ve şifreyi şifrelemeden gönderir; aynı ağdaki biri trafiği dinleyerek şifreni okuyabilir. "
        "Anonim giriş açıksa şifre bile gerekmeden dosyalara erişilebilir.",
        [
            _group(
                "Linux",
                "FTP sunucusunu kullanmıyorsan durdur ve kapat (servis adı vsftpd, proftpd veya pure-ftpd olabilir):",
                "$ sudo systemctl disable --now vsftpd",
                "Dosya aktarımı lazımsa FTP yerine SFTP kullan; SSH açıksa ek kurulum gerekmez:",
                "$ sftp kullanici@{ip}",
            ),
            _group(
                "Windows",
                "Denetim Masası, Programlar, 'Windows özelliklerini aç veya kapat' bölümüne gir. Internet Information Services altındaki 'FTP Sunucusu' kutusunun işaretini kaldır.",
            ),
            _group(
                "Router / NAS / kamera",
                "Cihaz panelinde FTP hizmetini kapat; SFTP veya SMB seçeneği varsa onu kullan.",
                "Anonim (misafir) girişi mutlaka kapat.",
            ),
        ],
    ),
    22: _entry(
        "SSH", "medium",
        "Uzak cihaza şifreli komut satırı erişimi. Linux sunucular, Raspberry Pi, NAS ve bazı router'larda bulunur.",
        "SSH güvenli bir protokol, risk zayıf şifre ve değiştirilmemiş varsayılan hesaplardır. Port internete açıksa şifre deneme saldırıları dakikalar içinde başlar. "
        "Kullanıyorsan sorun yok, ama düzgün yapılandırılmalı. Kullanmıyorsan kapat.",
        [
            _group(
                "Kullanmıyorsan (Linux)",
                "SSH servisini kapat (Debian/Ubuntu'da adı ssh, Fedora/Arch'ta sshd):",
                "$ sudo systemctl disable --now ssh",
            ),
            _group(
                "Kullanıyorsan: şifre yerine anahtarla gir",
                "Önce anahtar üret ve sunucuya kopyala:",
                "$ ssh-keygen -t ed25519",
                "$ ssh-copy-id kullanici@{ip}",
                "ÖNEMLİ: Başka bir terminalde anahtarla girişin çalıştığını doğrula. Doğrulamadan şifreyi kapatırsan kendini dışarıda bırakabilirsin.",
                "Sonra /etc/ssh/sshd_config dosyasında şu satırları ayarla:",
                "$ PasswordAuthentication no",
                "$ PermitRootLogin no",
                "$ sudo systemctl restart ssh",
            ),
            _group(
                "Kullanıyorsan: erişimi sınırla",
                "Sadece yerel ağdan bağlanmaya izin ver. Uzaktan (SSH ile) bağlıysan önce allow kuralını ekle, sonra enable et:",
                "$ sudo ufw allow from {subnet} to any port 22 proto tcp",
                "$ sudo ufw enable",
                "Şifre denemelerini otomatik engellemek için:",
                "$ sudo apt install fail2ban",
            ),
            _group(
                "Raspberry Pi / NAS / router",
                "Varsayılan şifreyi değiştir:",
                "$ passwd",
                "NAS veya router panelinde SSH'ye ihtiyacın yoksa kapat.",
            ),
        ],
    ),
    23: _telnet(23),
    2323: _telnet(2323),
    53: _entry(
        "DNS", "low",
        "Alan adı çözümleme servisi. Router'larda ve Pi-hole, dnsmasq çalıştıran cihazlarda bulunması normaldir.",
        "Yerel ağda tehlikesi düşüktür. Asıl risk iki şey: DNS'in internete açık kalması (açık çözümleyiciler DDoS saldırılarında alet olarak kullanılır) "
        "ve DNS ayarlarının değiştirilmesi (DNS hijack): saldırgan router'ın DNS adresini kendi sunucusuyla değiştirirse seni sahte sitelere yönlendirebilir.",
        [
            _group(
                "Router",
                "Router panelinde 'WAN'dan erişim' veya 'uzaktan yönetim' kapalı olsun.",
                "DNS ayarlarına bak (birincil/ikincil DNS). Tanımadığın bir adres görüyorsan router ele geçirilmiş olabilir: şifreyi değiştir, firmware'i güncelle, DNS'i bilinen güvenilir bir sunucuya geri al.",
            ),
            _group(
                "Linux (dnsmasq / Pi-hole)",
                "Hangi programın açtığını doğrula:",
                "$ sudo ss -tulpn | grep :53",
                "dnsmasq'i sadece yerel arayüzde dinlet, /etc/dnsmasq.conf içine:",
                "$ interface=eth0",
                "$ bind-interfaces",
            ),
        ],
    ),
    80: _entry(
        "HTTP (web arayüzü)", "medium",
        "Web arayüzü. Router, kamera, yazıcı, NAS ve akıllı priz gibi cihazların yönetim paneli genelde burada çalışır.",
        "HTTP şifrelenmez: panele girerken yazdığın şifre ağda düz metin gider. Birçok cihazda varsayılan şifre (admin/admin gibi) hiç değiştirilmemiştir "
        "ve yönetim panelleri çoğu zaman güncellenmeyen eski yazılım çalıştırır.",
        [
            _group(
                "Önce ne olduğunu bul",
                "Tarayıcıda http://{ip} adresini aç ve hangi cihazın paneli olduğuna bak.",
            ),
            _group(
                "Cihaz paneliyse",
                "Varsayılan şifreyi değiştir; her cihaza farklı, uzun bir şifre koy.",
                "Panelde HTTPS seçeneği varsa kullan (443 veya 8443).",
                "Firmware güncellemesi varsa kur.",
                "Router'da 'uzaktan yönetim' ve UPnP'yi kapat; böylece panel internetten görünmez.",
            ),
            _group(
                "Kendi web sunucunsa (Linux)",
                "Kullanmıyorsan kapat (nginx veya apache2):",
                "$ sudo systemctl disable --now nginx",
            ),
        ],
    ),
    111: _entry(
        "rpcbind", "medium",
        "RPC port eşleyici. NFS dosya paylaşımıyla birlikte çalışır.",
        "Hangi RPC servislerinin çalıştığını herkese söyler ve geçmişte DDoS yansıtma saldırılarında kullanıldı. NFS kullanmıyorsan bu servise ihtiyacın yok.",
        [
            _group(
                "Linux",
                "NFS kullanmıyorsan kapat:",
                "$ sudo systemctl disable --now rpcbind.service rpcbind.socket",
            ),
        ],
    ),
    139: _entry(
        "NetBIOS", "high",
        "Windows dosya ve yazıcı paylaşımının eski taşıma yolu (NetBIOS Oturum Servisi).",
        "Eski bir protokol: ağdaki bilgisayar ve paylaşım isimlerini ifşa eder ve SMB ile aynı saldırı yüzeyini paylaşır. Modern ağlarda gerekmez. "
        "Genellikle 445 ile birlikte çıkar; aynı çözümler geçerli.",
        [
            _group(
                "Windows",
                "Ağ bağdaştırıcı özelliklerini aç, IPv4 seç, Gelişmiş, WINS sekmesi, 'NetBIOS over TCP/IP'yi devre dışı bırak'ı işaretle.",
                "Dosya paylaşımına ihtiyacın yoksa: Ayarlar, Ağ ve İnternet, Gelişmiş paylaşım ayarları, 'Dosya ve yazıcı paylaşımı'nı kapat.",
            ),
            _group(
                "Linux (Samba)",
                "$ sudo systemctl disable --now nmbd",
                "Kullanmaya devam edeceksen /etc/samba/smb.conf içinde [global] bölümüne şunu ekle:",
                "$ disable netbios = yes",
            ),
        ],
    ),
    443: _entry(
        "HTTPS", "low",
        "Şifreli web arayüzü. Router, NAS ve kamera panelleri ya da web siteleri.",
        "Şifrelemenin kendisi iyi bir şey; risk panelin kendisinde: varsayılan şifre, eski yazılım sürümü ve kendi imzaladığı (self-signed) sertifikaya körü körüne güvenmek.",
        [
            _group(
                "Kontrol listesi",
                "Tarayıcıda https://{ip} aç, hangi cihaz olduğunu doğrula.",
                "Varsayılan şifre değişmiş mi bak, firmware güncel mi kontrol et.",
                "Panel internete açık olmasın: router'da port yönlendirme (Port Forwarding) listesinde bu cihazı gösteren bir kural varsa kaldır.",
            ),
        ],
        firewall=False,
    ),
    445: _entry(
        "SMB (Windows dosya paylaşımı)", "high",
        "Windows (ve Samba) dosya ve yazıcı paylaşımı. NAS cihazları ve router USB paylaşımları da SMB kullanır.",
        "WannaCry ve EternalBlue gibi büyük salgınlar SMB açıklarından yayıldı. Eski SMBv1 açıksa ve cihaz yamalı değilse tüm ağ risk altındadır. "
        "Ayrıca şifresiz veya herkese açık paylaşımlardan dosyalar sızar.",
        [
            _group(
                "Windows (yönetici PowerShell)",
                "SMBv1 açık mı bak:",
                "$ Get-SmbServerConfiguration | Select EnableSMB1Protocol",
                "Açıksa kapat:",
                "$ Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
                "Hangi klasörleri paylaştığını listele:",
                "$ Get-SmbShare",
                "Kendi oluşturduğun ve artık kullanmadığın paylaşımı kaldır:",
                "$ Remove-SmbShare -Name PaylasimAdi",
                "Ağ türünü 'Genel' yap: Ayarlar, Ağ ve İnternet, ağ özellikleri, Genel ağ. Böylece dosya paylaşımı varsayılan olarak kapalı kalır.",
            ),
            _group(
                "Linux (Samba)",
                "Kullanmıyorsan kapat:",
                "$ sudo systemctl disable --now smbd nmbd",
                "Kullanıyorsan /etc/samba/smb.conf dosyasında [global] bölümüne şunları ekle, paylaşımlarda 'guest ok = no' olduğundan emin ol:",
                "$ server min protocol = SMB2",
                "$ hosts allow = 127.0.0.1 {subnet}",
                "$ sudo systemctl restart smbd",
            ),
            _group(
                "macOS",
                "Sistem Ayarları, Genel, Paylaşım bölümünde 'Dosya Paylaşımı'nı kapat.",
            ),
            _group(
                "NAS / router",
                "SMB1 seçeneğini kapat, misafir/anonim erişimi kapat, her paylaşıma kullanıcı şifresi koy.",
            ),
        ],
    ),
    554: _entry(
        "RTSP (kamera yayını)", "medium",
        "IP kameraların canlı görüntü yayın portu.",
        "Birçok ucuz kamerada yayın şifresiz açıktır ya da varsayılan şifre kullanılır. Yayına erişen biri evini izleyebilir. Bu bir gizlilik meselesi, yani riskin gerçek boyutu kamerana bağlı.",
        [
            _group(
                "Önce test et (kendi kameranda)",
                "VLC'de Medya, Ağ Akışını Aç bölümüne rtsp://{ip}:554/ yaz. Şifre sormadan görüntü geliyorsa kamera herkese açık demektir ve risk kritik seviyeye çıkar.",
            ),
            _group(
                "Kamera ayarları",
                "Kamera uygulamasında ya da panelinde kullanıcı adı ve şifre iste; varsayılan şifreyi değiştir.",
                "Firmware'i güncelle. Kameranı bulut üzerinden kullanıyorsan yerel RTSP'yi tamamen kapatabilirsin.",
                "Router'da kameraya yönelik bir port yönlendirme (Port Forwarding) kuralı varsa sil.",
                "Mümkünse kamerayı ayrı bir konuk/IoT ağına al.",
            ),
        ],
    ),
    631: _entry(
        "CUPS (yazıcı servisi)", "medium",
        "Linux ve macOS'un yazıcı yönetim servisi (CUPS).",
        "Yazıcı paylaşıyorsan gerekli, ama ağa açık CUPS servisinde geçmişte uzaktan kod çalıştırmaya varan açıklar bulundu (özellikle cups-browsed). "
        "Yazıcı paylaşmıyorsan servise ihtiyacın yok.",
        [
            _group(
                "Linux",
                "Yazıcı paylaşmıyorsan hepsini kapat:",
                "$ sudo systemctl disable --now cups-browsed",
                "$ sudo systemctl disable --now cups.socket cups.path cups.service",
                "Kullanmaya devam edeceksen /etc/cups/cupsd.conf içinde 'Listen localhost:631' kullan ve sistemi güncel tut.",
            ),
        ],
    ),
    1883: _entry(
        "MQTT", "medium",
        "Akıllı ev ve IoT cihazlarının mesajlaşma protokolü (Home Assistant, Mosquitto).",
        "Varsayılan MQTT kurulumları şifresiz ve şifrelenmemiştir. Bağlanan herkes cihazlardan gelen veriyi okuyabilir ve priz, lamba, kilit gibi cihazlara komut gönderebilir.",
        [
            _group(
                "Mosquitto (Linux)",
                "Anonim bağlantıyı kapat ve kullanıcı şifresi iste. /etc/mosquitto/mosquitto.conf dosyasına ekle:",
                "$ allow_anonymous false",
                "$ password_file /etc/mosquitto/passwd",
                "Kullanıcı oluştur ve servisi yeniden başlat:",
                "$ sudo mosquitto_passwd -c /etc/mosquitto/passwd kullanici",
                "$ sudo systemctl restart mosquitto",
                "Sadece aynı bilgisayardaki uygulamalar bağlanacaksa dinlemeyi yerel adrese kısıtla:",
                "$ listener 1883 127.0.0.1",
                "Ağdan bağlanacaksa TLS'li 8883 portunu kullan.",
            ),
        ],
    ),
    2049: _entry(
        "NFS", "medium",
        "Linux/Unix dosya paylaşım protokolü.",
        "NFS erişimi şifreyle değil IP adresiyle kontrol eder. '*' ile paylaşılmış bir klasörü ağdaki herkes bağlayıp okuyabilir, yazma izni varsa değiştirebilir.",
        [
            _group(
                "Linux",
                "Neyi paylaştığına bak:",
                "$ sudo exportfs -v",
                "/etc/exports dosyasında '*' yerine sadece güvendiğin IP'yi yaz ve 'ro' (salt okunur) tercih et. Kullanmıyorsan kapat:",
                "$ sudo systemctl disable --now nfs-server",
            ),
        ],
    ),
    2375: _entry(
        "Docker API (şifresiz)", "critical",
        "Docker servisinin ağdan açık yönetim arayüzü.",
        "Şifresiz Docker API'sine erişen herkes ana makinede, tüm dosya sistemine bağlı bir container başlatıp root yetkisiyle komut çalıştırabilir; yani bilgisayarın tamamen ele geçirilmesi demek. "
        "Hemen kapatılmalı.",
        [
            _group(
                "Linux",
                "Bu portu açan ayarı bul:",
                "$ grep -r 2375 /etc/docker /etc/systemd/system /lib/systemd/system 2>/dev/null",
                "'-H tcp://0.0.0.0:2375' ifadesini veya daemon.json içindeki 'tcp://' girişini sil. Docker varsayılanı sadece yerel unix soketidir.",
                "$ sudo systemctl daemon-reload",
                "$ sudo systemctl restart docker",
                "Başka bir bilgisayardan Docker'a erişmen gerekiyorsa API'yi açmak yerine SSH üzerinden bağlan:",
                "$ docker -H ssh://kullanici@{ip} ps",
            ),
        ],
    ),
    3306: _database(
        "MySQL / MariaDB", 3306, "medium",
        "Uygulama kullanıcıları '%' (her yerden) olarak tanımlıysa risk daha da büyür.",
        [
            _group(
                "Linux",
                "Sadece yerel bağlantıya izin ver. Yapılandırma dosyasında (genelde /etc/mysql/mysql.conf.d/mysqld.cnf) şunu ayarla:",
                "$ bind-address = 127.0.0.1",
                "$ sudo systemctl restart mysql",
                "Hangi hesapların uzaktan bağlanabildiğini kontrol et:",
                "$ SELECT user, host FROM mysql.user;",
                "host değeri '%' olan ve ihtiyacın olmayan hesapları sil, root'un şifresi olduğundan emin ol.",
            ),
        ],
    ),
    3389: _entry(
        "RDP (Uzak Masaüstü)", "high",
        "Windows Uzak Masaüstü. Bilgisayara ağ üzerinden görsel olarak bağlanmayı sağlar.",
        "RDP fidye yazılımı saldırılarının en sık kullandığı girişlerden biri: zayıf şifreler kaba kuvvetle denenir ve BlueKeep gibi açıklar bulundu. "
        "Portu router'dan internete yönlendirdiysen risk çok daha büyüktür.",
        [
            _group(
                "Kullanmıyorsan (Windows)",
                "Ayarlar, Sistem, Uzak Masaüstü bölümünde kapat. Komutla (yönetici):",
                "$ netsh advfirewall firewall set rule group=\"remote desktop\" new enable=No",
            ),
            _group(
                "Kullanıyorsan",
                "'Ağ Düzeyinde Kimlik Doğrulaması (NLA)' açık olsun; güçlü ve benzersiz şifre kullan.",
                "Router'da 3389 için port yönlendirme (Port Forwarding) kuralı varsa hemen sil; RDP'yi asla doğrudan internete açma. Uzaktan erişim için VPN kullan.",
                "Windows'u güncel tut ve Windows Defender Güvenlik Duvarı'nda RDP erişimini sadece yerel ağ adresleriyle sınırla.",
            ),
            _group(
                "Linux (xrdp)",
                "$ sudo systemctl disable --now xrdp",
            ),
        ],
    ),
    5000: _entry(
        "Port 5000 (UPnP / AirPlay / geliştirme sunucusu)", "medium",
        "Bu port farklı şeyler olabilir: macOS'un AirPlay Alıcısı, Synology NAS paneli, UPnP servisi ya da Flask geliştirme sunucusu.",
        "Ne çalıştığını bilmiyorsan risk bilinmeziyle başlar. Flask debug sunucuları ele geçirilebilir; açık AirPlay alıcısı komşunun ekranına yayın göndermesine izin verebilir.",
        [
            _group(
                "Önce ne olduğunu bul",
                "Tarayıcıda http://{ip}:{port} aç. Bilgisayarında şu komut hangi programın açtığını söyler:",
                "$ sudo ss -tulpn | grep :{port}",
            ),
            _group(
                "macOS",
                "Sistem Ayarları, Genel, AirDrop ve Handoff bölümünde 'AirPlay Alıcısı'nı kapat.",
            ),
            _group(
                "Flask / geliştirme sunucusu",
                "app.run(host='127.0.0.1', debug=False) kullan: sadece kendi bilgisayarın erişebilir.",
            ),
            _group(
                "NAS / router",
                "Panelde bu portu kullanan hizmeti bul. Kullanmıyorsan kapat; kullanıyorsan varsayılan şifreyi değiştir.",
            ),
        ],
    ),
    5353: _entry(
        "mDNS (Bonjour / Avahi)", "low",
        "Yerel ağda cihazların birbirini bulma servisi (Bonjour, Avahi). Yazıcı, Chromecast ve AirPlay bununla bulunur.",
        "Tehlikesi düşük ama cihazının adını, türünü ve bazen servislerini ağdaki herkese duyurur; bilgi toplamayı kolaylaştırır.",
        [
            _group(
                "Linux",
                "Yazıcı ve cihaz keşfine ihtiyacın yoksa kapat:",
                "$ sudo systemctl disable --now avahi-daemon.socket avahi-daemon.service",
            ),
        ],
    ),
    5432: _database(
        "PostgreSQL", 5432, "medium",
        "pg_hba.conf'ta herkese izin veren (0.0.0.0/0) bir satır varsa sunucu fiilen herkese açıktır.",
        [
            _group(
                "Linux",
                "postgresql.conf dosyasında sadece yerel dinlemeyi aç:",
                "$ listen_addresses = 'localhost'",
                "pg_hba.conf içinde '0.0.0.0/0' gibi geniş kuralları sil, sadece ihtiyacın olan IP'lere izin ver. Sonra:",
                "$ sudo systemctl restart postgresql",
            ),
        ],
    ),
    5555: _entry(
        "Android ADB (ağdan hata ayıklama)", "critical",
        "Android Debug Bridge ağ üzerinden açık. Android TV, TV kutusu, tablet ve telefonlarda görülür.",
        "Açık ADB, cihaza şifresiz bir kabuk (shell) erişimi verir: uygulama kurulur, dosya çalınır, cihaz botnet'e katılır. "
        "Bu port, internette aktif olarak taranan ve kullanılan zararlı yazılımların favori hedefi.",
        [
            _group(
                "Android cihazda",
                "Ayarlar, Geliştirici seçenekleri bölümünde 'USB hata ayıklama' ve 'Ağ üzerinden hata ayıklama / kablosuz hata ayıklama' seçeneklerini kapat. Geliştirici seçeneklerini tamamen kapatmak da mümkün.",
                "Bilgisayarına USB ile bağlıysa ADB'yi ağ modundan çıkar:",
                "$ adb usb",
            ),
            _group(
                "Ucuz TV kutusu / marka dışı cihaz",
                "Bazı cihazlar ADB açık ve kapatılamaz şekilde gelir. Kapatamıyorsan cihazı konuk/IoT ağına izole et ya da değiştir.",
            ),
        ],
    ),
    5900: _entry(
        "VNC (ekran paylaşımı)", "high",
        "Ekran paylaşımı ve uzaktan kontrol protokolü.",
        "VNC çoğu kurulumda zayıf şifreyle ve şifrelenmeden çalışır; bağlanan kişi ekranı görür, klavye ve fareyi kullanır. Şifre boşsa kimse sormadan içeri girer.",
        [
            _group(
                "Kullanmıyorsan",
                "macOS: Sistem Ayarları, Genel, Paylaşım bölümünde 'Ekran Paylaşımı'nı kapat.",
                "Linux: VNC servisini kapat (adı x11vnc, tigervnc ya da vncserver olabilir):",
                "$ sudo systemctl disable --now x11vnc",
            ),
            _group(
                "Kullanıyorsan",
                "VNC'ye doğrudan bağlanma; SSH tüneli kullan, böylece trafik şifrelenir ve VNC portu ağdan kapatılabilir:",
                "$ ssh -L 5901:localhost:5900 kullanici@{ip}",
                "Sonra VNC istemcisiyle localhost:5901 adresine bağlan. VNC servisini sadece 127.0.0.1'de dinletmek en güvenlisi.",
                "Güçlü bir VNC şifresi belirle.",
            ),
        ],
    ),
    6379: _entry(
        "Redis", "high",
        "Hızlı bir bellek içi veri deposu (önbellek, kuyruk).",
        "Redis varsayılan olarak şifresizdir ve yerel kullanım için tasarlanmıştır. Ağa açıksa herkes veriyi okuyup silebilir; yapılandırma komutlarıyla dosya yazarak komut çalıştırmaya bile ulaşılabilir.",
        [
            _group(
                "Linux",
                "/etc/redis/redis.conf içinde şunları ayarla:",
                "$ bind 127.0.0.1 ::1",
                "$ protected-mode yes",
                "$ requirepass GucluBirSifreYaz",
                "$ sudo systemctl restart redis-server",
                "Servis adı dağıtıma göre redis olabilir.",
            ),
        ],
    ),
    8000: _web_alt(8000, "Web (port 8000)"),
    8080: _web_alt(8080, "Web (port 8080)"),
    8443: _entry(
        "HTTPS alternatif (8443)", "low",
        "Alternatif şifreli web arayüzü; birçok NAS, kamera ve yönetim paneli bu portu kullanır.",
        "HTTPS olduğu için trafik şifreli; risk panelin kendisinde (varsayılan şifre, eski yazılım).",
        [
            _group(
                "Kontrol listesi",
                "https://{ip}:{port} adresini aç ve hangi cihaz olduğunu doğrula.",
                "Varsayılan şifreyi değiştir, firmware'i güncelle.",
                "Router'da bu cihaz için port yönlendirme kuralı varsa kaldır.",
            ),
        ],
        firewall=False,
    ),
    9100: _entry(
        "Yazıcı (RAW / JetDirect)", "medium",
        "Ağ yazıcılarının ham baskı portu.",
        "Bu porta bağlanan herkes kimlik doğrulaması olmadan yazıcıya iş gönderebilir. Bazı yazıcılarda bu porttan yapılandırma okunabilir, hafızadaki belgeler ele geçirilebilir. "
        "Yazıcı da bir bilgisayardır ve nadiren güncellenir.",
        [
            _group(
                "Yazıcı paneli",
                "Yazıcının web arayüzünü aç (http://{ip}) ve yönetici şifresi belirle.",
                "Yazıcın AirPrint/IPP destekliyorsa 'RAW 9100' baskıyı kapat.",
                "Firmware'i güncelle; kullanmadığın ağ servislerini (FTP, Telnet, SNMP) kapat.",
                "Yazıcıya erişebilecek IP'leri sınırlayan bir ayar (erişim listesi) varsa kullan.",
            ),
        ],
        firewall=False,
    ),
    27017: _entry(
        "MongoDB", "high",
        "NoSQL veritabanı sunucusu.",
        "Eski MongoDB sürümleri kimlik doğrulaması olmadan ve her arayüzde dinleyerek kuruluyordu; binlerce açık veritabanı silinip fidye notuyla değiştirildi.",
        [
            _group(
                "Linux",
                "/etc/mongod.conf dosyasında şunları ayarla:",
                "$ net:",
                "$   bindIp: 127.0.0.1",
                "$ security:",
                "$   authorization: enabled",
                "$ sudo systemctl restart mongod",
            ),
        ],
    ),
    62078: _entry(
        "iPhone / iPad (lockdownd)", "info",
        "Apple cihazlarının eşitleme servisi (iTunes/Finder Wi-Fi eşitlemesi).",
        "Bu port bir iPhone veya iPad'de normaldir ve kendi başına tehlike değildir. Cihazın bir Apple ürünü olduğunu gösterir.",
        [
            _group(
                "İstersen",
                "Finder veya iTunes'da 'Wi-Fi üzerinden bu iPhone ile eşitle' seçeneğini kapatabilirsin. Yapman gereken başka bir şey yok.",
            ),
        ],
        firewall=False,
    ),
}


VERIFY_STEPS = [
    "Servisi kapattıktan sonra bu araç portu en geç 30 dakika içinde (bir sonraki port taramasında) listeden siler. main.py'yi yeniden başlatırsan tarama hemen yapılır. Beklemeden kontrol etmek için:",
    "$ nc -zv {ip} {port}",
    "'Connection refused' veya zaman aşımı görüyorsan port kapanmıştır; 'succeeded' ya da 'Connected' görüyorsan hâlâ açıktır.",
]


def _firewall_group(port):
    return _group(
        "Servisi kapatamıyorsan: güvenlik duvarıyla engelle",
        "Aşağıdaki komutlar sadece portu açan cihazın kendisinde çalışır.",
        "Linux:",
        f"$ sudo ufw deny {port}/tcp",
        "Windows (yönetici):",
        f"$ netsh advfirewall firewall add rule name=\"Block {port}\" dir=in action=block protocol=TCP localport={port}",
        "Router, kamera, yazıcı gibi cihazlarda bu mümkün değildir; oradaki çözüm cihazın panelinden servisi kapatmak ya da cihazı ayrı bir ağa almaktır.",
    )


def _unknown_entry(port, service):
    label = service if service and service != "unknown" else "bilinmeyen servis"
    return {
        "name": f"Port {port} ({label})",
        "risk": "medium",
        "what": "Bu port bilgi tabanında yok. Hangi programın veya hizmetin açtığını bulman gerekiyor.",
        "why": "Ne olduğunu bilmediğin açık bir port, bilinmeyen bir kapı demektir. Çoğu zaman zararsız bir uygulamadır, ama kontrol etmeden emin olamazsın.",
        "fix": [
            _group(
                "Linux",
                "Portu hangi programın açtığını bul:",
                "$ sudo ss -tulpn | grep :{port}",
                "Kullanmadığın bir program ise durdur ve servisini kapat:",
                "$ sudo systemctl disable --now servis-adi",
            ),
            _group(
                "Windows",
                "Portu kullanan işlemin numarasını (PID) bul, sonra o numarayı programa çevir:",
                "$ netstat -ano | findstr :{port}",
                "$ tasklist /FI \"PID eq 1234\"",
            ),
            _group(
                "macOS",
                "$ sudo lsof -iTCP:{port} -sTCP:LISTEN",
            ),
            _group(
                "Router / kamera / IoT cihaz",
                "Cihazın panelinde bu portu kullanan servisi bul. Kullanmıyorsan kapat, kullanıyorsan varsayılan şifreyi değiştir ve firmware'i güncelle.",
            ),
        ],
        "firewall": True,
    }


def port_info(port, service="unknown"):
    """Panel çipleri için hafif bilgi: {"name": ..., "risk": ...}"""
    entry = ENTRIES.get(port)
    if entry:
        return {"name": entry["name"], "risk": entry["risk"]}
    unknown = _unknown_entry(port, service)
    return {"name": unknown["name"], "risk": unknown["risk"]}


def get_advice(port, service="unknown"):
    """Bir port için tam tavsiye: ne olduğu, neden riskli, nasıl kapatılır, nasıl doğrulanır."""
    entry = ENTRIES.get(port) or _unknown_entry(port, service)
    fix = list(entry["fix"])
    if entry["firewall"]:
        fix.append(_firewall_group(port))
    return {
        "port": port,
        "name": entry["name"],
        "risk": entry["risk"],
        "what": entry["what"],
        "why": entry["why"],
        "fix": fix,
        "verify": list(VERIFY_STEPS),
    }


def is_risky(port):
    return port_info(port)["risk"] in RISKY_LEVELS


def highest_risk(risks):
    """Verilen risk seviyelerinin en yükseği; liste boşsa (veya hepsi 'info') 'none' döner."""
    best = "none"
    best_rank = RISK_RANK["info"]
    for risk in risks:
        if RISK_RANK[risk] > best_rank:
            best, best_rank = risk, RISK_RANK[risk]
    return best


def score_label(score):
    if score >= 90:
        return "Güçlü"
    if score >= 70:
        return "İyi"
    if score >= 50:
        return "Dikkat"
    return "Riskli"


def build_summary(devices):
    """Cihaz listesinden ağın güvenlik özetini çıkarır.

    devices: app.get_devices() çıktısı. Her portta "risk" ve "accepted" alanları bulunur.
    Kullanıcının 'biliyorum, normal' dediği (accepted) portlar skora ve aksiyon listesine girmez.
    """
    counts = {level: 0 for level in RISK_LEVELS}
    penalty = 0
    untrusted = 0
    actions = []

    for device in devices:
        if not device["trusted"]:
            untrusted += 1
        for port in device["ports"]:
            if port["accepted"]:
                continue
            counts[port["risk"]] += 1
            penalty += RISK_PENALTY[port["risk"]]
            if RISK_RANK[port["risk"]] >= RISK_RANK["medium"]:
                actions.append({
                    "mac": device["mac"],
                    "ip": device["ip"],
                    "device_name": device["name"],
                    "port": port["port"],
                    "name": port["name"],
                    "risk": port["risk"],
                })

    penalty += min(untrusted * UNTRUSTED_PENALTY, MAX_UNTRUSTED_PENALTY)
    score = max(0, 100 - penalty)

    actions.sort(key=lambda a: (-RISK_RANK[a["risk"]], a["ip"], a["port"]))

    return {
        "score": score,
        "label": score_label(score),
        "counts": counts,
        "untrusted_devices": untrusted,
        "top_actions": actions[:3],
        "penalties": {
            "per_port": RISK_PENALTY,
            "per_untrusted_device": UNTRUSTED_PENALTY,
            "untrusted_cap": MAX_UNTRUSTED_PENALTY,
        },
    }
