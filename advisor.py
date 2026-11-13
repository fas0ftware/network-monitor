"""Security knowledge base: what an open port is, why it matters, how to close it.

For every port the scanner checks, an entry says what usually runs there, why
it is (or is not) a risk, how to close or secure it per platform, and how to
check that it is closed. It also turns the device list into a network
security score.

In the fix steps, lines starting with "$ " are commands (the dashboard shows
them as copyable code). {ip}, {port} and {subnet} are filled in by the
dashboard for the selected device.
"""

import ipaddress
import math

RISK_LEVELS = ["info", "low", "medium", "high", "critical"]
RISK_RANK = {level: rank for rank, level in enumerate(RISK_LEVELS)}

# Every open port the owner has not acknowledged, and every untrusted device, adds
# penalty points. The score is 100 * exp(-points / SCORE_SCALE): the first problems
# cost the most, and a bad network still shows a number that moves when you fix
# things, instead of sitting at 0.
RISK_PENALTY = {"info": 0, "low": 2, "medium": 6, "high": 14, "critical": 25}
UNTRUSTED_PENALTY = 4
MAX_UNTRUSTED_PENALTY = 20
SCORE_SCALE = 80
# One open port at these levels caps the score, however clean the rest is:
# a network with an open Telnet is never "Good".
SCORE_CAP = {"critical": 39, "high": 69}

# Ports at these levels are flagged as "risky" (red chips, the Risky filter, alerts).
RISKY_LEVELS = {"high", "critical"}


def _group(where, *steps):
    return {"where": where, "steps": list(steps)}


def _entry(name, risk, what, why, fix, firewall=True):
    return {"name": name, "risk": risk, "what": what, "why": why, "fix": fix, "firewall": firewall}


def _telnet():
    return _entry(
        "Telnet", "critical",
        "Remote command-line login. Common on old routers, cameras, printers and cheap IoT devices.",
        "Telnet sends everything, user name and password included, in plain text: anyone on the network can read "
        "the password. IoT devices with Telnet often still have their factory password and are the first target "
        "of botnets such as Mirai. One of the most dangerous ports on this list.",
        [
            _group(
                "Router / camera / IoT device",
                "Open the device's admin page (usually http://{ip}) and turn Telnet off. It is often under "
                "Administration, Services or Remote access.",
                "If there is no switch for it, install the latest firmware; newer versions often ship with Telnet off.",
                "If it cannot be turned off at all, move the device to the router's guest/IoT network or replace it. "
                "A device whose Telnet cannot be disabled is not maintained.",
                "Change the device's default password now; until Telnet is gone it is your only defence.",
            ),
            _group(
                "Linux",
                "Stop the Telnet server and keep it from starting at boot:",
                "$ sudo systemctl disable --now telnet.socket",
                "If you use xinetd or inetd, check that too:",
                "$ sudo systemctl disable --now xinetd",
                "Use SSH instead of Telnet for remote logins.",
            ),
            _group(
                "Windows",
                "Open Services (Win+R, then services.msc), find 'Telnet', set Startup type to 'Disabled' and stop it.",
            ),
        ],
    )


def _web_alt(name):
    return _entry(
        name, "medium",
        "Usually a development server or an alternative admin page: a Python/Django/Flask server, a proxy, "
        "or a NAS or camera panel.",
        "Development servers are not built to face a network. 'python -m http.server' lists every file in its "
        "folder to anyone; a Flask or Django app in debug mode can be taken over. Device panels often still have "
        "their default password.",
        [
            _group(
                "Find out what it is",
                "Open http://{ip}:{port} in a browser and look at what answers.",
                "If it is on your own computer, find the program that opened it:",
                "$ sudo ss -tulpn | grep :{port}",
            ),
            _group(
                "Your own development server",
                "Bind it to this computer only, so the network cannot reach it:",
                "$ python3 -m http.server {port} --bind 127.0.0.1",
                "In Flask use host='127.0.0.1' and debug=False. In Django run "
                "'python manage.py runserver 127.0.0.1:{port}'.",
                "Stop the server when you are done (Ctrl+C).",
            ),
            _group(
                "Router / NAS / camera panel",
                "Change the default password and update the firmware.",
                "Use HTTPS if the panel offers it, and turn off remote administration on the router.",
            ),
        ],
    )


def _database(name, default_risk, why_extra, fix_groups):
    return _entry(
        name, default_risk,
        f"{name} database server. It holds an application's data; normally only applications on the same "
        "computer should connect to it.",
        "A database open to the network invites password guessing; an account with a weak or empty password "
        "lets an attacker read or delete everything. " + why_extra,
        fix_groups,
    )


ENTRIES = {
    21: _entry(
        "FTP", "high",
        "File transfer protocol. Found on NAS boxes, router USB sharing, cameras and old servers.",
        "FTP sends the user name and password unencrypted: anyone listening on the network can read them. "
        "If anonymous login is on, files can be reached without any password.",
        [
            _group(
                "Linux",
                "If you do not use the FTP server, stop and disable it (vsftpd, proftpd or pure-ftpd):",
                "$ sudo systemctl disable --now vsftpd",
                "Need file transfer? Use SFTP instead; it comes with SSH, nothing else to install:",
                "$ sftp user@{ip}",
            ),
            _group(
                "Windows",
                "Control Panel, Programs, 'Turn Windows features on or off': under Internet Information Services "
                "untick 'FTP Server'.",
            ),
            _group(
                "Router / NAS / camera",
                "Turn FTP off in the device's admin page; use SFTP or SMB if offered.",
                "Make sure anonymous (guest) login is off.",
            ),
        ],
    ),
    22: _entry(
        "SSH", "medium",
        "Encrypted remote command line. Linux servers, Raspberry Pis, NAS boxes and some routers have it.",
        "SSH itself is secure; the risks are weak passwords and untouched default accounts. If the port is open "
        "to the internet, password guessing starts within minutes. Fine if you use it and set it up well; "
        "turn it off if you do not.",
        [
            _group(
                "If you do not use it (Linux)",
                "Disable the SSH service (called ssh on Debian/Ubuntu, sshd on Fedora/Arch):",
                "$ sudo systemctl disable --now ssh",
            ),
            _group(
                "If you use it: keys instead of passwords",
                "Create a key and copy it to the server:",
                "$ ssh-keygen -t ed25519",
                "$ ssh-copy-id user@{ip}",
                "IMPORTANT: check in a second terminal that the key login works. Turning passwords off before that "
                "can lock you out.",
                "Then set these lines in /etc/ssh/sshd_config:",
                "$ PasswordAuthentication no",
                "$ PermitRootLogin no",
                "$ sudo systemctl restart ssh",
            ),
            _group(
                "If you use it: limit who can connect",
                "Allow the local network only. If you are connected over SSH, add the allow rule before enabling:",
                "$ sudo ufw allow from {subnet} to any port 22 proto tcp",
                "$ sudo ufw enable",
                "Block repeated password guesses automatically:",
                "$ sudo apt install fail2ban",
            ),
            _group(
                "Raspberry Pi / NAS / router",
                "Change the default password:",
                "$ passwd",
                "Turn SSH off in the NAS or router admin page if you do not need it.",
            ),
        ],
    ),
    23: _telnet(),
    2323: _telnet(),
    53: _entry(
        "DNS", "low",
        "Name resolution. Normal on routers and on devices running Pi-hole or dnsmasq.",
        "Low risk inside the home network. The real risks are DNS open to the internet (open resolvers are used "
        "in DDoS attacks) and changed DNS settings (DNS hijacking): an attacker who points your router at their "
        "own DNS server can send you to fake sites.",
        [
            _group(
                "Router",
                "Make sure 'access from WAN' / remote administration is off.",
                "Look at the DNS settings (primary/secondary DNS). An address you do not recognise may mean the router "
                "was taken over: change its password, update the firmware, set DNS back to automatic or a provider "
                "you trust.",
            ),
            _group(
                "Linux (dnsmasq / Pi-hole)",
                "Check which program opened it:",
                "$ sudo ss -tulpn | grep :53",
                "Let dnsmasq listen on the local interface only; in /etc/dnsmasq.conf:",
                "$ interface=eth0",
                "$ bind-interfaces",
            ),
        ],
    ),
    80: _entry(
        "HTTP (web page)", "medium",
        "A web interface. Routers, cameras, printers, NAS boxes and smart plugs usually have their admin page here.",
        "HTTP is not encrypted: the password you type into the panel crosses the network in plain text. Many "
        "devices still have their default password (admin/admin) and their panels run old, unpatched software.",
        [
            _group(
                "Find out what it is",
                "Open http://{ip} in a browser and see which device's page it is.",
            ),
            _group(
                "A device's admin page",
                "Change the default password; give every device its own long password.",
                "Use HTTPS if the panel offers it (443 or 8443).",
                "Install firmware updates.",
                "Turn off remote administration and UPnP on the router so the panel is not visible from the internet.",
            ),
            _group(
                "Your own web server (Linux)",
                "Turn it off if you do not use it (nginx or apache2):",
                "$ sudo systemctl disable --now nginx",
            ),
        ],
    ),
    111: _entry(
        "rpcbind", "medium",
        "The RPC port mapper. It works together with NFS file sharing.",
        "It tells anyone which RPC services are running and has been abused for DDoS reflection. Without NFS you "
        "do not need it.",
        [
            _group(
                "Linux",
                "Turn it off if you do not use NFS:",
                "$ sudo systemctl disable --now rpcbind.service rpcbind.socket",
            ),
        ],
    ),
    139: _entry(
        "NetBIOS", "high",
        "The old transport for Windows file and printer sharing (NetBIOS session service).",
        "An old protocol: it reveals computer and share names and shares SMB's attack surface. Modern networks do "
        "not need it. Usually shows up together with 445; the same fixes apply.",
        [
            _group(
                "Windows",
                "Network adapter properties, IPv4, Advanced, WINS tab: choose 'Disable NetBIOS over TCP/IP'.",
                "If you do not share files: Settings, Network & internet, Advanced sharing settings, turn off "
                "'File and printer sharing'.",
            ),
            _group(
                "Linux (Samba)",
                "$ sudo systemctl disable --now nmbd",
                "If you keep Samba, add this to the [global] section of /etc/samba/smb.conf:",
                "$ disable netbios = yes",
            ),
        ],
    ),
    443: _entry(
        "HTTPS", "low",
        "An encrypted web interface: router, NAS and camera panels, or a web site.",
        "Encryption is good; the risk is the panel itself: default password, old software, and blindly accepting "
        "its self-signed certificate.",
        [
            _group(
                "Checklist",
                "Open https://{ip} and confirm which device it is.",
                "Check that the default password has been changed and the firmware is current.",
                "Keep it off the internet: remove any router Port Forwarding rule that points at this device.",
            ),
        ],
        firewall=False,
    ),
    445: _entry(
        "SMB (Windows file sharing)", "high",
        "Windows (and Samba) file and printer sharing. NAS boxes and router USB sharing use SMB too.",
        "Large outbreaks such as WannaCry (EternalBlue) spread through SMB flaws. With old SMBv1 on and the device "
        "unpatched, the whole network is at risk. Shares without a password leak files.",
        [
            _group(
                "Windows (administrator PowerShell)",
                "Is SMBv1 on?",
                "$ Get-SmbServerConfiguration | Select EnableSMB1Protocol",
                "If it is, turn it off:",
                "$ Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
                "List the folders you share:",
                "$ Get-SmbShare",
                "Remove a share you created and no longer use:",
                "$ Remove-SmbShare -Name ShareName",
                "Set the network profile to 'Public' (Settings, Network & internet, network properties), which keeps "
                "file sharing off by default.",
            ),
            _group(
                "Linux (Samba)",
                "Turn it off if you do not use it:",
                "$ sudo systemctl disable --now smbd nmbd",
                "If you do, add these to [global] in /etc/samba/smb.conf and make sure shares say 'guest ok = no':",
                "$ server min protocol = SMB2",
                "$ hosts allow = 127.0.0.1 {subnet}",
                "$ sudo systemctl restart smbd",
            ),
            _group(
                "macOS",
                "System Settings, General, Sharing: turn off 'File Sharing'.",
            ),
            _group(
                "NAS / router",
                "Turn off SMB1 and guest/anonymous access; protect every share with a user password.",
            ),
        ],
    ),
    554: _entry(
        "RTSP (camera stream)", "medium",
        "The live video port of IP cameras.",
        "Many cheap cameras stream without a password or with the default one. Whoever reaches the stream can watch "
        "your home. A privacy problem: how bad depends on your camera.",
        [
            _group(
                "Test it first (your own camera)",
                "In VLC choose Media, Open Network Stream and enter rtsp://{ip}:554/. If video plays without asking for "
                "a password, the camera is open to everyone and the risk is critical.",
            ),
            _group(
                "Camera settings",
                "Require a user name and password in the camera app or admin page; change the default password.",
                "Update the firmware. If you only use the camera through its cloud app, turn local RTSP off.",
                "Delete any router Port Forwarding rule that points at the camera.",
                "If you can, move the camera to a separate guest/IoT network.",
            ),
        ],
    ),
    631: _entry(
        "CUPS (printing service)", "medium",
        "The printing service of Linux and macOS.",
        "Needed if you share a printer, but network-exposed CUPS has had flaws up to remote code execution "
        "(cups-browsed in particular). Without printer sharing you do not need it on the network.",
        [
            _group(
                "Linux",
                "If you do not share a printer, turn the browsing part off:",
                "$ sudo systemctl disable --now cups-browsed",
                "No printing at all on this machine:",
                "$ sudo systemctl disable --now cups.socket cups.path cups.service",
                "Otherwise use 'Listen localhost:631' in /etc/cups/cupsd.conf and keep the system updated.",
            ),
        ],
    ),
    1883: _entry(
        "MQTT", "medium",
        "Messaging for smart-home and IoT devices (Home Assistant, Mosquitto).",
        "Default MQTT setups have no password and no encryption. Anyone who connects can read the devices' data and "
        "send commands to plugs, lights and locks.",
        [
            _group(
                "Mosquitto (Linux)",
                "Turn off anonymous access and require a password. Add to /etc/mosquitto/mosquitto.conf:",
                "$ allow_anonymous false",
                "$ password_file /etc/mosquitto/passwd",
                "Create a user and restart:",
                "$ sudo mosquitto_passwd -c /etc/mosquitto/passwd username",
                "$ sudo systemctl restart mosquitto",
                "If only programs on the same computer connect, listen on localhost only:",
                "$ listener 1883 127.0.0.1",
                "If devices connect over the network, use TLS on port 8883.",
            ),
        ],
    ),
    2049: _entry(
        "NFS", "medium",
        "Linux/Unix file sharing.",
        "NFS decides access by IP address, not by password. A folder exported to '*' can be mounted and read by "
        "anyone on the network, and changed if it is writable.",
        [
            _group(
                "Linux",
                "See what you export:",
                "$ sudo exportfs -v",
                "In /etc/exports replace '*' with the addresses you trust and prefer 'ro' (read-only). If you do not "
                "use it, turn it off:",
                "$ sudo systemctl disable --now nfs-server",
            ),
        ],
    ),
    2375: _entry(
        "Docker API (no TLS)", "critical",
        "Docker's management API, reachable over the network.",
        "Anyone who reaches an unauthenticated Docker API can start a container with the host's whole file system "
        "mounted and run commands as root: a complete takeover of the computer. Close it now.",
        [
            _group(
                "Linux",
                "Find the setting that opened the port:",
                "$ grep -r 2375 /etc/docker /etc/systemd/system /lib/systemd/system 2>/dev/null",
                "Remove '-H tcp://0.0.0.0:2375' or the 'tcp://' entry in daemon.json. Docker's default is the local "
                "unix socket only.",
                "$ sudo systemctl daemon-reload",
                "$ sudo systemctl restart docker",
                "Need Docker from another computer? Connect over SSH instead of opening the API:",
                "$ docker -H ssh://user@{ip} ps",
            ),
        ],
    ),
    3306: _database(
        "MySQL / MariaDB", "medium",
        "Application users defined with host '%' (from anywhere) make it worse.",
        [
            _group(
                "Linux",
                "Allow local connections only. In the config file (often /etc/mysql/mysql.conf.d/mysqld.cnf):",
                "$ bind-address = 127.0.0.1",
                "$ sudo systemctl restart mysql",
                "Check which accounts may connect remotely:",
                "$ SELECT user, host FROM mysql.user;",
                "Delete accounts with host '%' that you do not need and make sure root has a password.",
            ),
        ],
    ),
    3389: _entry(
        "RDP (Remote Desktop)", "high",
        "Windows Remote Desktop: full graphical control of the computer over the network.",
        "One of ransomware's favourite ways in: weak passwords are brute-forced, and flaws such as BlueKeep were "
        "found. Much worse if the router forwards the port to the internet.",
        [
            _group(
                "If you do not use it (Windows)",
                "Turn it off in Settings, System, Remote Desktop. As administrator:",
                "$ netsh advfirewall firewall set rule group=\"remote desktop\" new enable=No",
            ),
            _group(
                "If you use it",
                "Keep 'Network Level Authentication (NLA)' on; use a strong, unique password.",
                "Delete any router Port Forwarding rule for 3389; never expose RDP to the internet. Use a VPN for "
                "remote access.",
                "Keep Windows updated and limit RDP in Windows Defender Firewall to local addresses.",
            ),
            _group(
                "Linux (xrdp)",
                "$ sudo systemctl disable --now xrdp",
            ),
        ],
    ),
    5000: _entry(
        "Port 5000 (UPnP / AirPlay / dev server)", "medium",
        "Several things use this port: macOS AirPlay Receiver, the Synology NAS panel, UPnP, or a Flask "
        "development server.",
        "If you do not know what it is, that is the risk. Flask debug servers can be taken over; an open AirPlay "
        "receiver lets a neighbour stream to your screen.",
        [
            _group(
                "Find out what it is",
                "Open http://{ip}:{port}. On your own computer this shows the program:",
                "$ sudo ss -tulpn | grep :{port}",
            ),
            _group(
                "macOS",
                "System Settings, General, AirDrop & Handoff: turn off 'AirPlay Receiver'.",
            ),
            _group(
                "Flask / development server",
                "Use app.run(host='127.0.0.1', debug=False): only your own computer can reach it.",
            ),
            _group(
                "NAS / router",
                "Find the service on this port in the admin page. Turn it off if unused, otherwise change the "
                "default password.",
            ),
        ],
    ),
    5353: _entry(
        "mDNS (Bonjour / Avahi)", "low",
        "Lets devices find each other on the local network (Bonjour, Avahi). Printers, Chromecast and AirPlay use it.",
        "Low risk, but it announces the device's name, type and sometimes services to everyone on the network, "
        "which makes reconnaissance easier.",
        [
            _group(
                "Linux",
                "If you do not need printer and device discovery, turn it off:",
                "$ sudo systemctl disable --now avahi-daemon.socket avahi-daemon.service",
            ),
        ],
    ),
    5432: _database(
        "PostgreSQL", "medium",
        "A pg_hba.conf line that allows everyone (0.0.0.0/0) makes the server effectively public.",
        [
            _group(
                "Linux",
                "Listen locally only, in postgresql.conf:",
                "$ listen_addresses = 'localhost'",
                "Remove wide rules such as '0.0.0.0/0' from pg_hba.conf and allow only the addresses you need. Then:",
                "$ sudo systemctl restart postgresql",
            ),
        ],
    ),
    5555: _entry(
        "Android ADB (network debugging)", "critical",
        "Android Debug Bridge over the network. Seen on Android TVs, TV boxes, tablets and phones.",
        "Open ADB gives a password-less shell on the device: apps get installed, files stolen, the device joins a "
        "botnet. This port is actively scanned and exploited on the internet.",
        [
            _group(
                "On the Android device",
                "Settings, Developer options: turn off 'USB debugging' and 'Wireless debugging' / 'ADB over network'. "
                "You can also turn Developer options off completely.",
                "If it is connected to your computer by USB, take ADB out of network mode:",
                "$ adb usb",
            ),
            _group(
                "Cheap TV box / no-name device",
                "Some ship with ADB on and no way to turn it off. Then isolate it on a guest/IoT network or replace it.",
            ),
        ],
    ),
    5900: _entry(
        "VNC (screen sharing)", "high",
        "Screen sharing and remote control.",
        "VNC often runs with a weak password and no encryption; whoever connects sees the screen and uses the "
        "keyboard and mouse. With an empty password, nobody is even asked.",
        [
            _group(
                "If you do not use it",
                "macOS: System Settings, General, Sharing: turn off 'Screen Sharing'.",
                "Linux: stop the VNC service (x11vnc, tigervnc or vncserver):",
                "$ sudo systemctl disable --now x11vnc",
            ),
            _group(
                "If you use it",
                "Do not connect to VNC directly; use an SSH tunnel so the traffic is encrypted and the VNC port can be "
                "closed to the network:",
                "$ ssh -L 5901:localhost:5900 user@{ip}",
                "Then point the VNC client at localhost:5901. Letting VNC listen on 127.0.0.1 only is safest.",
                "Set a strong VNC password.",
            ),
        ],
    ),
    6379: _entry(
        "Redis", "high",
        "A fast in-memory data store (cache, queue).",
        "Redis has no password by default and is meant for local use. Open to the network, anyone can read and "
        "delete the data; through its config commands an attacker can even write files and run commands.",
        [
            _group(
                "Linux",
                "Set these in /etc/redis/redis.conf:",
                "$ bind 127.0.0.1 ::1",
                "$ protected-mode yes",
                "$ requirepass PutAStrongPasswordHere",
                "$ sudo systemctl restart redis-server",
                "The service may be called redis on your distribution.",
            ),
        ],
    ),
    8000: _web_alt("Web (port 8000)"),
    8080: _web_alt("Web (port 8080)"),
    8443: _entry(
        "HTTPS alternative (8443)", "low",
        "An alternative encrypted web interface; many NAS boxes, cameras and admin panels use it.",
        "Traffic is encrypted; the risk is the panel itself (default password, old software).",
        [
            _group(
                "Checklist",
                "Open https://{ip}:{port} and confirm which device it is.",
                "Change the default password and update the firmware.",
                "Remove any router Port Forwarding rule for this device.",
            ),
        ],
        firewall=False,
    ),
    9100: _entry(
        "Printer (RAW / JetDirect)", "medium",
        "The raw printing port of network printers.",
        "Anyone who connects can send jobs without authentication. On some printers the configuration can be read "
        "through it, and stored documents retrieved. A printer is a computer that is rarely updated.",
        [
            _group(
                "Printer admin page",
                "Open the printer's web page (http://{ip}) and set an administrator password.",
                "If it supports AirPrint/IPP, turn off 'RAW 9100' printing.",
                "Update the firmware; turn off network services you do not use (FTP, Telnet, SNMP).",
                "Use an access list that limits which addresses may print, if there is one.",
            ),
        ],
        firewall=False,
    ),
    27017: _entry(
        "MongoDB", "high",
        "A NoSQL database server.",
        "Old MongoDB versions installed without authentication and listened on every interface; thousands of open "
        "databases were wiped and replaced with ransom notes.",
        [
            _group(
                "Linux",
                "Set these in /etc/mongod.conf:",
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
        "Apple devices' sync service (Wi-Fi sync with Finder or iTunes).",
        "Normal on an iPhone or iPad and not a danger by itself; it shows the device is an Apple product.",
        [
            _group(
                "Optional",
                "You can turn off 'Show this iPhone when on Wi-Fi' in Finder or iTunes. Nothing else to do.",
            ),
        ],
        firewall=False,
    ),
}


VERIFY_STEPS = [
    "After you close the service, this tool drops the port at the next port scan (within 30 minutes; "
    "restarting main.py scans at once). To check right away from another computer:",
    "$ nc -zv {ip} {port}",
    "'Connection refused' or a timeout means the port is closed; 'succeeded' or 'Connected' means it is still open.",
]


def _firewall_group(port):
    return _group(
        "If you cannot turn the service off: block it with a firewall",
        "These commands only work on the device that has the port open.",
        "Linux:",
        f"$ sudo ufw deny {port}/tcp",
        "Windows (administrator):",
        f"$ netsh advfirewall firewall add rule name=\"Block {port}\" dir=in action=block protocol=TCP localport={port}",
        "Routers, cameras and printers have no such firewall; there the fix is turning the service off in the "
        "device's admin page, or moving the device to a separate network.",
    )


def _unknown_entry(port, service):
    label = service if service and service != "unknown" else "unknown service"
    return {
        "name": f"Port {port} ({label})",
        "risk": "medium",
        "what": "This port is not in the knowledge base. Find out which program or service opened it.",
        "why": "An open port you cannot explain is an unknown door. Usually it is a harmless application, but you "
               "cannot be sure without checking.",
        "fix": [
            _group(
                "Linux",
                "Find the program that opened the port:",
                "$ sudo ss -tulpn | grep :{port}",
                "If you do not use it, stop and disable its service:",
                "$ sudo systemctl disable --now service-name",
            ),
            _group(
                "Windows",
                "Find the process ID (PID) on the port, then the program behind it:",
                "$ netstat -ano | findstr :{port}",
                "$ tasklist /FI \"PID eq 1234\"",
            ),
            _group(
                "macOS",
                "$ sudo lsof -iTCP:{port} -sTCP:LISTEN",
            ),
            _group(
                "Router / camera / IoT device",
                "Find the service on this port in the device's admin page. Turn it off if unused; otherwise change the "
                "default password and update the firmware.",
            ),
        ],
        "firewall": True,
    }


def port_info(port, service="unknown"):
    """Light information for the port chips: {"name": ..., "risk": ...}."""
    entry = ENTRIES.get(port) or _unknown_entry(port, service)
    return {"name": entry["name"], "risk": entry["risk"]}


def get_advice(port, service="unknown"):
    """Full advice for one port: what it is, why it matters, how to close it, how to verify."""
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


RISKY_PORTS = frozenset(port for port, entry in ENTRIES.items() if entry["risk"] in RISKY_LEVELS)


def _ip_key(ip):
    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, 0)


def score_label(score):
    if score >= 90:
        return "Strong"
    if score >= 70:
        return "Good"
    if score >= 50:
        return "Needs attention"
    return "At risk"


def build_summary(devices):
    """The network's security summary from the device list.

    devices: app.get_devices() output; every port carries "risk" and "accepted".
    Ports the owner acknowledged ("I know about this") count neither towards the
    score nor towards the action list.
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
                    "service": port["service"],
                    "name": port["name"],
                    "risk": port["risk"],
                })

    penalty += min(untrusted * UNTRUSTED_PENALTY, MAX_UNTRUSTED_PENALTY)
    score = round(100 * math.exp(-penalty / SCORE_SCALE))
    for level, cap in SCORE_CAP.items():
        if counts[level]:
            score = min(score, cap)
    actions.sort(key=lambda a: (-RISK_RANK[a["risk"]], _ip_key(a["ip"]), a["port"]))

    return {
        "score": score,
        "label": score_label(score),
        "counts": counts,
        "untrusted_devices": untrusted,
        "top_actions": actions[:3],
        "penalty_points": penalty,
        "penalties": {
            "per_port": RISK_PENALTY,
            "per_untrusted_device": UNTRUSTED_PENALTY,
            "untrusted_cap": MAX_UNTRUSTED_PENALTY,
            "scale": SCORE_SCALE,
            "caps": SCORE_CAP,
        },
    }
