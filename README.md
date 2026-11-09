# Home Network Monitor

A lightweight home-network security tool. It scans your local network, remembers every device it sees, checks each device for open ports, alerts you when something new appears, and shows everything in a live web dashboard. Click any open port and the dashboard explains what it is, why it is risky, and step by step how to close it (Linux, Windows, macOS, router/IoT), with copy-ready commands.

Built with Python, Scapy, SQLite, Flask and vanilla JavaScript.

![Dashboard screenshot](docs/dashboard.png)

## Why this project

Most people have no idea what is connected to their home Wi-Fi. This tool answers a few simple questions:

- Which devices are on my network right now?
- When did each device first and last appear?
- Did something new just connect?
- Did a device suddenly open a new (possibly risky) port?

## Features

- **ARP network scan** – discovers devices on a subnet using Scapy. Several scan passes are merged so sleeping devices are less likely to be missed.
- **Vendor lookup** – identifies the manufacturer from the MAC address (TP-Link, Samsung, etc.) using Scapy's built-in manufacturer database.
- **Persistent device inventory** – every device is stored in SQLite with its first-seen and last-seen timestamps. The MAC address is the primary key, because IP addresses change.
- **New-device alerts** – prints a terminal alert and sends a desktop notification when an unknown MAC appears. The first run is silent so your existing devices are not reported as intruders.
- **Port scanning** – each device is checked for a list of common TCP ports (SSH, HTTP, SMB, RDP, VNC, printers, …). Ports are rescanned at most every 30 minutes per device.
- **New-port alerts** – when a device opens a port that was not open before, you get an alert. Risky services (FTP, Telnet, SMB, RDP, VNC) are flagged as `riskli!`. Closed ports are removed from the database.
- **Device naming and trust** – give each device a friendly name and mark it as trusted from the dashboard. Untrusted devices are highlighted with an orange bar.
- **Continuous monitoring** – rescans on a fixed interval (default: 60 seconds).
- **Web dashboard** – live table with online/offline status, auto-refreshing every 10 seconds. Auto-refresh pauses while you are editing a row.
- **Security advisor** – 29 common ports (Telnet, FTP, SMB, RDP, VNC, ADB, Docker API, Redis, databases, cameras, printers, ...) each have a risk level (critical / high / medium / low / info), a plain-language explanation, per-platform hardening steps, and a way to verify the port is really closed. Unknown ports get a generic "find out what opened it" guide.
- **Clickable ports** – open ports show as colored chips in the table. Clicking one opens a side panel with the advice, with the device's own IP and subnet filled into the commands and a copy button on every command.
- **Network security score** – 0-100 score, a breakdown of open ports by risk, and a "do these first" list of the three most urgent findings. The formula is shown in the dashboard.
- **"I know about this" acceptance** – mark a port as expected on a device (e.g. your own SSH server). It stops counting against the score and the to-do list, and you can undo it any time.
- **"Defend your network" tab** – a 17-item checklist (router, devices, monitoring) with progress saved in the browser, plus a step-by-step playbook for "I found a device I don't recognize" (including how to spot randomized MAC addresses).
- **Demo mode** – open the dashboard with `?demo=1` to mask the last half of MAC addresses (handy for screenshots).
- **Automatic database migration** – older databases get the new `name` / `trusted` columns and `ports` table added on startup.

## How it works

```
 scanner.py ─┐
 (ARP scan)  │
             ├──► main.py ──► db.py ──► devices.db
 portscan.py ┘   (loop +     (SQLite)       ▲
 (TCP ports)      alerts)                   │
                     │                      │
                  alert.py               app.py ──► templates/index.html
               (notify-send)          (Flask API)     (dashboard UI)
```

1. `scanner.py` broadcasts ARP requests and collects the IP/MAC replies.
2. `main.py` runs the scan in a loop and passes each device to `db.py`.
3. `db.py` inserts unseen MACs, updates known ones, and reports whether a device is new.
4. `portscan.py` checks the device's common ports in parallel; `db.py` stores them and reports newly opened ones.
5. New devices and new ports trigger `alert.py`.
6. `app.py` reads the same database and serves it as JSON to the dashboard, and saves names / trust flags sent from the dashboard.

A device is shown as **online** if it was seen within the last 3 minutes.

Port alerts need a baseline: the first port scan of a device in each run of `main.py` is only recorded, alerts are sent from the second scan on.

## Project structure

```
network-monitor/
├── scanner.py            # ARP scan + MAC vendor lookup
├── portscan.py           # Threaded TCP port scan of common ports
├── advisor.py            # Security knowledge base: port risks, fix steps, score calculation
├── defense_guide.py      # "Defend your network" checklist and unknown-device playbook
├── db.py                 # SQLite storage, migrations, new-device / new-port detection
├── alert.py              # Terminal and desktop notifications
├── main.py               # Continuous scan loop
├── app.py                # Flask web server and JSON API
├── templates/
│   └── index.html        # Dashboard page (devices tab + defense tab + advice panel)
├── tests/                # Unit tests (unittest)
├── docs/
│   └── dashboard.png
├── requirements.txt
└── README.md
```

## Requirements

- Linux
- Python 3.8+
- Root privileges (Scapy needs them to send raw ARP packets)
- `notify-send` for desktop notifications (optional)

## Installation

```bash
git clone https://github.com/fas0ftware/network-monitor.git
cd network-monitor

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

For desktop notifications, install `libnotify`:

```bash
# Debian / Ubuntu / Mint
sudo apt install libnotify-bin

# Fedora
sudo dnf install libnotify

# Arch / Manjaro
sudo pacman -S libnotify
```

## Configuration

Find your subnet with `ip -4 -brief a`. An address like `192.168.1.23/24` means your range is `192.168.1.0/24`.

Open `main.py` and adjust:

```python
IP_RANGE = "192.168.1.0/24"           # your subnet
SCAN_INTERVAL = 60                    # seconds between network scans
PORT_RESCAN_INTERVAL = 30 * 60        # minimum seconds between port scans of the same device
```

The list of ports that are checked is `COMMON_PORTS` in `portscan.py`. Alerts flag a new port as risky when its level in `advisor.py` is `high` or `critical`. To teach the tool about another port, add it to `COMMON_PORTS` and add an entry to `ENTRIES` in `advisor.py`; a unit test fails if a scanned port has no advice.

## Usage

Run the scanner (needs root, so call the virtual environment's Python explicitly):

```bash
sudo venv/bin/python main.py
```

In a second terminal, start the dashboard (no root needed):

```bash
source venv/bin/activate
python app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000). Type a name, tick **Güvenilir** (trusted) and press **Kaydet** (save) to label a device. Click any port chip to see how to close it, and open the **Ağını Savun** tab for the hardening checklist.

### Tests

```bash
python -m unittest -v
```

Tests cover the knowledge base (every scanned port has advice, placeholders are valid), the score calculation, and the Flask API (including the Host check, JSON-only POSTs and security headers).

On the first run the database is empty, so the first scan is silent and registers your current devices as known. From then on, any new MAC address triggers an alert.

> The dashboard UI is in Turkish; the code and API are language-neutral.

### API

| Method | Endpoint | Description |
| ------ | -------- | ----------- |
| `GET`  | `/api/devices` | All devices with `mac`, `ip`, `vendor`, `first_seen`, `last_seen`, `online`, `name`, `trusted`, `risk` and open `ports` (each with `port`, `name`, `risk`, `accepted`) |
| `POST` | `/api/devices/<mac>` | Body `{"name": "Laptop", "trusted": true}` – sets the name (trimmed, max 50 chars) and trust flag |
| `GET`  | `/api/summary` | Security score, label, open-port counts by risk, untrusted device count, top 3 actions |
| `GET`  | `/api/advice/<port>` | What the port is, why it is risky, fix steps per platform, verification steps |
| `POST` | `/api/devices/<mac>/ports/<port>/accept` | Body `{"accepted": true}` – mark a port as expected on that device (or `false` to undo). JSON only |
| `GET`  | `/api/defense-guide` | Checklist and unknown-device playbook |

### Testing the alert manually

Stop the scanner, delete one device from the database, and start it again:

```bash
sudo venv/bin/python -c "import sqlite3; c=sqlite3.connect('devices.db'); c.execute(\"DELETE FROM devices WHERE ip='192.168.1.X'\"); c.commit()"
sudo venv/bin/python main.py
```

Replace `192.168.1.X` with the device's IP. It will be detected as new.

## Security notes

- **Scan only networks you own or are authorized to test.** Scanning other people's networks, including port scans, may be illegal.
- The dashboard binds to `127.0.0.1`, so it is only reachable from the machine running it, not from other devices on the network.
- Requests whose `Host` header is not `127.0.0.1` or `localhost` are rejected, which blocks DNS rebinding attacks against the local dashboard.
- State-changing endpoints accept JSON only, so another website cannot trigger them with a hidden form.
- A Content-Security-Policy with a per-request nonce allows only the dashboard's own script. Other headers: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`.
- Advice commands are only displayed and copied, never executed by the tool.
- SQL queries are parameterized (`?` placeholders), which prevents SQL injection.
- The dashboard writes data into the page with `textContent` instead of `innerHTML`, so a malicious device name cannot inject script into the page.
- Device names are trimmed and limited to 50 characters on the server.
- `devices.db` and `.env` are listed in `.gitignore`, so your device inventory and future secrets are never committed.

## Known limitations

- **Randomized MAC addresses.** Modern phones use a different private MAC per network, so their vendor shows as "Bilinmiyor" (unknown). The same phone may also appear as a new device if it rotates its address.
- **Sleeping devices.** Some phones and TVs ignore ARP requests in power-saving mode, so they can briefly appear offline.
- **Client isolation.** If your router has AP/client isolation enabled, devices cannot see each other and the scan will find little.
- **Port scan scope.** Only a fixed list of common TCP ports is checked; UDP is not scanned. A "Temiz" (clean) device only means no unaccepted risky port was found among those ports.
- **Risk is per port, not per device.** The risk level comes from what the port usually means (e.g. port 80 is "medium" on any device). The advice explains how to check what is really behind it.
- **Trust does not silence alerts yet.** New-device alerts fire for every unknown MAC; the trusted flag is currently informational.
- **Linux only.** The notification code relies on `notify-send` and `/run/user/<uid>/bus`.

## Roadmap

- [x] Name devices and mark them as trusted
- [x] Port scanning for basic exposure checks
- [x] Show open ports in the dashboard
- [x] Security advisor: risk levels, how to close each port, network score
- [x] "Defend your network" checklist and unknown-device playbook
- [ ] Banner grabbing to detect outdated service versions
- [ ] Use the trusted flag to filter alerts
- [ ] Telegram notifications (token stored in `.env`)
- [ ] Better handling of randomized MAC addresses
- [ ] Device history and online/offline timeline
- [ ] Docker setup

## Tech stack

Python · Scapy · SQLite · Flask · JavaScript · HTML/CSS

