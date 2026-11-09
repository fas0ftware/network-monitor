# Home Network Monitor

A lightweight tool that scans your local network, remembers every device it sees, checks each device for open ports, alerts you when something new appears, and shows everything in a live web dashboard where you can name devices and mark them as trusted.

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
- **Web dashboard** – live table with online/offline status and open ports (risky ones in red), auto-refreshing every 10 seconds. Auto-refresh pauses while you are editing a row.
- **Demo mode** – open the dashboard with `?demo=1` to mask the last half of MAC addresses (handy for screenshots).
- **Command-line options** – choose the subnet and scan interval when you start the scanner, no code editing needed.
- **Robust storage** – SQLite runs in WAL mode so the dashboard can read while the scanner writes, connections are always closed, and a failed write is rolled back.
- **Automatic database migration** – older databases get the new `name` / `trusted` columns and `ports` table added on startup.
- **Tested** – automated tests cover the database, the API, the port scanner and input validation (no root or network needed).

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
├── portscan.py           # Threaded TCP port scan of common ports, risky port list
├── db.py                 # SQLite storage, migrations, new-device / new-port detection
├── alert.py              # Terminal and desktop notifications
├── config.py             # Default settings and subnet validation
├── main.py               # Continuous scan loop (command-line entry point)
├── app.py                # Flask web server and JSON API
├── templates/
│   └── index.html        # Dashboard page
├── tests/                # Automated tests (unittest)
├── .github/workflows/
│   └── tests.yml         # Runs the tests on every push
├── docs/
│   └── dashboard.png
├── requirements.txt
└── README.md
```

## Requirements

- Linux
- Python 3.10+
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

Pass your subnet on the command line, or set it once with an environment variable:

```bash
sudo venv/bin/python main.py --range 192.168.0.0/24 --interval 60
# or
export NETMON_IP_RANGE=192.168.0.0/24
```

The range is validated: a host address such as `192.168.1.6/24` is turned into `192.168.1.0/24`, and IPv6 or very large networks (bigger than `/20`) are refused.

Other settings live in the code:

| Setting | File | Default |
| ------- | ---- | ------- |
| `DEFAULT_IP_RANGE` | `config.py` | `192.168.1.0/24` |
| `SCAN_INTERVAL` (seconds between network scans) | `config.py` | `60` |
| `PORT_RESCAN_INTERVAL` (minimum seconds between port scans of one device) | `config.py` | `30 * 60` |
| `RISKY_PORTS` (flagged in alerts and shown in red) | `portscan.py` | `{21, 23, 445, 3389, 5900}` |
| `COMMON_PORTS` (ports that are checked) | `portscan.py` | 19 common ports |

The database file is `devices.db` in the folder you start the program from; set `NETMON_DB` to use another path (both `main.py` and `app.py` read it).

## Usage

Run the scanner (needs root, so call the virtual environment's Python explicitly; without root it stops with a clear message):

```bash
sudo venv/bin/python main.py
```

In a second terminal, start the dashboard (no root needed):

```bash
source venv/bin/activate
python app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000). Type a name, tick **Güvenilir** (trusted) and press **Kaydet** (save) to label a device.

On the first run the database is empty, so the first scan is silent and registers your current devices as known. From then on, any new MAC address triggers an alert.

> The dashboard UI is in Turkish; the code and API are language-neutral.

### API

| Method | Endpoint | Description |
| ------ | -------- | ----------- |
| `GET`  | `/api/devices` | All devices with `mac`, `ip`, `vendor`, `first_seen`, `last_seen`, `online`, `name`, `trusted` and open `ports` (each with `port`, `service` and `risky`) |
| `POST` | `/api/devices/<mac>` | Body `{"name": "Laptop", "trusted": true}` – sets the name (trimmed, max 50 chars) and trust flag |

The `POST` endpoint answers `400` for a malformed MAC address, a body that is not JSON, or values of the wrong type (`trusted` must be `true` or `false`, not a string), and `404` for a device that is not in the database.

### Running the tests

```bash
python -m unittest discover -v
```

The tests use a temporary database and local sockets only. They need neither root nor Scapy. The same command runs on every push through GitHub Actions.

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
- SQL queries are parameterized (`?` placeholders), which prevents SQL injection.
- The dashboard writes data into the page with `textContent` instead of `innerHTML`, so a malicious device name cannot inject script into the page.
- Device names are trimmed and limited to 50 characters on the server, and the API checks the type of every field.
- The update endpoint only accepts `application/json`, so a web page you happen to visit cannot change device names or trust flags in the background.
- `devices.db` (including its `-wal` / `-shm` files) and `.env` are listed in `.gitignore`, so your device inventory and future secrets are never committed.

## Known limitations

- **Randomized MAC addresses.** Modern phones use a different private MAC per network, so their vendor shows as "Bilinmiyor" (unknown). The same phone may also appear as a new device if it rotates its address.
- **Sleeping devices.** Some phones and TVs ignore ARP requests in power-saving mode, so they can briefly appear offline.
- **Client isolation.** If your router has AP/client isolation enabled, devices cannot see each other and the scan will find little.
- **Port scan scope.** Only a fixed list of common TCP ports is checked; UDP is not scanned.
- **Trust does not silence alerts yet.** New-device alerts fire for every unknown MAC; the trusted flag is currently informational.
- **Linux only.** The notification code relies on `notify-send` and `/run/user/<uid>/bus`.

## Roadmap

- [x] Name devices and mark them as trusted
- [x] Port scanning for basic exposure checks
- [x] Show open ports in the dashboard
- [x] Automated tests and CI
- [ ] Use the trusted flag to filter alerts
- [ ] Telegram notifications (token stored in `.env`)
- [ ] Better handling of randomized MAC addresses
- [ ] Device history and online/offline timeline
- [ ] Docker setup

## Tech stack

Python · Scapy · SQLite · Flask · JavaScript · HTML/CSS

