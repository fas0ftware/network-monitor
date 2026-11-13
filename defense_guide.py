"""Defend your network: a hardening checklist and an "unknown device" playbook.

The dashboard's "Defend your network" tab reads this through /api/defense-guide.
Item ids must stay stable: the browser stores the ticks under these ids.
"""


def _item(item_id, text, detail):
    return {"id": item_id, "text": text, "detail": detail}


CHECKLIST = [
    {
        "id": "router",
        "title": "Router (the door to your network)",
        "items": [
            _item(
                "router-admin-password",
                "Change the router's admin password",
                "admin/admin or the password on the sticker under the router is a password everyone knows. Open the "
                "admin page (usually 192.168.1.1 or 192.168.0.1) and change it under Administration or System. "
                "At least 12 characters, not used anywhere else.",
            ),
            _item(
                "router-wifi-encryption",
                "Use WPA3 or WPA2-AES for Wi-Fi",
                "WEP and WPA/TKIP can be cracked in minutes. In the wireless settings choose WPA3 or WPA2-PSK "
                "(AES/CCMP). A passphrase of 4-5 random words is easy to remember and hard to crack.",
            ),
            _item(
                "router-wps",
                "Turn WPS off",
                "WPS's PIN method can be brute-forced (Reaver, Pixie Dust). Find WPS in the wireless settings and turn "
                "it off; joining with the passphrase is easy enough.",
            ),
            _item(
                "router-remote-admin",
                "Turn off remote administration (access from WAN)",
                "The router's admin page does not need to be reachable from the internet. Turn off 'Remote "
                "management' / 'Access from WAN'. Need to reach home from outside? Set up a VPN instead.",
            ),
            _item(
                "router-upnp-forwarding",
                "Review UPnP and the Port Forwarding list",
                "UPnP lets devices open ports on the router by themselves, and malware can use it too. Delete Port "
                "Forwarding rules you do not recognise. Turn UPnP off if you do not need it; some games and apps "
                "do, so if something breaks, turn it back on and check what it opened.",
            ),
            _item(
                "router-firmware",
                "Update the router's firmware",
                "Routers are rarely updated and new flaws keep appearing, which makes them a favourite target. Check "
                "the Firmware Update page. If the maker no longer ships updates, consider replacing the router.",
            ),
            _item(
                "router-dns",
                "Check the DNS settings",
                "Look at the DNS addresses in the WAN/Internet settings. One you do not recognise may be a DNS "
                "hijack that sends you to fake sites. Change the router password, update the firmware and set DNS "
                "back to automatic or a provider you trust.",
            ),
            _item(
                "router-guest-network",
                "Put IoT devices and guests on a separate (guest) network",
                "Cameras, smart plugs and TVs are rarely updated. If one is taken over it should not reach your "
                "computer and phone. Note: this tool only sees devices on its own network; devices on an isolated "
                "guest network may not show up.",
            ),
        ],
    },
    {
        "id": "devices",
        "title": "Your devices",
        "items": [
            _item(
                "devices-updates",
                "Turn on automatic updates everywhere",
                "Updates for phones, computers, TVs and printers mostly fix security holes. Turn on automatic updates "
                "where you can; consider taking devices that no longer get updates off the network.",
            ),
            _item(
                "devices-firewall",
                "Keep the firewall on in computers",
                "Linux: 'sudo ufw enable' (connected over SSH? run 'sudo ufw allow 22/tcp' first). Windows: Windows "
                "Security, Firewall & network protection. macOS: System Settings, Network, Firewall. A firewall "
                "blocks incoming connections by default.",
            ),
            _item(
                "devices-close-services",
                "Turn off services you do not use (SSH, SMB, Telnet, VNC, RDP...)",
                "A service that is not running cannot be attacked. Click an open port on the Devices tab: the side "
                "panel explains what it is and how to close it, step by step.",
            ),
            _item(
                "devices-passwords",
                "Change default passwords, use a password manager and two-factor login",
                "A different, long password for every device and account, kept in a password manager rather than in "
                "your head. Turn on two-step verification wherever it is offered.",
            ),
            _item(
                "devices-cameras",
                "Check cameras and smart-home devices",
                "Check whether the camera stream opens without a password (the test is in the side panel of port "
                "554). Change the cameras' default passwords and move them to a guest/IoT network if you can.",
            ),
        ],
    },
    {
        "id": "monitoring",
        "title": "Monitoring (with this tool)",
        "items": [
            _item(
                "monitoring-name-devices",
                "Name every device and mark it as trusted",
                "Knowing which device is which is the first step to noticing a stranger. On the Devices tab type a "
                "name, tick 'Trusted' and press Save.",
            ),
            _item(
                "monitoring-no-unknown",
                "Leave no unknown device",
                "Identify every device with the amber bar (not trusted). If you cannot, follow the 'I see a device I "
                "do not know' plan below.",
            ),
            _item(
                "monitoring-review-ports",
                "Close critical and high-risk ports, or acknowledge them",
                "Click the red and orange port chips. Close what you do not need. If it is a service you really use "
                "(your own SSH server, say), secure it and then press 'I know about this' in the side panel; it no "
                "longer lowers your score.",
            ),
            _item(
                "monitoring-routine",
                "Keep the monitor running and look at the dashboard weekly",
                "Most trouble shows up over time: a new device, a newly opened port. Leave main.py running and open "
                "the dashboard once a week.",
            ),
        ],
    },
]


UNKNOWN_DEVICE_PLAYBOOK = {
    "title": "I see a device I do not know. What now?",
    "intro": "Don't panic: most unknown devices are harmless. Work through these steps in order.",
    "steps": [
        {
            "title": "First think of randomized MACs",
            "text": "Modern phones and laptops use a random (private) MAC address per Wi-Fi network, so your own phone "
                    "can look like a new device. If the second character of the MAC is 2, 6, A or E, the address is "
                    "randomized and the vendor shows as unknown. That alone is not a bad sign.",
        },
        {
            "title": "Look at the vendor and the IP address",
            "text": "Does the vendor (Samsung, TP-Link, Apple...) match something at home? Think of what you own from "
                    "that brand: TV, vacuum, plug, camera, printer, game console.",
        },
        {
            "title": "Find it by switching devices off one by one",
            "text": "Turn off Wi-Fi on your devices one at a time and watch which one goes 'Offline' on the dashboard. "
                    "When the unknown device goes offline, you have found it.",
        },
        {
            "title": "Check the router's list of connected devices",
            "text": "The router's 'Connected devices' or 'DHCP clients' page may show the device's host name, which "
                    "often tells you what it is.",
        },
        {
            "title": "Still unknown? Cut off who can join",
            "text": "Change the Wi-Fi passphrase: every device drops off and only those who know the new one get back "
                    "in. Check that WPS is off. Blocking the MAC on the router helps but is not enough on its own, "
                    "because MAC addresses can be faked; the passphrase is the real protection.",
        },
        {
            "title": "Then tidy up",
            "text": "Reconnect your own devices and mark them as trusted on the dashboard. Check the router password "
                    "and firmware while you are at it.",
        },
    ],
}


def get_guide():
    return {"checklist": CHECKLIST, "unknown_device_playbook": UNKNOWN_DEVICE_PLAYBOOK}
