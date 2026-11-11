"""Alerts: terminal, desktop (notify-send) and optional push webhooks.

Webhooks are configured with environment variables:
  NETMON_NTFY_URL     e.g. https://ntfy.sh/my-secret-topic  (plain-text POST, phone push via ntfy app)
  NETMON_WEBHOOK_URL  Discord / Slack / Mattermost incoming webhook (JSON POST)
"""

import json
import os
import shutil
import subprocess  # only fixed argument lists, never a shell  # nosec B404
import urllib.request
from urllib.parse import urlparse

WEBHOOK_TIMEOUT = 5


def valid_webhook(url):
    """Only http(s) URLs with a host are used; anything else (file:, ftp:, typos) is ignored."""
    try:
        parts = urlparse(url)
    except ValueError:
        return False
    return parts.scheme in ("https", "http") and bool(parts.netloc)


def _post(url, data, content_type, headers=None):
    request = urllib.request.Request(url, data=data, method="POST",
                                     headers={"Content-Type": content_type, **(headers or {})})
    with urllib.request.urlopen(request, timeout=WEBHOOK_TIMEOUT) as response:  # scheme checked  # nosec B310
        return response.status


def send_push(title, message, env=os.environ):
    """Send to the configured webhooks. Returns the number of successful deliveries."""
    sent = 0
    ntfy = env.get("NETMON_NTFY_URL", "").strip()
    if ntfy and valid_webhook(ntfy):
        try:
            # ntfy headers must be latin-1; strip what does not fit
            safe_title = title.encode("latin-1", "ignore").decode("latin-1")
            _post(ntfy, message.encode("utf-8"), "text/plain; charset=utf-8",
                  {"Title": safe_title, "Tags": "warning"})
            sent += 1
        except Exception as error:
            print(f"(ntfy notification failed: {type(error).__name__})")

    hook = env.get("NETMON_WEBHOOK_URL", "").strip()
    if hook and valid_webhook(hook):
        text = f"**{title}**\n{message}"
        body = json.dumps({"content": text, "text": text, "title": title, "message": message})
        try:
            _post(hook, body.encode("utf-8"), "application/json")
            sent += 1
        except Exception as error:
            print(f"(webhook notification failed: {type(error).__name__})")
    return sent


def send_desktop(title, message):
    if not shutil.which("notify-send"):
        return
    sudo_user = os.environ.get("SUDO_USER")
    try:
        if hasattr(os, "geteuid") and os.geteuid() == 0 and sudo_user:
            # Running under sudo: deliver the notification to the real user's session
            uid = subprocess.check_output(["id", "-u", sudo_user], text=True).strip()  # fixed argv  # nosec B603 B607
            command = [
                "sudo", "-u", sudo_user, "env",
                f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus",
                "notify-send", "--", title, message,
            ]
        else:
            command = ["notify-send", "--", title, message]
        subprocess.run(command, check=False, timeout=5)  # argument list, no shell  # nosec B603
    except Exception as error:
        print(f"(Desktop notification could not be sent: {error})")


def send_notification(title, message):
    # Always print (\a rings the terminal bell)
    print(f"\a[ALERT] {title}: {message}")
    send_desktop(title, message)
    send_push(title, message)
