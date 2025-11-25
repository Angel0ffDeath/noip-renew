#!/usr/bin/env python3
"""
No-IP Free DDNS auto-confirm script (HTTP + 2FA, HTML parsing, AJAX confirm)

Requirements:
  pip3 install requests beautifulsoup4 pyotp

Files:
  /home/current_user/noip-renew/noip-renew.py        ← this script
  /home/current_user/noip-renew/credentials.txt      ← credentials file (KEY=VALUE)
  /home/current_user/noip-renew/state.json           ← created automatically
  /var/log/noip-renew.log                            ← log file (must be writable)

credentials.txt file content:
  NOIP_USER=your_user_name
  NOIP_PASS_B64=BASE64_ENCODED_PASSWORD
  NOIP_TOTP_SECRET=YOUR_2FA_SECRET_KEY
"""

import base64
import json
import logging
import os
import re
import sys
from datetime import date, timedelta
from pathlib import Path

import pyotp
import requests
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Paths / constants
# ---------------------------------------------------------------------------

VERSION = "1.0"

SCRIPT_DIR = Path(__file__).resolve().parent
CREDENTIALS_FILE = SCRIPT_DIR / "credentials.txt"
STATE_FILE = SCRIPT_DIR / "state.json"
LOG_FILE = Path("/var/log/noip-renew.log")

BASE_URL = "https://www.noip.com"
MY_URL = "https://my.noip.com"

LOGIN_URL = BASE_URL + "/login"
TWOFA_URL = BASE_URL + "/2fa/verify"
RECORDS_URL = MY_URL + "/dns/records"

# Scheduling logic
CONFIRM_THRESHOLD_DAYS = 7      # if "Expires in X days" and X <= this → confirm
NEXT_RUN_AFTER_CONFIRM = 25     # days after a successful confirmation
NEXT_RUN_NO_ACTION = 3          # days when nothing to renew / confirm

# Logger (global)
logger = logging.getLogger("noip-renew")


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def setup_logging():
    logger.setLevel(logging.INFO)

    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # File handler
    try:
        fh = logging.FileHandler(LOG_FILE)
        fh.setFormatter(formatter)
        logger.addHandler(fh)
        logger.info("Logging to %s", LOG_FILE)
    except Exception as e:
        logger.warning("Could not open log file %s: %s", LOG_FILE, e)


# ---------------------------------------------------------------------------
# Credentials & state
# ---------------------------------------------------------------------------

def load_credentials():
    if not CREDENTIALS_FILE.exists():
        logger.error("Credentials file not found: %s", CREDENTIALS_FILE)
        sys.exit(1)

    creds = {}
    with CREDENTIALS_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            creds[key.strip()] = value.strip()

    missing = []
    for k in ("NOIP_USER", "NOIP_PASS_B64", "NOIP_TOTP_SECRET"):
        if k not in creds or not creds[k]:
            missing.append(k)

    if missing:
        logger.error("Missing required credentials key(s): %s", ", ".join(missing))
        sys.exit(1)

    # Decode base64 password
    try:
        raw = base64.b64decode(creds["NOIP_PASS_B64"])
        password = raw.decode("utf-8")
    except Exception as e:
        logger.error("Failed to decode NOIP_PASS_B64: %s", e)
        sys.exit(1)

    return creds["NOIP_USER"], password, creds["NOIP_TOTP_SECRET"]


def load_state():
    if not STATE_FILE.exists():
        return None
    try:
        with STATE_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return data
    except Exception as e:
        logger.warning("Could not read state file %s: %s", STATE_FILE, e)
        return None


def save_state(next_run_date: date):
    data = {"next_run_date": next_run_date.strftime("%Y-%m-%d")}
    try:
        with STATE_FILE.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        logger.info("State saved to %s", STATE_FILE)
    except Exception as e:
        logger.warning("Failed to save state file %s: %s", STATE_FILE, e)


def should_run_today():
    today = date.today()
    state = load_state()
    if not state or "next_run_date" not in state:
        # No state yet → first run, so run now
        return True

    try:
        nr = state["next_run_date"]
        next_run = date.fromisoformat(nr)
    except Exception:
        logger.warning("State file has invalid next_run_date, ignoring.")
        return True

    if today < next_run:
        logger.info(
            "Next run scheduled for %s, today is %s -> exiting.",
            next_run.isoformat(),
            today.isoformat(),
        )
        return False

    return True


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def create_session():
    s = requests.Session()
    # Pretend to be a browser
    s.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux; rv:109.0) "
            "Gecko/20100101 Firefox/117.0"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive",
    })
    return s


def extract_login_form_token(html: str):
    soup = BeautifulSoup(html, "html.parser")
    form = soup.find("form", {"action": "/login"})
    if not form:
        # Fallback: any form that posts to /login
        forms = soup.find_all("form")
        for f in forms:
            action = f.get("action", "")
            if "/login" in action:
                form = f
                break
    if not form:
        return None, None

    token_input = form.find("input", {"name": "_token"})
    token = token_input["value"] if token_input and token_input.has_attr("value") else None

    # Try to guess the username/password field names
    payload = {}
    for inp in form.find_all("input"):
        name = inp.get("name")
        if not name:
            continue
        if name == "_token":
            payload[name] = token
        else:
            # Initialize with empty strings; we'll fill username/password later
            payload.setdefault(name, "")

    return token, payload


def login(session: requests.Session, user: str, password: str):
    logger.info("Opening login page...")
    r = session.get(LOGIN_URL, timeout=20)
    r.raise_for_status()

    token, payload = extract_login_form_token(r.text)
    if not token or payload is None:
        logger.error("Could not find login form or CSRF token on login page.")
        sys.exit(1)

    # Fill username & password intelligently
    for key in list(payload.keys()):
        low = key.lower()
        if "user" in low or "email" in low or "login" in low:
            payload[key] = user
        elif "pass" in low:
            payload[key] = password

    logger.info("Submitting login credentials...")
    r = session.post(LOGIN_URL, data=payload, timeout=20)
    r.raise_for_status()

    # If we already got into my.noip.com dashboard, 2FA might be remembered
    if "Two-Factor Authentication" in r.text or "/2fa/verify" in r.url:
        return r, True
    if "My No-IP" in r.text or MY_URL in r.url:
        logger.info("Logged in without 2FA challenge (trusted device).")
        return r, False

    # Fallback: check if we got redirected somewhere else but still need 2FA
    if "/2fa/verify" in r.text:
        return r, True

    # Best effort — if we aren't obviously logged in, treat as error
    logger.warning(
        "Login response did not clearly show dashboard or 2FA page. "
        "URL: %s", r.url
    )
    return r, ("Two-Factor Authentication" in r.text or "/2fa/verify" in r.text)


def extract_twofa_token(html: str):
    soup = BeautifulSoup(html, "html.parser")
    form = soup.find("form", {"action": "/2fa/verify"})
    if not form:
        # maybe plain /2fa/verify relative
        forms = soup.find_all("form")
        for f in forms:
            action = f.get("action", "")
            if "2fa/verify" in action:
                form = f
                break
    if not form:
        return None

    inp = form.find("input", {"name": "_token"})
    if inp and inp.has_attr("value"):
        return inp["value"]
    return None


def do_twofactor(session: requests.Session, totp_secret: str, initial_response: requests.Response):
    # Ensure we are on /2fa/verify
    if "/2fa/verify" in initial_response.url:
        html = initial_response.text
    else:
        logger.info("Fetching 2FA page...")
        resp = session.get(TWOFA_URL, timeout=20)
        resp.raise_for_status()
        html = resp.text

    # --- DEBUG: Dump 2FA HTML page ---
    """	
    try:
        dump_path = SCRIPT_DIR / "dump_2fa.html"
        with dump_path.open("w", encoding="utf-8") as f:
            f.write(html)
        logger.info("Dumped 2FA HTML to %s", dump_path)
    except Exception as e:
        logger.warning("Failed to dump 2FA HTML: %s", e)
    """		
    # --- END DEBUG ---


    token = extract_twofa_token(html)
    if not token:
        logger.error("Could not find CSRF token on 2FA page.")
        sys.exit(1)

    # Generate TOTP (do NOT log the code itself)
    logger.info("2FA required, submitting TOTP code...")
    try:
        totp = pyotp.TOTP(totp_secret)
        code = totp.now()
    except Exception as e:
        logger.error("Failed to generate TOTP code with pyotp: %s", e)
        sys.exit(1)

    payload = {
        "type": "totp",
        "challenge_code": code,
        "_token": token,
        # we can choose to trust or not trust this device
        # comment out if you don't want trust:
        "trust_device": "1",
    }

    r = session.post(TWOFA_URL, data=payload, timeout=20)
    r.raise_for_status()

    if "/2fa/verify" in r.url and "Two-Factor Authentication" in r.text:
        logger.error("2FA verification seems to have failed; still on 2FA page.")
        sys.exit(1)

    logger.info("2FA successful.")
    return r


# ---------------------------------------------------------------------------
# DNS page parsing
# ---------------------------------------------------------------------------

def extract_csrf_token_from_dns_page(html: str):
    soup = BeautifulSoup(html, "html.parser")
    meta = soup.find("meta", {"name": "token"})
    if not meta or not meta.get("content"):
        return None
    return meta["content"]


def parse_expiring_hosts(html: str):
    """
    Returns dict: fqdn.lower() -> days_left (int)
    using the "Expires in X days - hostname" banners.
    """
    soup = BeautifulSoup(html, "html.parser")
    expiring = {}

    for banner in soup.select("div[id^=expiration-banner-hostname-]"):
        h4 = banner.find("h4")
        if not h4:
            continue
        text = h4.get_text(" ", strip=True)
        # Example: "Expires in 5 days - yourhostname.ddns.net"
        m_days = re.search(r"Expires in\s+(\d+)\s+day", text)
        m_host = re.search(r"-\s*([A-Za-z0-9\.\-]+)$", text)
        if not m_days or not m_host:
            continue
        try:
            days_left = int(m_days.group(1))
        except ValueError:
            continue
        fqdn = m_host.group(1).strip().lower()
        expiring[fqdn] = days_left

    return expiring


def parse_hosts_from_dns_page(html: str):
    """
    Returns list of hosts:
      {
        "fqdn": "yourhost.ddns.net",
        "zone": "ddns.net",
        "name": "yourhost",
        "id": "70****12",
        "ip": "89.215.XX.XX",
        "last_update": "Nov 24, 2025 02:54:51",
        "days_left": 5 or None
      }
    """
    soup = BeautifulSoup(html, "html.parser")
    expiring = parse_expiring_hosts(html)

    hosts = []
    # New layout uses div.zone-record.record_preview_wrapper
    for row in soup.select("div.zone-record.record_preview_wrapper"):
        zone = (row.get("data-zone") or "").strip()
        name = (row.get("data-name") or "").strip()
        fqdn = None
        if name and zone:
            fqdn = f"{name}.{zone}"

        data_label = row.get("data-label") or ""
        host_id = None
        m = re.search(r"host=(\d+)", data_label)
        if m:
            host_id = m.group(1)

        last_update = (row.get("data-update") or "").strip()

        # IP address from span.word-break-all
        ip = None
        span = row.select_one("span.word-break-all")
        if span:
            txt = span.get_text(" ", strip=True)
            m_ip = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", txt)
            if m_ip:
                ip = m_ip.group(0)

        days_left = None
        if fqdn:
            days_left = expiring.get(fqdn.lower())

        hosts.append({
            "fqdn": fqdn,
            "zone": zone,
            "name": name,
            "id": host_id,
            "ip": ip,
            "last_update": last_update,
            "days_left": days_left,
        })

    return hosts


# ---------------------------------------------------------------------------
# Host confirmation (AJAX /touch with full headers)
# ---------------------------------------------------------------------------

def confirm_host(session: requests.Session, csrf_token: str, host_id: str, fqdn: str):
    url = f"{MY_URL}/ajax/host/{host_id}/touch"

    headers = {
        "X-Requested-With": "XMLHttpRequest",
        "X-CSRF-TOKEN": csrf_token,
        "HX-Request": "true",
        "Referer": RECORDS_URL,
        "Accept": "application/json, text/plain, */*",
    }

    logger.info("Confirming host %s (ID %s)...", fqdn, host_id)
    r = session.get(url, headers=headers, timeout=20)
    if r.status_code == 200:
        logger.info("Successfully confirmed %s.", fqdn)
        return True
    else:
        logger.warning(
            "Failed to confirm %s (ID %s) – HTTP %s, body: %.200s",
            fqdn,
            host_id,
            r.status_code,
            r.text,
        )
        return False


# ---------------------------------------------------------------------------
# Main logic
# ---------------------------------------------------------------------------

def main():
    setup_logging()
    logger.info("No-IP renew script ver. %s starting.", VERSION)

    if not should_run_today():
        return

    user, password, totp_secret = load_credentials()

    session = create_session()

    # 1) Login
    login_resp, needs_2fa = login(session, user, password)

    # 2) 2FA if required
    if needs_2fa:
        login_resp = do_twofactor(session, totp_secret, login_resp)

    # 3) Fetch DNS records page
    logger.info("Fetching DNS records page...")
    r = session.get(RECORDS_URL, timeout=20)
    r.raise_for_status()
    html = r.text

    # --- DEBUG: Dump DNS records HTML page ---
    """	
    try:
        dump_path = SCRIPT_DIR / "dump_dns_records.html"
        with dump_path.open("w", encoding="utf-8") as f:
            f.write(html)
        logger.info("Dumped DNS records HTML to %s", dump_path)
    except Exception as e:
        logger.warning("Failed to dump DNS records HTML: %s", e)
    """		
    # --- END DEBUG ---


    csrf_token = extract_csrf_token_from_dns_page(html)
    if not csrf_token:
        logger.warning("Could not find CSRF token on DNS records page.")

    hosts = parse_hosts_from_dns_page(html)
    if not hosts:
        logger.info("No zone records found on page (no hosts?).")
        # still schedule a short retry
        next_run = date.today() + timedelta(days=NEXT_RUN_NO_ACTION)
        logger.info(
            "No hosts to process. Scheduling next run in %d days (on %s).",
            NEXT_RUN_NO_ACTION,
            next_run,
        )
        save_state(next_run)
        logger.info("Script finished OK.")
        return

    logger.info("Found %d host record(s).", len(hosts))

    # Decide which to confirm
    any_has_days = any(h["days_left"] is not None for h in hosts)
    hosts_to_confirm = []

    if any_has_days:
        for h in hosts:
            if h["days_left"] is None:
                continue
            if h["days_left"] <= CONFIRM_THRESHOLD_DAYS:
                hosts_to_confirm.append(h)
        if hosts_to_confirm:
            logger.info(
                "%d host(s) need confirmation (<= %d days to expire).",
                len(hosts_to_confirm),
                CONFIRM_THRESHOLD_DAYS,
            )
        else:
            logger.info(
                "All hosts have more than %d days before expiration – nothing to renew now.",
                CONFIRM_THRESHOLD_DAYS,
            )
    else:
        # No explicit expiration info – safer to confirm everything
        logger.info(
            "No explicit 'Expires in X days' banners found. "
            "Will confirm all hosts as a safety measure."
        )
        hosts_to_confirm = hosts

    confirmed_count = 0

    if hosts_to_confirm and csrf_token:
        for h in hosts_to_confirm:
            if not h["id"] or not h["fqdn"]:
                continue
            if confirm_host(session, csrf_token, h["id"], h["fqdn"]):
                confirmed_count += 1
    elif hosts_to_confirm and not csrf_token:
        logger.warning(
            "Hosts appear to need confirmation but CSRF token is missing – cannot confirm."
        )

    # Scheduling
    today = date.today()
    if confirmed_count > 0:
        next_run = today + timedelta(days=NEXT_RUN_AFTER_CONFIRM)
        logger.info(
            "Confirmed %d host(s). Scheduling next run in %d days (on %s).",
            confirmed_count,
            NEXT_RUN_AFTER_CONFIRM,
            next_run,
        )
    else:
        next_run = today + timedelta(days=NEXT_RUN_NO_ACTION)
        logger.info(
            "Nothing to renew → next run in %d days (on %s).",
            NEXT_RUN_NO_ACTION,
            next_run,
        )

    save_state(next_run)
    logger.info("Script finished OK.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        # Make sure any unhandled exception is also visible on screen
        logger = logging.getLogger("noip-renew")
        if not logger.handlers:
            # if logging wasn't configured for some reason
            logging.basicConfig(
                level=logging.INFO,
                format="%(asctime)s - %(levelname)s - %(message)s",
            )
        logger.exception("Fatal error in script: %s", e)
        sys.exit(1)
