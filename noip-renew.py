#!/usr/bin/env python3
"""
No-IP Free DDNS auto-confirm script (HTTP + 2FA, HTML parsing, AJAX confirm)

Requirements:
  pip3 install requests beautifulsoup4 pyotp
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
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-d", "--debug", action="store_true", help="Debug mode. Dump html pages")
parser.add_argument("-f", "--force", action="store_true", help="Force run even if not scheduled")
ARGS = parser.parse_args()

VERSION = "1.0.2"

SCRIPT_DIR = Path(__file__).resolve().parent
CREDENTIALS_FILE = SCRIPT_DIR / "credentials.txt"
STATE_FILE = SCRIPT_DIR / "state.json"
LOG_FILE = Path("/var/log/noip-renew.log")

BASE_URL = "https://www.noip.com"
MY_URL = "https://my.noip.com"

LOGIN_URL = BASE_URL + "/login"
TWOFA_URL = BASE_URL + "/2fa/verify"
RECORDS_URL = MY_URL + "/dns/records"

NEXT_RUN_AFTER_CONFIRM = 25
NEXT_RUN_NO_ACTION = 3

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

    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

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

    for k in ("NOIP_USER", "NOIP_PASS_B64", "NOIP_TOTP_SECRET"):
        if k not in creds:
            logger.error("Missing credential %s", k)
            sys.exit(1)

    try:
        password = base64.b64decode(creds["NOIP_PASS_B64"]).decode("utf-8")
    except Exception as e:
        logger.error("Failed to decode password: %s", e)
        sys.exit(1)

    return creds["NOIP_USER"], password, creds["NOIP_TOTP_SECRET"]


def load_state():
    if not STATE_FILE.exists():
        return {"hosts": {}, "next_run_date": None}
    try:
        with STATE_FILE.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"hosts": {}, "next_run_date": None}


def save_state(state):
    with STATE_FILE.open("w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def should_run_today():
    if ARGS.debug or ARGS.force:
        return True

    state = load_state()
    nr = state.get("next_run_date")
    if not nr:
        return True

    return date.today() >= date.fromisoformat(nr)


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def create_session():
    s = requests.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0",
        "Accept-Language": "en-US,en;q=0.5",
    })
    return s


def extract_login_form_token(html):
    soup = BeautifulSoup(html, "html.parser")
    form = soup.find("form", {"action": "/login"})
    token = form.find("input", {"name": "_token"})["value"]

    payload = {}
    for i in form.find_all("input"):
        if i.get("name"):
            payload[i["name"]] = ""

    payload["_token"] = token
    return payload


def login(session, user, password):
    r = session.get(LOGIN_URL)
    payload = extract_login_form_token(r.text)

    for k in payload:
        if "user" in k or "email" in k:
            payload[k] = user
        if "pass" in k:
            payload[k] = password

    r = session.post(LOGIN_URL, data=payload)
    return r, ("/2fa/verify" in r.text or "Two-Factor" in r.text)


def extract_twofa_token(html):
    soup = BeautifulSoup(html, "html.parser")
    form = soup.find("form", {"action": "/2fa/verify"})
    if not form:
        return None
    inp = form.find("input", {"name": "_token"})
    return inp["value"] if inp else None


def do_twofactor(session, secret, initial):
    if "/2fa/verify" in initial.url:
        html = initial.text
    else:
        html = session.get(TWOFA_URL).text

    token = extract_twofa_token(html)
    totp = pyotp.TOTP(secret).now()

    payload = {
        "_token": token,
        "type": "totp",
        "challenge_code": totp,
        "trust_device": "1",
    }

    r = session.post(TWOFA_URL, data=payload)
    r.raise_for_status()
    return r


# ---------------------------------------------------------------------------
# DNS page parsing (LANGUAGE-INDEPENDENT CHANGE)
# ---------------------------------------------------------------------------

def parse_expiring_hosts(html: str):
    """
    Returns dict: fqdn.lower() -> host_id
    Detection based on /ajax/host/<id>/touch buttons.
    """
    soup = BeautifulSoup(html, "html.parser")
    expiring = {}

    for banner in soup.select("div[id^=expiration-banner-hostname-]"):
        btn = banner.select_one("button[hx-get*='/ajax/host/'][hx-get$='/touch']")
        if not btn:
            continue

        hx = btn.get("hx-get", "")
        m = re.search(r"/ajax/host/(\d+)/touch", hx)
        if not m:
            continue

        host_id = m.group(1)
        fqdn = banner.get("id", "").replace(
            "expiration-banner-hostname-", ""
        ).strip().lower()

        expiring[fqdn] = host_id

    return expiring


def extract_csrf_token_from_dns_page(html):
    soup = BeautifulSoup(html, "html.parser")
    meta = soup.find("meta", {"name": "token"})
    return meta["content"] if meta else None


def parse_hosts_from_dns_page(html):
    soup = BeautifulSoup(html, "html.parser")
    expiring = parse_expiring_hosts(html)

    hosts = []

    for row in soup.select("div.zone-record.record_preview_wrapper"):
        zone = (row.get("data-zone") or "").strip()
        name = (row.get("data-name") or "").strip()

        fqdn = f"{name}.{zone}" if name and zone else None
        host_id = expiring.get(fqdn.lower()) if fqdn else None

        hosts.append({
            "fqdn": fqdn,
            "zone": zone,
            "name": name,
            "id": host_id,
            "needs_confirm": host_id is not None,
        })

    return hosts


# ---------------------------------------------------------------------------
# Host confirmation
# ---------------------------------------------------------------------------

def confirm_host(session, csrf_token, host_id, fqdn):
    url = f"{MY_URL}/ajax/host/{host_id}/touch"

    headers = {
        "X-Requested-With": "XMLHttpRequest",
        "X-CSRF-TOKEN": csrf_token,
        "Referer": RECORDS_URL,
    }

    logger.info("Confirming host %s (ID %s)...", fqdn, host_id)
    r = session.get(url, headers=headers, timeout=20)
    return r.status_code == 200


# ---------------------------------------------------------------------------
# Main logic
# ---------------------------------------------------------------------------

def main():
    setup_logging()

    if not should_run_today():
        return

    user, password, secret = load_credentials()
    session = create_session()

    login_resp, needs_2fa = login(session, user, password)
    if needs_2fa:
        login_resp = do_twofactor(session, secret, login_resp)

    r = session.get(RECORDS_URL)
    r.raise_for_status()

    csrf = extract_csrf_token_from_dns_page(r.text)
    hosts = parse_hosts_from_dns_page(r.text)

    hosts_to_confirm = [h for h in hosts if h.get("needs_confirm")]

    today = date.today()
    state = {"hosts": {}}

    for h in hosts:
        if h["needs_confirm"]:
            run_date = today + timedelta(days=NEXT_RUN_AFTER_CONFIRM)
        else:
            run_date = today + timedelta(days=NEXT_RUN_NO_ACTION)

        state["hosts"][h["fqdn"]] = {"next_run_date": run_date.isoformat()}

    state["next_run_date"] = min(
        date.fromisoformat(v["next_run_date"])
        for v in state["hosts"].values()
    ).isoformat()

    if csrf:
        for h in hosts_to_confirm:
            confirm_host(session, csrf, h["id"], h["fqdn"])

    if not ARGS.debug:
        save_state(state)

    logger.info("Script finished OK.")


if __name__ == "__main__":
    main()
