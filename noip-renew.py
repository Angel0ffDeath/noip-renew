#!/usr/bin/env python3
"""
No-IP Free DDNS auto-confirm script (LANGUAGE INDEPENDENT)

Changes made:
- Removed text-based expiration parsing ("Expires in X days")
- Detection of expiring hosts is now based solely on presence of /ajax/host/<id>/touch buttons
- Works for all UI languages (German, English, etc.)
"""

import base64
import json
import logging
import sys
import re
from datetime import date, timedelta
from pathlib import Path

import pyotp
import requests
from bs4 import BeautifulSoup
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-d", "--debug", action="store_true")
parser.add_argument("-f", "--force", action="store_true")
ARGS = parser.parse_args()

VERSION = "1.0.3"

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


def setup_logging():
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    logger.addHandler(ch)
    try:
        fh = logging.FileHandler(LOG_FILE)
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except Exception:
        pass


def load_credentials():
    creds = {}
    with CREDENTIALS_FILE.open() as f:
        for line in f:
            if "=" in line:
                k, v = line.strip().split("=", 1)
                creds[k] = v
    password = base64.b64decode(creds["NOIP_PASS_B64"]).decode()
    return creds["NOIP_USER"], password, creds["NOIP_TOTP_SECRET"]


def load_state():
    if not STATE_FILE.exists():
        return {"hosts": {}, "next_run_date": None}
    with STATE_FILE.open() as f:
        return json.load(f)


def save_state(state):
    with STATE_FILE.open("w") as f:
        json.dump(state, f, indent=2)


def should_run_today():
    if ARGS.debug or ARGS.force:
        return True
    state = load_state()
    if not state.get("next_run_date"):
        return True
    return date.today() >= date.fromisoformat(state["next_run_date"])


def create_session():
    s = requests.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0",
        "Accept-Language": "en-US,en;q=0.5",
    })
    return s


def extract_login_form_token(html):
    soup = BeautifulSoup(html, "html.parser")
    form = soup.find("form", action=re.compile("/login"))
    token = form.find("input", {"name": "_token"})["value"]
    payload = {i.get("name"): "" for i in form.find_all("input") if i.get("name")}
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
    return r, "/2fa/verify" in r.text or "Two-Factor" in r.text


def do_twofactor(session, secret):
    r = session.get(TWOFA_URL)
    soup = BeautifulSoup(r.text, "html.parser")
    token = soup.find("input", {"name": "_token"})["value"]
    code = pyotp.TOTP(secret).now()
    payload = {
        "_token": token,
        "type": "totp",
        "challenge_code": code,
        "trust_device": "1",
    }
    session.post(TWOFA_URL, data=payload)


def extract_csrf_token_from_dns_page(html):
    soup = BeautifulSoup(html, "html.parser")
    meta = soup.find("meta", {"name": "token"})
    return meta["content"] if meta else None


# -------- LANGUAGE-INDEPENDENT EXPIRATION DETECTION --------

def parse_expiring_hosts(html):
    soup = BeautifulSoup(html, "html.parser")
    expiring = {}

    for banner in soup.select("div[id^=expiration-banner-hostname-]"):
        btn = banner.select_one("button[hx-get*='/ajax/host/'][hx-get$='/touch']")
        if not btn:
            continue

        m = re.search(r"/ajax/host/(\d+)/touch", btn["hx-get"])
        if not m:
            continue

        fqdn = banner["id"].replace("expiration-banner-hostname-", "").lower()
        expiring[fqdn] = m.group(1)

    return expiring


def parse_hosts_from_dns_page(html):
    soup = BeautifulSoup(html, "html.parser")
    expiring = parse_expiring_hosts(html)
    hosts = []

    for row in soup.select("div.zone-record.record_preview_wrapper"):
        zone = row.get("data-zone", "")
        name = row.get("data-name", "")
        fqdn = f"{name}.{zone}" if name and zone else None
        host_id = expiring.get(fqdn.lower()) if fqdn else None

        hosts.append({
            "fqdn": fqdn,
            "id": host_id,
            "needs_confirm": host_id is not None,
        })

    return hosts


def confirm_host(session, csrf, host_id, fqdn):
    url = f"{MY_URL}/ajax/host/{host_id}/touch"
    headers = {
        "X-CSRF-TOKEN": csrf,
        "X-Requested-With": "XMLHttpRequest",
        "Referer": RECORDS_URL,
    }
    r = session.get(url, headers=headers)
    return r.status_code == 200


def main():
    setup_logging()
    if not should_run_today():
        return

    user, password, secret = load_credentials()
    session = create_session()

    resp, need_2fa = login(session, user, password)
    if need_2fa:
        do_twofactor(session, secret)

    r = session.get(RECORDS_URL)
    csrf = extract_csrf_token_from_dns_page(r.text)
    hosts = parse_hosts_from_dns_page(r.text)

    to_confirm = [h for h in hosts if h["needs_confirm"]]

    state = {"hosts": {}}
    today = date.today()

    for h in hosts:
        if h["needs_confirm"]:
            next_run = today + timedelta(days=NEXT_RUN_AFTER_CONFIRM)
        else:
            next_run = today + timedelta(days=NEXT_RUN_NO_ACTION)
        state["hosts"][h["fqdn"]] = {"next_run_date": next_run.isoformat()}

    state["next_run_date"] = min(
        date.fromisoformat(v["next_run_date"])
        for v in state["hosts"].values()
    ).isoformat()

    if csrf:
        for h in to_confirm:
            confirm_host(session, csrf, h["id"], h["fqdn"])

    if not ARGS.debug:
        save_state(state)


if __name__ == "__main__":
    main()
