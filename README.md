# Script to auto renew/confirm noip.com free hosts

[noip.com](https://www.noip.com/) free hosts expire every month.

Feel free to contribute!

- Platform: Debian/Ubuntu/Raspbian/Arch Linux, no GUI needed
- Python 3.7+
- Created: 25/11/2025

## Prerequisites

ENABLE 2FA authentication on your account and save the 2FA Secret key that is shared only once when you activate it

## Requirements

requests beautifulsoup4 pyotp - will be installed, if missing, during setup

## Usage

1. Clone this repository to the device you will be running it from. (`git clone https://github.com/Angel0ffDeath/noip-renew.git`)
2. Run setup.sh (ensure it is executable - chmod +x setup.sh)
3. Enjoy
4. Debug mode. This will dump login html page, 2 factor html page and dns records html page. Files will be stored in /usr/local/sbin/noip-renew/

    python3 /usr/local/sbin/noip-renew/noip-renew.py -d (or --debug)

5. Force run - always run. This will skip check for next running date.

    python3 /usr/local/sbin/noip-renew/noip-renew.py -f (or --force)

6. Tested with 2 host.
