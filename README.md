# Script to auto renew/confirm noip.com free hosts

[noip.com](https://www.noip.com/) free hosts expire every month.

Feel free to contribute!

- Platform: Debian/Ubuntu/Raspbian/Arch Linux, no GUI needed
- Python 3.7+
- Created: 25/11/2025

## Prerequisites

ENABLE 2FA authentication on your account and save the 2FA Secret key that is shared only once when you activate it

## Requirements

requests beautifulsoup4 pyotp - will be installed if missing during setup

## Usage

1. Clone this repository to the device you will be running it from. (`git clone https://github.com/Angel0ffDeath/noip-renew.git`)
2. Run setup.sh
3. Enjoy

## Known issues
If you have more than one host to confirm and all host expire on the same day - script will work. If hosts expire on different days - sheduling logic should be improved.
I have only 1 host and no way to test it.
