# Script to auto renew/confirm noip.com free hosts

[noip.com](https://www.noip.com/) free hosts expire every month.

Feel free to contribute!

- Platform: Debian/Ubuntu/Raspbian/Arch Linux, no GUI needed ; python 3.7+
- Created: 25/11/2025

## Prerequisites

ENABLE 2FA authentication on your account and save the 2FA Secret key that is shared only once when you activate it

Install requirements: pip3 install requests beautifulsoup4 pyotp

## Usage

1. Clone this repository to the device you will be running it from. (`git clone https://github.com/Angel0ffDeath/noip-renew.git`)
2. Fill the information in credentials.txt
3. Run script manually - python3 noip-renew.py.
4. Create cron job:
   crontab -e

   Add at the end:
   5 2 * * * /usr/bin/python3 /home/your_username/noip-renew/noip-renew.py >> /var/log/noip-renew.log 2>&1

   This will run the script daily at 2:05AM, but you can change the time.
   The script will decide wether to log to noip.com or will exit.

   Remark: If your user cannot write in /var/log/, before running the script create log file:
   sudo touch /var/log/noip-renew.log
   sudo chown your_username:group_of_user /var/log/noip-renew.log

## Known issues
If you have more than one host to confirm and all host expire on the same day - script will work. If hosts expire on different days - sheduling logic should be improved.
I have only 1 host and no way to test it.

Enjoy
