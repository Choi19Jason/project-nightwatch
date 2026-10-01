# IP Reputation Checker (AbuseIPDB)

A small SOC triage helper. Give it a list of IP addresses and it returns each one's
**AbuseIPDB confidence score**, country, ISP, and recent report count, flagging anything
at or above a threshold. Useful for quickly checking a batch of source IPs pulled from
SIEM or firewall logs.

## Why it exists
Checking IPs one by one in a browser is slow and doesn't scale. This automates that
lookup and can export the results to CSV for a ticket.

## Security note (important)
The API key is read from a **`.env` file that is never committed** (it's in `.gitignore`).
Hard-coded or leaked keys are a red flag on a security portfolio, so this project keeps
the secret out of the code and out of version control.

## Setup
```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env             # then paste your key into .env
# get a free key at https://www.abuseipdb.com/account/api
```

## Usage
```bash
# check a few IPs directly
python check_ips.py 8.8.8.8 1.1.1.1

# check a file (one IP per line), flag score >= 50, export to CSV
python check_ips.py --file sample_ips.txt --threshold 50 --csv results.csv

# add a small delay between requests to avoid rate limits
python check_ips.py --file sample_ips.txt --delay 1
```

## Example output
```
IP                 Score  Country Reports  ISP
----------------------------------------------------------------------
8.8.8.8                0  US            0  Google LLC
1.1.1.1                0  US            0  Cloudflare, Inc.
----------------------------------------------------------------------
Checked 2 IP(s); 0 at or above threshold 50.
```

## Notes
- Invalid IPs are skipped with a message rather than crashing the run.
- Rate limiting (HTTP 429) and auth errors (HTTP 401) are handled with clear messages.
- The free AbuseIPDB tier has a daily request limit; `--delay` helps stay under per-second limits.
