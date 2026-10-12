#!/usr/bin/env python3
"""
failed_logins.py - Summarize failed Windows logons from Wazuh alert files
and flag possible brute force activity.

Part of the Home SOC Lab project.

What it does:
  1. Reads one or more Wazuh alert files (plain .json or compressed .json.gz).
  2. Keeps only failed Windows logons (Event ID 4625).
  3. Counts failures by target user and by source host (agent).
  4. Flags possible brute force: THRESHOLD or more failures for the same
     user from the same host within WINDOW seconds.

Examples (run on the Wazuh server; root is needed to read the alert files):
  sudo python3 failed_logins.py
  sudo python3 failed_logins.py /var/ossec/logs/alerts/2026/Oct/ossec-alerts-11.json.gz
  sudo python3 failed_logins.py yesterday.json.gz today.json --threshold 3 --window 30
"""

import argparse
import gzip
import json
from collections import Counter, defaultdict
from datetime import datetime
from zoneinfo import ZoneInfo

DEFAULT_FILE = "/var/ossec/logs/alerts/alerts.json"  # today's alerts
FAILED_LOGON_EVENT_ID = "4625"                       # Windows: "An account failed to log on"


def parse_args():
    """Read the options given on the command line."""
    parser = argparse.ArgumentParser(
        description="Summarize failed Windows logons (4625) from Wazuh alerts "
                    "and flag possible brute force."
    )
    # nargs="*" = zero or more files. Several files let us see an attack
    # that crosses the daily file rotation.
    parser.add_argument("files", nargs="*", default=[DEFAULT_FILE],
                        help="Wazuh alert files (.json or .json.gz). "
                             f"Default: {DEFAULT_FILE}")
    parser.add_argument("--threshold", type=int, default=5,
                        help="Failures needed to flag brute force (default: 5)")
    parser.add_argument("--window", type=int, default=60,
                        help="Time window in seconds (default: 60)")
    parser.add_argument("--tz", default="Asia/Jerusalem",
                        help="Time zone for printed times (default: Asia/Jerusalem)")
    return parser.parse_args()


def read_alerts(path, stats):
    """
    Yield one alert (dict) at a time from a Wazuh alert file.
    Empty or broken lines are skipped and counted, instead of crashing.
    """
    # Archived daily files are compressed; "rt" = read as text
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                stats["bad_lines"] += 1


def collect_failures(files, tz):
    """
    Return {(user, host): [times]} for every failed logon in the given files,
    plus a stats dict (alerts read, bad lines).
    """
    failures = defaultdict(list)
    stats = Counter()

    for path in files:
        for alert in read_alerts(path, stats):
            stats["alerts"] += 1

            # Not every alert is from Windows (e.g. SSH alerts from Linux),
            # so .get(..., {}) avoids crashing on missing fields.
            win = alert.get("data", {}).get("win", {})
            if win.get("system", {}).get("eventID") != FAILED_LOGON_EVENT_ID:
                continue

            ts_text = alert.get("timestamp")
            if not ts_text:
                continue

            user = win.get("eventdata", {}).get("targetUserName", "unknown")  # data.win.eventdata.targetUserName
            host = alert.get("agent", {}).get("name", "unknown")              # agent.name

            # Wazuh timestamp example: "2026-10-11T12:27:02.721+0000" (server time, UTC)
            ts = datetime.strptime(ts_text, "%Y-%m-%dT%H:%M:%S.%f%z").astimezone(tz)
            failures[(user, host)].append(ts)

    return failures, stats


def find_bursts(times, threshold, window):
    """
    Group sorted times into bursts. A burst starts at a failure and includes
    every failure up to `window` seconds after it. Return bursts with at
    least `threshold` failures.
    """
    times = sorted(times)
    bursts = []
    burst = [times[0]]

    for t in times[1:]:
        if (t - burst[0]).total_seconds() <= window:
            burst.append(t)
        else:
            if len(burst) >= threshold:
                bursts.append(burst)
            burst = [t]

    if len(burst) >= threshold:
        bursts.append(burst)
    return bursts


def main():
    args = parse_args()
    tz = ZoneInfo(args.tz)

    failures, stats = collect_failures(args.files, tz)

    by_user = Counter()
    by_host = Counter()
    for (user, host), times in failures.items():
        by_user[user] += len(times)
        by_host[host] += len(times)

    # ---- Report ----
    print("=== Failed Logon Summary (Event ID 4625) ===")
    print("Files read:      ", ", ".join(args.files))
    print("Alerts read:     ", stats["alerts"])
    print("Bad lines skipped:", stats["bad_lines"])
    print("Failed logons:   ", sum(by_user.values()))

    print("\nBy target user:")
    for user, count in by_user.most_common():
        print(f"  {user:<20} {count}")

    print("\nBy source host:")
    for host, count in by_host.most_common():
        print(f"  {host:<20} {count}")

    print(f"\nPossible brute force (>= {args.threshold} failures within {args.window}s):")
    found = False
    for (user, host), times in failures.items():
        for burst in find_bursts(times, args.threshold, args.window):
            found = True
            start, end = burst[0], burst[-1]
            seconds = (end - start).total_seconds()
            print(f"  [!] {user} from {host}: {len(burst)} failures in {seconds:.0f}s "
                  f"({start:%Y-%m-%d %H:%M:%S} -> {end:%H:%M:%S})")
    if not found:
        print("  None found.")


# Run main() only when the file is executed directly, not when imported
if __name__ == "__main__":
    main()
