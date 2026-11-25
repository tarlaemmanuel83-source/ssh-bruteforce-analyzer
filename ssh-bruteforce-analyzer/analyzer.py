import argparse
import json
import re
from collections import Counter, defaultdict

FAILED_SSH_PATTERN = re.compile(
    r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed password for (?:invalid user )?(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)"
)

def analyze_log(file_path: str, threshold: int) -> dict:
    ip_counts = Counter()
    targeted_users = defaultdict(set)
    total_failed = 0

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            match = FAILED_SSH_PATTERN.search(line)
            if match:
                total_failed += 1
                ip = match.group("ip")
                user = match.group("user")
                ip_counts[ip] += 1
                targeted_users[ip].add(user)

    flagged_ips = []
    for ip, count in ip_counts.most_common():
        if count >= threshold:
            flagged_ips.append({
                "ip": ip,
                "failed_attempts": count,
                "targeted_users": sorted(targeted_users[ip]),
                "suggested_action": f"sudo iptables -A INPUT -s {ip} -j DROP"
            })

    return {
        "log_file": file_path,
        "threshold": threshold,
        "total_failed_attempts": total_failed,
        "unique_source_ips": len(ip_counts),
        "flagged_attackers": flagged_ips
    }

def main():
    parser = argparse.ArgumentParser(description="Analyze Linux auth logs for SSH brute-force attacks.")
    parser.add_argument("-f", "--file", default="sample_auth.log", help="Path to auth.log file")
    parser.add_argument("-t", "--threshold", type=int, default=5, help="Failed attempt threshold for alerts")
    parser.add_argument("-o", "--output", default="report.json", help="Output JSON report path")
    args = parser.parse_args()

    report = analyze_log(args.file, args.threshold)

    print(f"\n--- SSH Brute-Force Analysis ({args.file}) ---")
    print(f"Total Failed Attempts : {report['total_failed_attempts']}")
    print(f"Unique Source IPs     : {report['unique_source_ips']}")
    print(f"Alert Threshold       : {args.threshold}\n")

    if not report["flagged_attackers"]:
        print("[OK] No IP addresses exceeded the brute-force threshold.")
    else:
        for attacker in report["flagged_attackers"]:
            print(f"[ALERT] {attacker['ip']} -> {attacker['failed_attempts']} failed attempts")
            print(f"        Targeted Users : {', '.join(attacker['targeted_users'])}")
            print(f"        Mitigation     : {attacker['suggested_action']}\n")

    with open(args.output, "w", encoding="utf-8") as out:
        json.dump(report, out, indent=2)
    print(f"Report saved to {args.output}")

if __name__ == "__main__":
    main()
