About "SSH Brute-Force Log Analyzer" by SamaSecurity aka tarlaemmanuel83-source

This is a lightweight Python CLI tool that parses Linux SSH authentication logs (/var/log/auth.log) to detect brute-force login attempts, identify targeted usernames, and generate actionable mitigation commands. Acts as an Intrusion Detection System. This took me actually 3 weeks and 2 days to complete the project.
Features

    Parses sshd failed password events (both valid and invalid system users).
    Flags source IP addresses exceeding a configurable failure threshold.
    Lists targeted usernames per attacker IP.
    Outputs ready-to-use iptables mitigation rules and exports a structured JSON report.

How It Actually works

    Clone the repository: bash git clone https://github.com/tarlaemmanuel83-source/ssh-bruteforce-analyzer.git cd ssh-bruteforce-analyzer

    Run against the included sample log: bash python3 analyzer.py -f sample_auth.log -t 5

    Run against a live Linux server log: bash sudo python3 analyzer.py -f /var/log/auth.log -t 10
