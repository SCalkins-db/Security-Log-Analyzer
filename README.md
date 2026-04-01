# Security Log Analyzer

Python-based tool that analyzes authentication logs and detects suspicious login behavior using time-based event analysis.

## Features
- Burst attack detection
- Password spray detection
- Compromise detection (success after repeated failures)
- New host / port anomaly detection
- Impossible travel detection
- Severity-based incident summary

## How It Works
The analyzer processes log data and tracks activity within a sliding time window to identify patterns such as:
- Rapid login failures from a single IP
- One IP targeting multiple users
- Suspicious successful logins following failures

## Log Format
Each line must follow:

YYYY-MM-DD HH:MM:SS,username,ip,host,port,status

Example:
2026-02-18 13:01:00,dina,45.33.12.90,server01,22,FAIL

## Run
```bash
python analyzer.py
