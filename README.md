# Security Log Analyzer

Python-based security detection and response pipeline that analyzes authentication logs, identifies suspicious behavior, and simulates automated security actions.

# Features
- Burst attack detection
- Password spray detection
- Compromise detection (success after repeated failures)
- New host / port anomaly detection
- Impossible travel detection
- Risk scoring and automated response simulation

# Pipeline Overview

This project consists of two stages:

# 1. Detection Engine (`analyzer.py`)
- Processes authentication logs using sliding time window analysis
- Detects suspicious patterns such as burst attacks, password spraying, compromise, and anomalies
- Outputs structured findings to `security_report.json`

# 2. Response Engine (`response_engine.py`)
- Ingests detected incidents
- Assigns risk scores based on severity and context
- Simulates automated security responses such as:
  - IP blocking
  - Account locking
  - MFA enforcement
- Outputs results to `response_report.json`

# How It Works
The analyzer processes log data and tracks activity within a sliding time window to identify patterns such as:
- Rapid login failures from a single IP
- One IP targeting multiple users
- Suspicious successful logins following failures

# Log Format
Each line must follow:

YYYY-MM-DD HH:MM:SS,username,ip,host,port,status

Example:
2026-02-18 13:01:00,dina,45.33.12.90,server01,22,FAIL

# Run
```bash
python analyzer.py
python response_engine.py
