import json
from datetime import datetime, timezone

# =====================
# FILE CONFIGURATION
# =====================

INPUT_FILE = "security_report.json"
OUTPUT_FILE = "response_report.json"

SEVERITY_BASE = {
    "HIGH": 70,
    "MEDIUM": 40,
    "LOW": 15
}

# ===================================================
# Policy / Profiles (simulated enterprise controls)
# ===================================================

USER_PROFILES = {
    "admin": {
        "mfa": True,
        "min_password_length": 14,
        "vpn_required": True,
        "trusted_internal_prefixes": ("192.168.",),
    }
}

DEFAULT_PROFILE = {
    "mfa": False,
    "min_password_length": 10,
    "vpn_required": False,
    "trusted_internal_prefixes": ("192.168.",),
}

# ===================
# HELPER FUNCTIONS
# ===================

def is_internal_ip(ip: str | None) -> bool:
    return bool(ip) and ip.startswith("192.168.")

def get_profile(user: str | None) -> dict:
    if not user:
        return DEFAULT_PROFILE
    profile = USER_PROFILES.get(user, {})
    merged = DEFAULT_PROFILE.copy()
    merged.update(profile)
    return merged

def load_report():
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

# ===================
# RISK SCORING ENGINE
# ===================


def calculate_risk(incident, user_incident_counts):
    severity = incident.get("severity", "LOW")
    base = SEVERITY_BASE.get(severity, 10)
    score = base
    reasons = []

    entity = incident.get("entity", {})
    incident_type = incident.get("type", "")

    ip = entity.get("ip") or entity.get("from_ip")
    user = entity.get("user")

    profile = get_profile(user)

    device_is_trusted = entity.get("device_trusted", False)
    expected_users_for_host = entity.get("expected_users", [])
    no_prior_failures = entity.get("prior_failures", 0) == 0

    # -------------------
    # Threat Signals (+)
    # -------------------

    if ip and not is_internal_ip(ip):
        score += 10
        reasons.append("external_ip")

    if user and user_incident_counts.get(user, 0) > 1:
        score += 10
        reasons.append("repeat_user_activity")

    if incident_type == "COMPROMISE":
        score += 20
    elif incident_type == "IMPOSSIBLE_TRAVEL":
        score += 20
    elif incident_type == "SPRAY":
        score += 10
    elif incident_type == "BURST":
        score += 5

    if user == "admin" and incident_type in ("COMPROMISE", "IMPOSSIBLE_TRAVEL"):
        score += 10
        reasons.append("admin_account_risk")

    # --------------------------
    # Compensating Controls (-)
    # --------------------------

    if profile.get("mfa"):
        if incident_type in ("SPRAY", "BURST", "NEW_HOST", "NEW_PORT"):
            score -= 15
        elif incident_type == "IMPOSSIBLE_TRAVEL":
            score -= 10

    min_len = profile.get("min_password_length", 10)
    if min_len >= 12 and incident_type in ("SPRAY", "BURST"):
        score -= 5

    if incident_type in ("NEW_HOST", "NEW_PORT"):
        if (
                is_internal_ip(ip)
                and device_is_trusted
                and user in expected_users_for_host
                and no_prior_failures
        ):
            score -= 10
        if user == "admin" and profile.get("vpn_required") and is_internal_ip(ip):
            score -= 5

    score = max(0, min(score, 100))
    return score, reasons

# ===================
# RESPONSE DECISIONS
# ===================

def decide_actions(score):
    if score >= 90:
        return ["lock_account", "block_ip", "flag_for_review"]
    elif score >= 70:
        return ["require_mfa", "block_ip", "flag_for_review"]
    elif score >= 45:
        return ["block_ip", "monitor"]
    else:
        return ["monitor"]

# ===================
# MAIN PIPELINE
# ===================

def main():
    report = load_report()
    incidents = report.get("incidents", [])

    blocked_ips = set()
    locked_accounts = set()
    mfa_required = set()

    user_incident_counts = {}

    # Count incidents per user
    for inc in incidents:
        user = inc.get("entity", {}).get("user")
        if user:
            user_incident_counts[user] = user_incident_counts.get(user, 0) + 1

    responses = []


    for i, inc in enumerate(incidents, start=1):
        risk, reasons = calculate_risk(inc, user_incident_counts)
        actions = decide_actions(risk)

        entity = inc.get("entity", {})
        user = entity.get("user")
        ip = entity.get("ip") or entity.get("from_ip")

        if "lock_account" in actions and user:
            locked_accounts.add(user)

        if "block_ip" in actions and ip:
            blocked_ips.add(ip)

        if "require_mfa" in actions and user:
            mfa_required.add(user)

        responses.append({
            "incident_id": i,
            "type": inc.get("type"),
            "severity": inc.get("severity"),
            "risk_score": risk,
            'risk_reason': reasons,
            "actions_taken": actions
        })

    output = {
        "meta": {
            "generated_utc": datetime.now(timezone.utc).isoformat()
        },
        "incident_responses": responses,
        "final_system_state": {
            "locked_accounts": sorted(locked_accounts),
            "blocked_ips": sorted(blocked_ips),
            "mfa_required": sorted(mfa_required)
        }
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print("Response report written to:", OUTPUT_FILE)

if __name__ == "__main__":
    main()