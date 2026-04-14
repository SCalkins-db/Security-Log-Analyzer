from datetime import datetime, timedelta
from collections import Counter, defaultdict, deque
import os
import ipaddress

# =======
# CONFIG
# =======

TS_FORMAT = "%Y-%m-%d %H:%M:%S"
LOGFILE = "logs.txt"

# Detection thresholds
WINDOW = timedelta(minutes=2)
BURST_THRESHOLD = 5
SPRAY_USERS_THRESHOLD = 3
USER_THRESHOLD = 3

# For NEW HOST / NEW PORT: don’t flag until we have a tiny baseline
MIN_BASELINE_SUCCESSES = 2

# For "impossible travel" 
IMPOSSIBLE_TRAVEL_WINDOW = timedelta(minutes=5)  # keep your earlier 300s behavior
IMPOSSIBLE_TRAVEL_MAX_SECONDS = 300              # 5 minutes


# ========
# HELPERS
# ========

def ip_scope(ip: str) -> str:
    """internal if RFC1918 private ranges, else external; unknown if invalid."""
    try:
        addr = ipaddress.ip_address(ip)
        return "internal" if addr.is_private else "external"
    except ValueError:
        return "unknown"


def severity(label: str) -> str:
    """Simple, explainable severity mapping."""
    mapping = {
        "COMPROMISE": "HIGH",
        "IMPOSSIBLE_TRAVEL": "HIGH",
        "SPRAY": "MEDIUM",
        "BURST": "MEDIUM",
        "NEW_HOST": "LOW",
        "NEW_PORT": "LOW",
        "USER_BRUTE_FORCE": "LOW",
    }
    return mapping.get(label, "LOW")


def sev_rank(sev: str) -> int:
    """Sort order for incident summary."""
    return {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(sev, 3)


def parse_port(port_str: str) -> int | None:
    try:
        return int(port_str)
    except ValueError:
        return None


# ================
# DATA STRUCTURES
# ================

# Totals
user_failures: Counter[str] = Counter()
ip_failures: Counter[str] = Counter()
pair_failures: Counter[tuple[str, str]] = Counter()                # (user, ip)
service_failures: Counter[tuple[str, str, int]] = Counter()        # (ip, host, port)

user_successes: Counter[str] = Counter()
ip_successes: Counter[str] = Counter()

# Sliding windows (FAIL-based)
recent_fail_times_by_ip: dict[str, deque[datetime]] = defaultdict(deque)
recent_fail_users_by_ip: dict[str, deque[tuple[datetime, str]]] = defaultdict(deque)
recent_fail_times_by_pair: dict[tuple[str, str], deque[datetime]] = defaultdict(deque)

# Dedupe / “active incident” tracking
active_burst_ips: dict[str, datetime] = {}
active_spray_ips: dict[str, datetime] = {}

bursts: list[dict] = []
sprays: list[dict] = []
compromised: list[dict] = []

# Baseline (learned from SUCCESS)
known_hosts_by_user: dict[str, set[str]] = defaultdict(set)
known_ports_by_user: dict[str, set[int]] = defaultdict(set)
success_counts: Counter[str] = Counter()

# Anomalies (dedup)
new_host_findings: list[dict] = []
new_port_findings: list[dict] = []
impossible_travel_findings: list[dict] = []

new_host_seen: set[tuple[str, str, str]] = set()                   # (user, ip, host)
new_port_seen: set[tuple[str, str, str, int]] = set()              # (user, ip, host, port)
impossible_travel_seen: set[tuple[str, str, str, str]] = set()     # (user, from_ip, to_ip, to_time_str)

# Compromise dedupe
compromise_found: set[tuple[str, str, str]] = set()                # (user, ip, success_time_str)

# Recent successes for impossible travel
recent_success_by_user: dict[str, deque[tuple[datetime, str, str, int]]] = defaultdict(deque)

# Incident summary feed
incident_feed: list[dict] = []   # {"sev": str, "time": datetime, "msg": str}


# =====
# MAIN
# =====

def main() -> None:
    print("Reading file and creating report...")

    if not os.path.exists(LOGFILE):
        raise SystemExit(f"Log file not found: {os.path.abspath(LOGFILE)}")

    with open(LOGFILE, "r", encoding="utf-8") as f:
        for line_num, raw in enumerate(f, start=1):
            line = raw.strip()

            # skip blanks and comments
            if not line or line.startswith("#"):
                continue

            parts = [p.strip() for p in line.split(",")]
            if len(parts) != 6:
                print(f"Skipping bad line {line_num}: {line}")
                continue

            ts_str, user, ip, host, port_str, status = parts

            user = user.lower()
            host = host.lower()
            status = status.upper()

            port = parse_port(port_str)
            if port is None:
                print(f"Skipping bad port line {line_num}: {port_str}")
                continue

            try:
                ts = datetime.strptime(ts_str, TS_FORMAT)
            except ValueError:
                print(f"Skipping bad timestamp line {line_num}: {ts_str}")
                continue

            cutoff = ts - WINDOW

            # ============
            # FAIL EVENTS
            # ============
            if status == "FAIL":
                # totals
                user_failures[user] += 1
                ip_failures[ip] += 1
                pair_failures[(user, ip)] += 1
                service_failures[(ip, host, port)] += 1

                # sliding window: per IP timestamps
                dq_ip = recent_fail_times_by_ip[ip]
                dq_ip.append(ts)
                while dq_ip and dq_ip[0] < cutoff:
                    dq_ip.popleft()

                # sliding window: per IP (timestamp, user)
                dq_users = recent_fail_users_by_ip[ip]
                dq_users.append((ts, user))
                while dq_users and dq_users[0][0] < cutoff:
                    dq_users.popleft()

                # sliding window: per (user, ip) timestamps
                pair = (user, ip)
                dq_pair = recent_fail_times_by_pair[pair]
                dq_pair.append(ts)
                while dq_pair and dq_pair[0] < cutoff:
                    dq_pair.popleft()

                # ==========================
                # BURST DETECTION (DEDUPED)
                # ==========================
                if len(dq_ip) >= BURST_THRESHOLD:
                    start = dq_ip[0].strftime(TS_FORMAT)
                    end = dq_ip[-1].strftime(TS_FORMAT)

                    if ip not in active_burst_ips:
                        bursts.append({
                            "ip": ip,
                            "start": start,
                            "end": end,
                            "fail_count_in_window": len(dq_ip),
                            "host": host,
                            "port": port,
                        })
                        active_burst_ips[ip] = ts

                        incident_feed.append({
                            "sev": severity("BURST"),
                            "time": ts,
                            "msg": (
                                f"[BURST] {ip} ({ip_scope(ip)}) -> {host}:{port} "
                                f"{len(dq_ip)} FAILs in {int(WINDOW.total_seconds()/60)}m window"
                            )
                        })
                    else:
                        # update the most recent incident for this IP
                        if bursts and bursts[-1]["ip"] == ip:
                            bursts[-1]["end"] = end
                            bursts[-1]["fail_count_in_window"] = len(dq_ip)
                            bursts[-1]["host"] = host
                            bursts[-1]["port"] = port
                else:
                    if ip in active_burst_ips:
                        del active_burst_ips[ip]

                # ==========================
                # SPRAY DETECTION (DEDUPED)
                # ==========================
                users_in_window = {u for _, u in dq_users}
                if len(dq_users) >= BURST_THRESHOLD and len(users_in_window) >= SPRAY_USERS_THRESHOLD:
                    start = dq_users[0][0].strftime(TS_FORMAT)
                    end = dq_users[-1][0].strftime(TS_FORMAT)

                    if ip not in active_spray_ips:
                        sprays.append({
                            "ip": ip,
                            "users": sorted(users_in_window),
                            "start": start,
                            "end": end,
                            "fail_count_in_window": len(dq_users),
                            "unique_users_in_window": len(users_in_window),
                            "host": host,
                            "port": port,
                        })
                        active_spray_ips[ip] = ts

                        incident_feed.append({
                            "sev": severity("SPRAY"),
                            "time": ts,
                            "msg": (
                                f"[SPRAY] {ip} ({ip_scope(ip)}) -> {host}:{port} "
                                f"{len(dq_users)} FAILs across {len(users_in_window)} users"
                            )
                        })
                    else:
                        if sprays and sprays[-1]["ip"] == ip:
                            sprays[-1]["end"] = end
                            sprays[-1]["fail_count_in_window"] = len(dq_users)
                            sprays[-1]["unique_users_in_window"] = len(users_in_window)
                            sprays[-1]["users"] = sorted(users_in_window)
                            sprays[-1]["host"] = host
                            sprays[-1]["port"] = port
                else:
                    if ip in active_spray_ips:
                        del active_spray_ips[ip]

            # ===============
            # SUCCESS EVENTS
            # ===============
            elif status == "SUCCESS":
                success_counts[user] += 1
                user_successes[user] += 1
                ip_successes[ip] += 1

                # Keep the pair fail deque clean for compromise logic
                pair = (user, ip)
                dq_pair = recent_fail_times_by_pair[pair]
                while dq_pair and dq_pair[0] < cutoff:
                    dq_pair.popleft()

                # =====================
                # COMPROMISE DETECTION
                # =====================
                if len(dq_pair) >= BURST_THRESHOLD:
                    key = (user, ip, ts_str)
                    if key not in compromise_found:
                        compromise_found.add(key)
                        compromised.append({
                            "user": user,
                            "ip": ip,
                            "host": host,
                            "port": port,
                            "start": dq_pair[0].strftime(TS_FORMAT),
                            "end": dq_pair[-1].strftime(TS_FORMAT),
                            "success_time": ts_str,
                            "fail_count_in_window": len(dq_pair),
                        })

                        incident_feed.append({
                            "sev": severity("COMPROMISE"),
                            "time": ts,
                            "msg": (
                                f"[COMPROMISE] {user} SUCCESS after {len(dq_pair)} FAILs "
                                f"from {ip} ({ip_scope(ip)}) on {host}:{port}"
                            )
                        })

                # ===========================================
                # NEW HOST / NEW PORT (after baseline exists)
                # ===========================================
                if success_counts[user] >= MIN_BASELINE_SUCCESSES:
                    # NEW HOST
                    if known_hosts_by_user[user] and host not in known_hosts_by_user[user]:
                        nh_key = (user, ip, host)
                        if nh_key not in new_host_seen:
                            new_host_seen.add(nh_key)
                            new_host_findings.append({
                                "user": user,
                                "ip": ip,
                                "new_host": host,
                                "time": ts_str,
                            })

                            incident_feed.append({
                                "sev": severity("NEW_HOST"),
                                "time": ts,
                                "msg": f"[NEW_HOST] {user} SUCCESS from {ip} ({ip_scope(ip)}) on new host {host}"
                            })

                    # NEW PORT
                    if known_ports_by_user[user] and port not in known_ports_by_user[user]:
                        np_key = (user, ip, host, port)
                        if np_key not in new_port_seen:
                            new_port_seen.add(np_key)
                            new_port_findings.append({
                                "user": user,
                                "ip": ip,
                                "host": host,
                                "new_port": port,
                                "time": ts_str,
                            })

                            incident_feed.append({
                                "sev": severity("NEW_PORT"),
                                "time": ts,
                                "msg": f"[NEW_PORT] {user} SUCCESS from {ip} ({ip_scope(ip)}) on {host} new port {port}"
                            })

                # ==================
                # IMPOSSIBLE TRAVEL
                # ==================
                dq_s = recent_success_by_user[user]
                dq_s.append((ts, ip, host, port))

                cutoff_s = ts - IMPOSSIBLE_TRAVEL_WINDOW
                while dq_s and dq_s[0][0] < cutoff_s:
                    dq_s.popleft()

                if len(dq_s) >= 2:
                    first_ts, first_ip, first_host, first_port = dq_s[0]
                    last_ts, last_ip, last_host, last_port = dq_s[-1]
                    time_diff = (last_ts - first_ts).total_seconds()

                    if first_ip != last_ip and time_diff <= IMPOSSIBLE_TRAVEL_MAX_SECONDS:
                        it_key = (user, first_ip, last_ip, ts_str)
                        if it_key not in impossible_travel_seen:
                            impossible_travel_seen.add(it_key)
                            impossible_travel_findings.append({
                                "user": user,
                                "from_ip": first_ip,
                                "to_ip": last_ip,
                                "from_time": first_ts.strftime(TS_FORMAT),
                                "to_time": last_ts.strftime(TS_FORMAT),
                                "from_host": first_host,
                                "to_host": last_host,
                                "from_port": first_port,
                                "to_port": last_port,
                            })

                            incident_feed.append({
                                "sev": severity("IMPOSSIBLE_TRAVEL"),
                                "time": ts,
                                "msg": (
                                    f"[IMPOSSIBLE_TRAVEL] {user} {first_ip} -> {last_ip} "
                                    f"in {int(time_diff)}s ({first_host}:{first_port} -> {last_host}:{last_port})"
                                )
                            })

                # Learn baseline from SUCCESS (always)
                known_hosts_by_user[user].add(host)
                known_ports_by_user[user].add(port)

            else:
                # unknown status → ignore
                continue

    # ==============
    # REPORT OUTPUT
    # ==============

    print("\nFailure counts:", dict(user_failures))
    print("Failures by IP:", dict(ip_failures))

    print("\nTOP 5 TARGETED SERVICES (ip -> host:port by FAILs)")
    for (src_ip, tgt_host, tgt_port), cnt in service_failures.most_common(5):
        print(f"- {src_ip} ({ip_scope(src_ip)}) -> {tgt_host}:{tgt_port}: {cnt} FAILs")

    print("\nFINDINGS")

    if bursts:
        print("\nBURST ATTACKS")
        for b in bursts:
            sev = severity("BURST")
            print(
                f"- [{sev}] {b['ip']}: {b['fail_count_in_window']} FAILs from {b['start']} to {b['end']} "
                f"target={b.get('host','?')}:{b.get('port','?')}"
            )

    if sprays:
        print("\nPASSWORD SPRAY")
        for s in sprays:
            sev = severity("SPRAY")
            users_list = ",".join(s["users"])
            print(
                f"- [{sev}] {s['ip']}: {s['fail_count_in_window']} FAILs, "
                f"{s['unique_users_in_window']} users from {s['start']} to {s['end']} users={users_list} "
                f"target={s.get('host','?')}:{s.get('port','?')}"
            )

    if compromised:
        print("\nPOSSIBLE COMPROMISE")
        for c in compromised:
            sev = severity("COMPROMISE")
            print(
                f"- [{sev}] {c['user']} @ {c['ip']}: {c['fail_count_in_window']} FAILs "
                f"({c['start']} to {c['end']}) then SUCCESS at {c['success_time']} "
                f"on {c.get('host','?')}:{c.get('port','?')}"
            )

    if new_host_findings:
        print("\nANOMALY: NEW HOST")
        for a in new_host_findings[:10]:
            sev = severity("NEW_HOST")
            print(f"- [{sev}] {a['user']} SUCCESS from {a['ip']} on NEW host {a['new_host']} at {a['time']}")

    if new_port_findings:
        print("\nANOMALY: NEW PORT")
        for a in new_port_findings[:10]:
            sev = severity("NEW_PORT")
            print(f"- [{sev}] {a['user']} SUCCESS from {a['ip']} on {a['host']} NEW port {a['new_port']} at {a['time']}")

    if impossible_travel_findings:
        print("\nANOMALY: IMPOSSIBLE TRAVEL")
        for a in impossible_travel_findings[:10]:
            sev = severity("IMPOSSIBLE_TRAVEL")
            print(
                f"- [{sev}] {a['user']}: {a['from_ip']}@{a['from_time']} -> {a['to_ip']}@{a['to_time']} "
                f"({a['from_host']}:{a['from_port']} -> {a['to_host']}:{a['to_port']})"
            )

    print(f"\nUSER WARNINGS (total FAILs >= {USER_THRESHOLD})")
    any_warn = False
    for u, cnt in user_failures.items():
        if cnt >= USER_THRESHOLD:
            any_warn = True
            sev = severity("USER_BRUTE_FORCE")
            print(f"- [{sev}] Warning: Possible brute force on user '{u}' (total FAILs: {cnt})")
    if not any_warn:
        print("None.")

    # =================
    # INCIDENT SUMMARY
    # =================
    if incident_feed:
        print("\nINCIDENT SUMMARY (sorted by severity then time)")
        incident_feed_sorted = sorted(
            incident_feed,
            key=lambda x: (sev_rank(x["sev"]), -x["time"].timestamp())
        )
        for item in incident_feed_sorted[:25]:
            print(f"- [{item['sev']}] {item['time'].strftime(TS_FORMAT)} {item['msg']}")


if __name__ == "__main__":
    main()
