#!/usr/bin/env python3
"""
Synthetic syslog traffic generator for SIEM / Splunk pipeline labs.

Standard library only. Generates realistic-looking but synthetic logs in
multiple formats and transports them over UDP or TCP.

Examples:
  python3 syslog_pipeline_generator.py -H 10.0.0.46 --dport 514 -p udp -n 100
  python3 syslog_pipeline_generator.py -H 10.0.0.46 --dport 514 -p tcp -n 50 --interval 0.1
  python3 syslog_pipeline_generator.py -H 10.0.0.46 --dport 514 -p udp --format mixed --profile mixed --action mixed

All passwords, tokens, and card numbers are synthetic test values intended for
masking / routing exercises. They are not real credentials.
"""

import argparse
import json
import random
import socket
import string
import sys
import time
import uuid
from datetime import datetime, timezone

PROFILES = {
    "firewall": [
        "FW-EDGE-01", "FW-EDGE-02", "FW-DC-01", "PA-FW-01", "ASA-EDGE-01"
    ],
    "windows": [
        "WIN-DC-01", "WIN-APP-01", "WIN-FS-01", "WIN-AD-02", "WIN-WS-104"
    ],
    "linux": [
        "LNX-WEB-01", "LNX-AUTH-01", "LNX-DB-01", "UBU-APP-02", "RHEL-SRV-03"
    ],
    "web": [
        "WEB-01", "WEB-02", "NGINX-01", "APACHE-01", "PROXY-01"
    ],
    "dns": ["DNS-01", "DNS-02", "BIND-01", "WIN-DNS-01"],
    "database": ["DB-01", "DB-02", "PGSQL-01", "MSSQL-01"],
    "application": ["APP-01", "APP-02", "API-01", "PAYMENTS-01"],
    "cloud": ["AZ-VM-01", "AWS-EC2-02", "GCP-VM-03", "CLOUD-GW-01"],
}

PROTOCOLS = ["TCP", "UDP", "ICMP"]
USERS = ["alice", "bob", "charlie", "svc_backup", "svc_web", "admin", "analyst"]
DOMAINS = ["corp.example", "lab.example", "internal.example", "example.test"]
PRIVATE_IPS = [
    "10.10.12.15", "10.20.5.23", "172.16.4.81", "172.20.30.14",
    "192.168.10.44", "192.168.50.77", "192.168.100.23"
]
PUBLIC_TEST_IPS = [
    "198.51.100.17", "198.51.100.42", "203.0.113.9", "203.0.113.55", "192.0.2.88"
]
URL_PATHS = [
    "/login", "/api/v1/users", "/admin/export", "/health", "/checkout",
    "/download/report.csv", "/wp-login.php", "/oauth/token", "/index.html"
]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140.0",
    "curl/8.10.1",
    "python-requests/2.32",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/142.0",
]

# Synthetic data intentionally used for masking tests.
TEST_PASSWORDS = [
    "TestP@ssw0rd!", "LabOnly-Password-123!", "S3cur3Lab!", "Winter2026!Lab"
]
TEST_TOKENS = [
    "lab-token-7f3a9d2c", "Bearer-TEST-4c8b2e91", "sk-test-91f4a2c7"
]
TEST_CARDS = [
    "4111111111111111",  # common test Visa number
    "5555555555554444",  # common test Mastercard number
    "4000000000000002",  # common test Visa number
]


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return now_utc().isoformat(timespec="milliseconds").replace("+00:00", "Z")


def r_ip(public=False) -> str:
    return random.choice(PUBLIC_TEST_IPS if public else PRIVATE_IPS)


def rand_port() -> int:
    return random.randint(1024, 65535)


def rand_user() -> str:
    return random.choice(USERS)


def rand_password() -> str:
    return random.choice(TEST_PASSWORDS)


def rand_card() -> str:
    return random.choice(TEST_CARDS)


def rand_id(prefix="evt") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def rand_hex(n=12) -> str:
    chars = string.hexdigits.lower()
    return "".join(random.choice(chars) for _ in range(n))


def checksumish_card(card: str) -> str:
    # Preserve a familiar test-card shape while allowing deterministic masking demos.
    return card


def choose_profile(requested: str) -> str:
    if requested == "mixed":
        return random.choice(list(PROFILES))
    return requested


def choose_format(requested: str) -> str:
    if requested == "mixed":
        return random.choice(["rfc3164", "rfc5424", "kv", "json", "cef", "plain"])
    return requested


def syslog_priority(profile: str) -> tuple[int, int]:
    # Facility/severity pairs chosen for realism rather than strict vendor mapping.
    choices = {
        "firewall": [(4, 5), (4, 6), (13, 5), (10, 4)],
        "windows": [(10, 6), (10, 5), (4, 6)],
        "linux": [(10, 5), (10, 6), (4, 5)],
        "web": [(10, 6), (16, 6)],
        "dns": [(14, 6), (5, 5)],
        "database": [(11, 5), (11, 6)],
        "application": [(16, 6), (16, 5)],
        "cloud": [(16, 5), (4, 5)],
    }
    return random.choice(choices[profile])


def body_firewall(host: str, action: str, event_id: str) -> str:
    src = r_ip(public=True)
    dst = r_ip(public=False)
    sport = rand_port()
    dport = random.choice([22, 53, 80, 123, 443, 514, 3389, 8080, 8443])
    proto = random.choice(PROTOCOLS[:2])
    rule = random.choice(["ALLOW_WEB_OUT", "DENY_SSH_IN", "BLOCK_SUSPICIOUS_GEO", "ALLOW_DNS", "DROP_MALFORMED"])
    reason = random.choice(["policy-match", "geoip-policy", "signature-match", "rate-limit", "default-deny"])
    return (
        f"device={host} action={action} event_id={event_id} rule={rule} "
        f"src={src}:{sport} dst={dst}:{dport} proto={proto} zone=untrust->trust "
        f"reason={reason} bytes={random.randint(64, 14800)} packets={random.randint(1, 80)}"
    )


def body_windows(host: str, action: str, event_id: str) -> str:
    user = rand_user()
    src = r_ip(public=True)
    logon_type = random.choice([2, 3, 4, 5, 7, 10])
    event_id_win = random.choice([4624, 4625, 4688, 4672])
    status = "Success" if action != "DROP" and event_id_win != 4625 else "Failure"
    return (
        f"EventID={event_id_win} Computer={host} User={user} Domain=LAB "
        f"LogonType={logon_type} IpAddress={src} Status={status} "
        f"ProcessName=C:\\Windows\\System32\\svchost.exe "
        f"Password={rand_password()} CreditCard={checksumish_card(rand_card())} "
        f"CorrelationId={event_id}"
    )


def body_linux(host: str, action: str, event_id: str) -> str:
    user = rand_user()
    src = r_ip(public=True)
    service = random.choice(["sshd", "sudo", "su", "systemd-logind"])
    outcome = random.choice(["accepted", "failed", "session-opened", "session-closed"])
    pid = random.randint(700, 65000)
    return (
        f"{service}[{pid}]: {outcome} user={user} rhost={src} "
        f"tty=pts/{random.randint(0,9)} cmd=\"sudo /usr/bin/systemctl status nginx\" "
        f"token={random.choice(TEST_TOKENS)} event_id={event_id} action={action}"
    )


def body_web(host: str, action: str, event_id: str) -> str:
    src = r_ip(public=True)
    path = random.choice(URL_PATHS)
    status = random.choice([200, 200, 201, 302, 401, 403, 404, 500])
    method = random.choice(["GET", "POST", "PUT"])
    bytes_out = random.randint(200, 80000)
    ua = random.choice(USER_AGENTS)
    # Includes secrets in query/form-like content for masking exercises.
    return (
        f'{src} - {rand_user()} [{now_utc().strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{method} {path} HTTP/1.1" '
        f'{status} {bytes_out} "https://portal.{random.choice(DOMAINS)}/" "{ua}" '
        f'password={rand_password()} credit_card={rand_card()} request_id={event_id}'
    )


def body_dns(host: str, action: str, event_id: str) -> str:
    qname = random.choice([
        "login.lab.example", "updates.corp.example", "cdn.example.test",
        "files.internal.example", "api.corp.example", "random.invalid"
    ])
    qtype = random.choice(["A", "AAAA", "TXT", "MX", "CNAME"])
    src = r_ip(public=False)
    ans = random.choice(["NOERROR", "NXDOMAIN", "SERVFAIL"])
    return (
        f"query={qname} qtype={qtype} src={src} resolver={host} answer={ans} "
        f"latency_ms={random.randint(1,180)} client_token={random.choice(TEST_TOKENS)} "
        f"action={action} event_id={event_id}"
    )


def body_database(host: str, action: str, event_id: str) -> str:
    user = random.choice(["app_user", "report_user", "dba", "svc_sql"])
    table = random.choice(["customers", "orders", "audit_log", "payments", "sessions"])
    rows = random.randint(1, 900)
    return (
        f"db={host} user={user} database=labdb operation={random.choice(['SELECT','UPDATE','INSERT','DELETE'])} "
        f"table={table} rows={rows} duration_ms={random.randint(1,700)} "
        f"password={rand_password()} credit_card={rand_card()} action={action} event_id={event_id}"
    )


def body_application(host: str, action: str, event_id: str) -> str:
    level = random.choice(["INFO", "WARN", "ERROR"])
    return (
        f"{iso_now()} level={level} service=checkout host={host} event=payment_attempt "
        f"user={rand_user()} order_id=ORD-{random.randint(100000,999999)} amount={random.randint(15,950)} "
        f"currency=USD password={rand_password()} card_number={rand_card()} "
        f"api_token={random.choice(TEST_TOKENS)} action={action} trace_id={event_id}"
    )


def body_cloud(host: str, action: str, event_id: str) -> str:
    src = r_ip(public=True)
    return (
        f'{{"cloud":"azure","resource":"{host}","operation":"SignIn","user":"{rand_user()}@{random.choice(DOMAINS)}",'
        f'"ip":"{src}","result":"{random.choice(["Success","Failure"])}",'
        f'"token":"{random.choice(TEST_TOKENS)}","password":"{rand_password()}",'
        f'"event_id":"{event_id}","action":"{action}"}}'
    )


BODY_BUILDERS = {
    "firewall": body_firewall,
    "windows": body_windows,
    "linux": body_linux,
    "web": body_web,
    "dns": body_dns,
    "database": body_database,
    "application": body_application,
    "cloud": body_cloud,
}


def build_payload(profile: str, fmt: str, host: str, action: str, event_id: str) -> str:
    body = BODY_BUILDERS[profile](host, action, event_id)
    pri_fac, pri_sev = syslog_priority(profile)
    pri = pri_fac * 8 + pri_sev
    dt = now_utc()

    if fmt == "rfc3164":
        stamp = dt.strftime("%b %d %H:%M:%S")
        app = {
            "firewall": "filterlog", "windows": "winlog", "linux": "sshd",
            "web": "nginx", "dns": "named", "database": "postgres",
            "application": "checkout", "cloud": "cloud-audit"
        }[profile]
        pid = random.randint(100, 65000)
        return f"<{pri}>{stamp} {host} {app}[{pid}]: {body}"

    if fmt == "rfc5424":
        app = {
            "firewall": "firewalld", "windows": "eventlog", "linux": "sshd",
            "web": "nginx", "dns": "named", "database": "postgres",
            "application": "checkout-api", "cloud": "cloudtrail"
        }[profile]
        return f"<{pri}>1 {dt.strftime('%Y-%m-%dT%H:%M:%S.%fZ')} {host} {app} {random.randint(100,99999)} {event_id} - {body}"

    if fmt == "kv":
        return f"<{pri}> {iso_now()} host={host} profile={profile} event_id={event_id} {body}"

    if fmt == "json":
        obj = {
            "timestamp": iso_now(),
            "host": host,
            "profile": profile,
            "event_id": event_id,
            "severity": random.choice(["info", "warning", "error"]),
            "action": action,
            "message": body,
            "user": rand_user(),
            "password": rand_password(),
            "credit_card": rand_card(),
            "api_token": random.choice(TEST_TOKENS),
        }
        return f"<{pri}> {json.dumps(obj, separators=(',', ':'))}"

    if fmt == "cef":
        src = r_ip(public=True)
        dst = r_ip(public=False)
        cef = (
            f"CEF:0|LabVendor|Synthetic-{profile}|1.0|{event_id}|Synthetic {profile} event|"
            f"{random.choice([3,5,7,9])}|src={src} dst={dst} dpt={random.choice([22,53,80,443,514,3389])} "
            f"proto={random.choice(['TCP','UDP'])} suser={rand_user()} "
            f"password={rand_password()} requestToken={random.choice(TEST_TOKENS)} "
            f"credit_card={rand_card()} act={action}"
        )
        return f"<{pri}> {cef}"

    # plain
    return f"<{pri}> {iso_now()} {host} [{profile}] {body}"


def send_udp(sock: socket.socket, payload: bytes, host: str, port: int) -> None:
    sock.sendto(payload, (host, port))


def send_tcp(sock: socket.socket, payload: bytes) -> None:
    # Common newline-delimited syslog framing (RFC 6587 non-transparent framing).
    sock.sendall(payload + b"\n")


def connect_tcp(host: str, port: int, timeout: float) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((host, port))
    return sock


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Generate synthetic syslog traffic for SIEM pipeline testing.")
    p.add_argument("-H", "--host", required=True, help="Destination syslog host/IP")
    p.add_argument("--dport", type=int, default=514, help="Destination port (default: 514)")
    p.add_argument("-p", "--protocol", choices=["tcp", "udp"], default="udp", help="Transport protocol")
    p.add_argument("-n", "--count", type=int, default=100, help="Number of messages; 0 = run forever")
    p.add_argument("-i", "--interval", type=float, default=0.10, help="Seconds between messages")
    p.add_argument("--profile", choices=sorted(list(PROFILES) + ["mixed"]), default="mixed")
    p.add_argument("--format", choices=["rfc3164", "rfc5424", "kv", "json", "cef", "plain", "mixed"], default="mixed")
    p.add_argument("--action", choices=["ALLOW", "DROP", "DENY", "BLOCK", "mixed"], default="mixed")
    p.add_argument("--hostname", help="Force one hostname for every event")
    p.add_argument("--tcp-reconnect", action="store_true", help="Reconnect after every TCP message")
    p.add_argument("--timeout", type=float, default=5.0, help="TCP connect timeout")
    p.add_argument("--seed", type=int, help="Random seed for repeatable patterns (IDs remain unique)")
    p.add_argument("--dry-run", action="store_true", help="Print generated events; do not send")
    p.add_argument("-v", "--verbose", action="count", default=0,
                   help="Show send progress; repeat (-vv or -vvv) for more detail")
    return p.parse_args()


def choose_action(requested: str) -> str:
    return random.choice(["ALLOW", "DROP", "DENY", "BLOCK"]) if requested == "mixed" else requested


def main() -> int:
    args = parse_args()
    if args.dport < 1 or args.dport > 65535:
        raise SystemExit("--dport must be between 1 and 65535")
    if args.count < 0:
        raise SystemExit("--count must be 0 or greater")
    if args.interval < 0:
        raise SystemExit("--interval must be >= 0")
    if args.seed is not None:
        random.seed(args.seed)

    tcp_sock = None
    udp_sock = None
    sent = 0

    if args.verbose:
        mode = "DRY-RUN" if args.dry_run else "SEND"
        count_label = "forever" if args.count == 0 else str(args.count)
        print(
            f"[{mode}] {args.protocol.upper()} -> {args.host}:{args.dport} "
            f"count={count_label} interval={args.interval}s "
            f"profile={args.profile} format={args.format} action={args.action}",
            flush=True,
        )

    if not args.dry_run:
        if args.protocol == "tcp":
            tcp_sock = connect_tcp(args.host, args.dport, args.timeout)
        else:
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        while args.count == 0 or sent < args.count:
            profile = choose_profile(args.profile)
            fmt = choose_format(args.format)
            action = choose_action(args.action)
            host = args.hostname or random.choice(PROFILES[profile])
            event_id = rand_id(profile[:3])
            payload = build_payload(profile, fmt, host, action, event_id)

            if args.dry_run:
                print(payload, flush=True)
            elif args.protocol == "udp":
                data = payload.encode("utf-8")
                send_udp(udp_sock, data, args.host, args.dport)
                if args.verbose >= 1:
                    print(f"[sent {sent + 1}] UDP {len(data)} bytes -> {args.host}:{args.dport} host={host} profile={profile} event_id={event_id}", flush=True)
                if args.verbose >= 3:
                    print(f"          {payload}", flush=True)
            else:
                if args.tcp_reconnect:
                    tcp_sock.close()
                    tcp_sock = connect_tcp(args.host, args.dport, args.timeout)
                data = payload.encode("utf-8")
                send_tcp(tcp_sock, data)
                if args.verbose >= 1:
                    print(f"[sent {sent + 1}] TCP {len(data)} bytes -> {args.host}:{args.dport} host={host} profile={profile} event_id={event_id}", flush=True)
                if args.verbose >= 3:
                    print(f"          {payload}", flush=True)

            sent += 1
            if args.interval:
                time.sleep(args.interval)
    except KeyboardInterrupt:
        print(f"\nStopped. Generated {sent} message(s).", file=sys.stderr)
    finally:
        if tcp_sock is not None:
            tcp_sock.close()
        if udp_sock is not None:
            udp_sock.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
