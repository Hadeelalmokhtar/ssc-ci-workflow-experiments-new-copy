import sys
import os
import json
import subprocess
import time
import re
import tarfile
import tempfile
import base64
import threading
import urllib.request
import string
import ast
import math
import ipaddress
from collections import Counter
from http.server import BaseHTTPRequestHandler, HTTPServer
from dnslib.server import DNSServer, BaseResolver
from dnslib import RR, A

# ============================================================
# STORAGE
# ============================================================

captured_requests = []
captured_dns      = []

# ============================================================
# HELPERS — عامة
# ============================================================

def is_readable(s):
    printable = set(string.printable)
    return sum(c in printable for c in s) / max(len(s), 1) > 0.85


def try_decode_base64(s):
    try:
        d = base64.b64decode(s).decode("utf-8", errors="ignore")
        if len(d) > 20 and is_readable(d):
            return d
    except Exception:
        pass
    return None


def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True


def calculate_entropy(text):
    if not text:
        return 0.0
    counts = Counter(text)
    total  = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def edit_distance(a, b):
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            dp[i][j] = dp[i-1][j-1] if a[i-1] == b[j-1] else 1 + min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1])
    return dp[m][n]


def check_typosquatting(name):
    popular = [
        'requests', 'numpy', 'pandas', 'flask', 'django',
        'boto3', 'urllib3', 'setuptools', 'pip', 'six',
        'cryptography', 'paramiko', 'pyyaml', 'pillow'
    ]
    for pkg in popular:
        if name != pkg and edit_distance(name.lower(), pkg) <= 2:
            return pkg
    return None

# ============================================================
# FAKE HTTP SERVER — محسّن مع تحليل عميق للـ payload
# ============================================================

class SmartFakeHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        entry = {
            "method":  "GET",
            "path":    self.path,
            "headers": dict(self.headers),
        }
        response = {"status": "ok"}
        if "/api/config"  in self.path:
            response = {"mode": "active", "token": "eyJhbGciOiJIUzI1NiJ9.fake"}
        if "/api/key"     in self.path:
            response = {"api_key": "honey_sk-proj-fake123456"}
        if "/api/update"  in self.path:
            response = {"version": "2.1.0", "url": "http://127.0.0.1:8080/payload"}

        entry["response"] = response
        captured_requests.append(entry)

        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length)

        analysis = self._analyze_payload(body)

        captured_requests.append({
            "method":       "POST",
            "path":         self.path,
            "body_raw":     body.hex()[:500],
            "body_text":    body.decode("utf-8", errors="ignore")[:500],
            "content_type": self.headers.get("Content-Type", ""),
            "user_agent":   self.headers.get("User-Agent", ""),
            "analysis":     analysis,
        })

        # رد يشجع الكود على الاستمرار وإرسال المزيد
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"status":"ok","session":"accepted","next":"ready"}')

    def _analyze_payload(self, body):
        findings = {"payload_size": len(body)}

        # محاولة decode base64
        try:
            decoded = base64.b64decode(body).decode("utf-8", errors="ignore")
            if len(decoded) > 10 and is_readable(decoded):
                findings["base64_decoded"] = decoded[:300]
        except Exception:
            pass

        # JSON يحتوي على مفاتيح حساسة
        try:
            data = json.loads(body)
            sensitive_keys = [k for k in data.keys()
                              if any(w in str(k).lower()
                                     for w in ['password', 'token', 'key', 'secret', 'credential', 'auth'])]
            if sensitive_keys:
                findings["sensitive_json_keys"] = sensitive_keys
        except Exception:
            pass

        if len(body) > 1024:
            findings["large_exfil_attempt"] = True

        return findings

    def log_message(self, *args):
        pass  # suppress stdout noise


def start_http():
    HTTPServer(("0.0.0.0", 8080), SmartFakeHandler).serve_forever()

threading.Thread(target=start_http, daemon=True).start()

# ============================================================
# FAKE DNS SERVER
# ============================================================

class FakeResolver(BaseResolver):
    def resolve(self, request, handler):
        qname = str(request.q.qname)
        captured_dns.append({
            "query":     qname,
            "timestamp": round(time.time(), 3),
        })
        reply = request.reply()
        reply.add_answer(RR(qname, rdata=A("127.0.0.1"), ttl=60))
        return reply


def start_dns():
    DNSServer(FakeResolver(), port=5353, address="0.0.0.0").start()

threading.Thread(target=start_dns, daemon=True).start()

# ============================================================
# HONEYTOKENS — ملفات طُعم تبدو حقيقية
# ============================================================

def setup_honeytokens(base_dir):
    tokens = {
        ".env": (
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7FAKE123\n"
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/FAKE/KEY\n"
            "DB_PASSWORD=honey_db_pass_2024\n"
            "API_SECRET=honey_sk-proj-fake123\n"
            "REDIS_URL=redis://:honey_redis_pass@127.0.0.1:6379\n"
        ),
        ".aws/credentials": (
            "[default]\n"
            "aws_access_key_id=AKIAIOSFODNN7FAKE\n"
            "aws_secret_access_key=wJalrXUtnFEMI/FAKE/bPxRfiCYEXAMPLEKEY\n"
        ),
        "config.json": json.dumps({
            "api_key":   "honey_sk-proj-fake123",
            "db_host":   "10.0.0.1",
            "db_user":   "admin",
            "db_pass":   "honey_db_2024",
            "jwt_secret":"honey_jwt_secret_xyz"
        }, indent=2),
        ".ssh/id_rsa": (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEAFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n"
            "-----END RSA PRIVATE KEY-----\n"
        ),
        "secrets.yaml": (
            "database:\n"
            "  password: honey_yaml_pass_2024\n"
            "stripe:\n"
            "  secret_key: sk_live_FAKE_HONEY_KEY\n"
        ),
    }
    for rel_path, content in tokens.items():
        full_path = os.path.join(base_dir, rel_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w") as f:
            f.write(content)

# ============================================================
# STATIC ANALYSIS — قبل التشغيل
# ============================================================

def static_analysis(file_path):
    findings = {}
    try:
        with open(file_path, "r", errors="ignore") as f:
            source = f.read()
    except Exception:
        return {"error": "unreadable"}

    findings["entropy"]      = round(calculate_entropy(source), 3)
    findings["line_count"]   = source.count("\n")
    findings["has_obfuscation"] = findings["entropy"] > 5.5  # threshold

    # AST تحليل (Python فقط)
    if file_path.endswith(".py"):
        try:
            tree = ast.parse(source)
            dynamic_calls     = []
            string_concat_ops = 0
            suspicious_imports = []

            for node in ast.walk(tree):
                # eval / exec / compile
                if isinstance(node, ast.Call):
                    func_name = None
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        func_name = node.func.attr
                    if func_name in ("eval", "exec", "compile", "__import__"):
                        dynamic_calls.append(func_name)

                # string concatenation مشبوهة
                if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                    string_concat_ops += 1

                # imports مشبوهة
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name in ("socket", "subprocess", "ctypes", "pty", "os"):
                            suspicious_imports.append(alias.name)
                if isinstance(node, ast.ImportFrom):
                    if node.module in ("socket", "subprocess", "ctypes", "pty", "os"):
                        suspicious_imports.append(node.module)

            findings["dynamic_exec_calls"]  = dynamic_calls
            findings["string_concat_ops"]   = string_concat_ops
            findings["suspicious_imports"]  = list(set(suspicious_imports))
        except SyntaxError:
            findings["parse_failed"] = True  # نفسه مشبوه

    # Pattern matching في الكود الخام
    raw_patterns = {
        "reverse_shell_pattern": r'nc\s+-e|bash\s+-i\s+>&|/dev/tcp/',
        "encoded_exec":          r'exec\s*\(\s*base64|eval\s*\(\s*atob',
        "curl_wget":             r'\bcurl\b|\bwget\b',
        "env_access":            r'os\.environ|process\.env',
    }
    for label, pattern in raw_patterns.items():
        if re.search(pattern, source, re.IGNORECASE):
            findings[label] = True

    return findings

# ============================================================
# PACKAGE METADATA — supply chain specific
# ============================================================

def analyze_package_metadata(package_dir):
    findings = {}

    # Python: setup.py
    setup_py = os.path.join(package_dir, "setup.py")
    if os.path.exists(setup_py):
        with open(setup_py, errors="ignore") as f:
            content = f.read()
        if re.search(r'cmdclass|post_install|entry_points', content):
            findings["python_install_hooks"] = True
        if re.search(r'install_requires.*?(requests|urllib|socket)', content, re.DOTALL):
            findings["network_dependency"]   = True
        pkg_name = re.search(r'name\s*=\s*["\']([^"\']+)["\']', content)
        if pkg_name:
            name = pkg_name.group(1)
            findings["package_name"]      = name
            findings["typosquat_suspect"] = check_typosquatting(name)

    # npm: package.json
    pkg_json = os.path.join(package_dir, "package.json")
    if os.path.exists(pkg_json):
        try:
            with open(pkg_json) as f:
                data = json.load(f)
            scripts = data.get("scripts", {})
            for hook in ("preinstall", "postinstall", "prepare", "install"):
                if hook in scripts:
                    findings[f"npm_{hook}_script"] = scripts[hook]
            pkg_name = data.get("name", "")
            if pkg_name:
                findings["package_name"]      = pkg_name
                findings["typosquat_suspect"] = check_typosquatting(pkg_name)
        except Exception:
            pass

    return findings

# ============================================================
# WEIGHTED SCORING — بدل الـ scoring البسيط
# ============================================================

WEIGHTS = {
    "critical": 10,
    "high":      5,
    "medium":    2,
    "low":       1,
}

# (label, tier, regex)
BEHAVIOR_RULES = [
    # Critical
    ("sensitive_file_passwd",    "critical", r'/etc/passwd|/etc/shadow'),
    ("sensitive_file_ssh",       "critical", r'\.ssh/id_rsa|\.ssh/authorized_keys'),
    ("sensitive_file_env",       "critical", r'\.env|\.aws/credentials|secrets\.yaml'),
    ("reverse_shell",            "critical", r'execve.*nc.*-e|execve.*bash.*-i.*>&|/dev/tcp/'),
    ("encoded_payload_exec",     "critical", r'exec.*base64|eval.*decode'),
    ("process_injection",        "critical", r'ptrace|process_vm_readv|process_vm_writev'),
    # High
    ("spawns_shell",             "high",     r'execve.*"(/bin/bash|/bin/sh|/bin/dash|cmd\.exe)"'),
    ("outbound_post",            "high",     r'connect.*443|sendto.*POST'),
    ("unknown_dns_query",        "high",     r'connect.*53'),
    ("reads_browser_data",       "high",     r'\.mozilla|Chrome/Default|\.config/google-chrome'),
    ("reads_credentials_store",  "high",     r'Keychain|libsecret|kwallet'),
    # Medium
    ("opens_socket",             "medium",   r'socket\(AF_INET'),
    ("reads_proc_net",           "medium",   r'/proc/net|/proc/self/net'),
    ("reads_env_vars",           "medium",   r'getenv\(|/proc/self/environ'),
    ("large_file_write",         "medium",   r'write\(.*[0-9]{5,}'),
    # Low
    ("reads_tmp",                "low",      r'open\("(/tmp|/var/tmp)'),
    ("normal_file_read",         "low",      r'openat\(.*O_RDONLY'),
]

def calculate_score(strace_lines):
    score    = 0
    findings = []
    seen     = set()

    for line in strace_lines:
        for label, tier, pattern in BEHAVIOR_RULES:
            if label in seen:
                continue
            if re.search(pattern, line, re.IGNORECASE):
                score += WEIGHTS[tier]
                findings.append({
                    "label":    label,
                    "tier":     tier,
                    "weight":   WEIGHTS[tier],
                    "evidence": line[:150],
                })
                seen.add(label)

    return score, findings

# ============================================================
# BEHAVIORAL PHASES — MITRE ATT&CK inspired
# ============================================================

PHASE_PATTERNS = {
    "reconnaissance":    [r'/proc/cpuinfo', r'/etc/os-release', r'uname', r'/proc/net', r'ifconfig', r'hostname'],
    "defense_evasion":   [r'chmod.*777|chmod.*\+x', r'unlink\(', r'/proc/self/exe', r'prctl.*PR_SET_NAME'],
    "credential_access": [r'/etc/passwd', r'\.ssh/', r'\.aws/', r'\.env', r'Keychain', r'libsecret'],
    "exfiltration":      [r'connect.*443', r'connect.*80\b', r'sendto\(', r'POST.*http'],
    "execution":         [r'execve\(', r'system\(', r'popen\(', r'posix_spawn'],
    "persistence":       [r'crontab', r'\.bashrc', r'\.profile', r'/etc/init\.d', r'systemctl enable'],
    "discovery":         [r'getdents', r'stat\("/etc', r'/proc/\d+/status', r'sysinfo\('],
}

def build_behavioral_phases(timeline):
    phases = {k: [] for k in PHASE_PATTERNS}
    for event in timeline:
        evt_text = event.get("event", "")
        for phase, patterns in PHASE_PATTERNS.items():
            for p in patterns:
                if re.search(p, evt_text, re.IGNORECASE):
                    phases[phase].append({
                        "time":  event["time"],
                        "event": evt_text[:150],
                    })
                    break
    # فلترة: أبقِ أول 20 حدث فقط لكل phase
    return {k: v[:20] for k, v in phases.items()}

# ============================================================
# MEMORY STRINGS — يستخرج من /proc/PID/mem
# ============================================================

def dump_process_strings(pid):
    results = []
    try:
        maps_path = f"/proc/{pid}/maps"
        mem_path  = f"/proc/{pid}/mem"
        with open(maps_path, "r") as maps_f:
            for line in maps_f:
                parts = line.split()
                if len(parts) < 2 or "r" not in parts[1]:
                    continue
                start_s, end_s = parts[0].split("-")
                start, end = int(start_s, 16), int(end_s, 16)
                size = end - start
                if size > 8 * 1024 * 1024:  # تجاهل مناطق أكبر من 8MB (مكتبات)
                    continue
                try:
                    with open(mem_path, "rb") as mem_f:
                        mem_f.seek(start)
                        chunk = mem_f.read(size)
                    results.extend(_extract_strings_from_bytes(chunk))
                except Exception:
                    pass
    except Exception:
        pass
    return list(set(results))[:100]  # حد 100 string


def _extract_strings_from_bytes(data):
    found = []
    patterns = [
        rb'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',   # IPs
        rb'https?://[^\x00\s]{8,80}',               # URLs
        rb'[A-Za-z0-9+/]{24,}={0,2}',               # base64-like
        rb'/[a-zA-Z0-9_/.-]{6,60}',                 # file paths
        rb'[a-z0-9._-]{4,30}\.[a-z]{2,6}',          # domains
    ]
    for p in patterns:
        for m in re.finditer(p, data):
            try:
                s = m.group().decode("utf-8", errors="ignore")
                if is_readable(s):
                    found.append(s)
            except Exception:
                pass
    return found

# ============================================================
# IP ENRICHMENT — منفصلة عن وقت التشغيل
# ============================================================

def post_run_enrich_ips(ip_set):
    enriched = []
    for ip in ip_set:
        if is_private_ip(ip):
            enriched.append({"ip": ip, "private": True})
            continue
        try:
            raw  = urllib.request.urlopen(f"http://ip-api.com/json/{ip}", timeout=4).read()
            data = json.loads(raw)
            enriched.append({
                "ip":      ip,
                "country": data.get("country"),
                "isp":     data.get("isp"),
                "org":     data.get("org"),
                "risk":    "high" if data.get("proxy") or data.get("hosting") else "unknown",
            })
        except Exception:
            enriched.append({"ip": ip, "error": "lookup_failed"})
    return enriched

# ============================================================
# INPUT
# ============================================================

original_input = sys.argv[1]

# ============================================================
# EXTRACT
# ============================================================

def extract_package_if_needed(path):
    if path.endswith(".tgz") or path.endswith(".tar.gz"):
        temp_dir = tempfile.mkdtemp()
        with tarfile.open(path, "r:gz") as tar:
            tar.extractall(temp_dir)
        return temp_dir
    return path

file_path = extract_package_if_needed(original_input)

# ============================================================
# SETUP HONEYTOKENS داخل الـ package dir
# ============================================================

setup_honeytokens(file_path)

# ============================================================
# STATIC ANALYSIS — قبل التشغيل
# ============================================================

static_results   = {}
package_metadata = analyze_package_metadata(file_path)

# ============================================================
# FIND FILES
# ============================================================

targets = []
for root, _, fs in os.walk(file_path):
    for f in fs:
        if f.endswith(".js") or f.endswith(".py"):
            targets.append(os.path.join(root, f))

# static analysis لكل ملف
for t in targets:
    static_results[os.path.basename(t)] = static_analysis(t)

# ============================================================
# ENV — توجيه الشبكة للـ fake servers
# ============================================================

env = os.environ.copy()
env["HTTP_PROXY"]  = "http://127.0.0.1:8080"
env["HTTPS_PROXY"] = "http://127.0.0.1:8080"
env["NO_PROXY"]    = ""

# ============================================================
# MAIN ANALYSIS LOOP
# ============================================================

ips              = set()
domains          = set()
accessed_files   = []
processes        = []
timeline         = []
decoded_payloads = []
behavior_findings= []
memory_strings   = []

strace_all_lines = []
counter          = 0

for target in targets:
    run_cmd = ["node", target] if target.endswith(".js") else ["python3", target]

    processes.append(os.path.basename(target))
    processes.append(os.path.basename(run_cmd[0]))

    proc = subprocess.Popen(
        ["strace", "-tt", "-f", "-e", "trace=all"] + run_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        text=True,
        env=env,
    )

    # memory dump بعد ثانية من التشغيل
    def _mem_dump(pid):
        time.sleep(1)
        memory_strings.extend(dump_process_strings(pid))

    mem_thread = threading.Thread(target=_mem_dump, args=(proc.pid,), daemon=True)
    mem_thread.start()

    try:
        stdout, stderr = proc.communicate(input="trigger\n", timeout=60)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()

    for line in stderr.split("\n"):
        if not line:
            continue

        m = re.match(r'^(\d+\.\d+)\s+(.*)', line)
        if m:
            timestamp = float(m.group(1))
            event     = m.group(2)
        else:
            counter  += 1
            timestamp = round(counter * 0.01, 2)
            event     = line

        strace_all_lines.append(event)

        timeline.append({
            "time":  timestamp,
            "event": event[:200],
        })

        # processes
        if "execve(" in event:
            m2 = re.search(r'execve\("([^"]+)"', event)
            if m2:
                processes.append(os.path.basename(m2.group(1)))

        # IPs
        for ip in re.findall(r'\d+\.\d+\.\d+\.\d+', event):
            ips.add(ip)

        # domains
        for d in re.findall(r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', event):
            domains.add(d)

        # file access
        if "open(" in event or "openat(" in event:
            fmatch = re.search(r'"([^"]+)"', event)
            if fmatch:
                accessed_files.append(fmatch.group(1))

        # base64 payloads
        for s in re.findall(r'[A-Za-z0-9+/=]{20,}', event):
            decoded = try_decode_base64(s)
            if decoded:
                decoded_payloads.append(decoded)

# ============================================================
# SCORING — weighted
# ============================================================

score, behavior_findings = calculate_score(strace_all_lines)

# bonus من static analysis
for fname, sa in static_results.items():
    if sa.get("has_obfuscation"):
        score += 5
        behavior_findings.append({"label": "obfuscated_code", "tier": "high", "weight": 5, "file": fname})
    if sa.get("dynamic_exec_calls"):
        score += 3
        behavior_findings.append({"label": "dynamic_exec_in_source", "tier": "high", "weight": 3, "file": fname})
    if sa.get("reverse_shell_pattern"):
        score += 10
        behavior_findings.append({"label": "reverse_shell_in_source", "tier": "critical", "weight": 10, "file": fname})

# bonus من package metadata
if package_metadata.get("python_install_hooks") or any(
        package_metadata.get(f"npm_{h}_script") for h in ("preinstall","postinstall","prepare","install")):
    score += 5
    behavior_findings.append({"label": "install_hook_detected", "tier": "high", "weight": 5})

if package_metadata.get("typosquat_suspect"):
    score += 3
    behavior_findings.append({
        "label":   "typosquatting_suspect",
        "tier":    "medium",
        "weight":  3,
        "similar_to": package_metadata["typosquat_suspect"],
    })

# ============================================================
# VERDICT
# ============================================================

verdict = "CLEAN"
if score >= 1:
    verdict = "SUSPICIOUS"
if score >= 10:
    verdict = "MALICIOUS"
if score >= 20:
    verdict = "CRITICAL"

# ============================================================
# BEHAVIORAL PHASES
# ============================================================

behavioral_phases = build_behavioral_phases(timeline)

# ============================================================
# PROCESS GRAPH
# ============================================================

graph_edges = []
prev        = "Package"
for p in processes:
    graph_edges.append({"from": prev, "to": p})
    prev = p

# ============================================================
# IP ENRICHMENT — بعد انتهاء التشغيل (آمن)
# ============================================================

network_details = post_run_enrich_ips(ips)

# ============================================================
# HONEYTOKENS ACCESS — هل لمس الكود الملفات الطُعم؟
# ============================================================

honeytoken_paths = [".env", ".aws/credentials", "config.json", ".ssh/id_rsa", "secrets.yaml"]
honeytoken_hits  = [f for f in accessed_files if any(h in f for h in honeytoken_paths)]

# ============================================================
# SAVE
# ============================================================

os.makedirs("decoy_logs/decoy_runs", exist_ok=True)

log = {
    # --- معلومات أساسية ---
    "package": os.path.basename(original_input),
    "verdict": verdict,
    "score":   score,
    "run_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),

    # --- نتائج الـ scoring المفصّلة ---
    "behavior_findings":  behavior_findings,
    "behavioral_phases":  behavioral_phases,

    # --- static analysis ---
    "static_analysis":    static_results,
    "package_metadata":   package_metadata,

    # --- honeytokens ---
    "honeytoken_hits":    honeytoken_hits,

    # --- network ---
    "domains":            list(domains),
    "dns":                captured_dns,
    "http_requests":      captured_requests,
    "network_details":    network_details,

    # --- execution ---
    "processes":          list(set(processes)),
    "graph_edges":        graph_edges,
    "accessed_files":     list(set(accessed_files)),
    "decoded_payloads":   decoded_payloads,

    # --- memory ---
    "memory_strings":     list(set(memory_strings))[:100],

    # --- raw timeline (كامل بدون قطع) ---
    "timeline":           timeline,
}

run_id = str(int(time.time()))

with open(f"decoy_logs/decoy_runs/log_{run_id}.json", "w") as f:
    json.dump(log, f, indent=4, ensure_ascii=False)

with open("decoy_logs/latest.json", "w") as f:
    json.dump(log, f, indent=4, ensure_ascii=False)

print(f"Saved: {run_id} | Verdict: {verdict} | Score: {score}")
