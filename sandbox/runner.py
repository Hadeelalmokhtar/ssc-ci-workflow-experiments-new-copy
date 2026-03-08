import sys
import os
import json
import subprocess
import time
import re
import tarfile
import tempfile
import urllib.request
from datetime import datetime
from collections import defaultdict

# ============================
# INPUT
# ============================

if len(sys.argv) < 2:
    print("Usage: python runner.py <file>")
    sys.exit(1)

original_input = sys.argv[1]

# ============================
# EXTRACT PACKAGE
# ============================

def extract_package_if_needed(path):
    if path.endswith(".tgz") or path.endswith(".tar.gz"):
        temp_dir = tempfile.mkdtemp()
        with tarfile.open(path, "r:gz") as tar:
            tar.extractall(temp_dir)
        return temp_dir
    return path

file_path = extract_package_if_needed(original_input)

# ============================
# FIND EXECUTABLE
# ============================

analysis_target = None

for root, dirs, files in os.walk(file_path):
    for f in files:
        if f.endswith(".js") or f.endswith(".py"):
            analysis_target = os.path.join(root, f)
            break
    if analysis_target:
        break

if analysis_target is None:
    print("No executable file found")
    sys.exit(0)

# ============================
# THREAT INTEL LOOKUP
# ============================

def enrich_ip(ip):
    try:
        url = f"http://ip-api.com/json/{ip}"
        response = urllib.request.urlopen(url, timeout=3)
        data = json.loads(response.read().decode())

        return {
            "ip": ip,
            "country": data.get("country"),
            "asn": data.get("as"),
            "org": data.get("org"),
            "isp": data.get("isp")
        }

    except:
        return {"ip": ip}

# ============================
# MALWARE FAMILY HINT
# ============================

def detect_family(commands):
    for c in commands:

        if "curl" in c or "wget" in c:
            return "Downloader"

        if "xmrig" in c:
            return "Crypto Miner"

        if "nc" in c or "netcat" in c:
            return "Backdoor"

    return "Unknown"

# ============================
# SANDBOX EXECUTION
# ============================

print("Starting dynamic analysis")

start = time.time()

# ---------- TCPDUMP (OPTIONAL) ----------
pcap_file = "network_capture.pcap"
tcpdump = None

try:
    tcpdump = subprocess.Popen(
        ["tcpdump", "-i", "any", "-w", pcap_file],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
except FileNotFoundError:
    print("tcpdump not available in sandbox - skipping capture")

# ---------- Runtime ----------

if analysis_target.endswith(".js"):
    run_cmd = ["node", analysis_target]
else:
    run_cmd = ["python3", analysis_target]

process = subprocess.Popen(

    ["strace", "-f", "-e", "trace=execve,open,connect,write,sendto"] + run_cmd,

    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True

)

try:
    stdout, stderr = process.communicate(timeout=20)

except subprocess.TimeoutExpired:
    process.kill()
    stdout, stderr = process.communicate()

if tcpdump:
    tcpdump.kill()

runtime = round(time.time() - start, 3)

# ============================
# PARSE EVENTS
# ============================

commands = set()
ips = set()
domains = set()

dns_activity = []
processes = []
files = []
timeline = []
syscalls = defaultdict(int)
sensitive = []

sensitive_paths = [
    "/etc/passwd",
    "/etc/shadow",
    ".ssh",
    "/root",
    ".env",
    "id_rsa"
]

ip_regex = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
domain_regex = r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

for line in stderr.split("\n"):
    if not line:
        continue

    timeline.append(line)

    parts = line.split("(")[0].split()

    if parts:
        syscall = parts[-1]
        syscalls[syscall] += 1

    # PROCESS
    if "execve(" in line:

        m = re.search(r'execve\("([^"]+)"', line)

        if m:
            proc = os.path.basename(m.group(1))
            processes.append(proc)
            commands.add(proc)

    # NETWORK IP
    ips_found = re.findall(ip_regex, line)
    for ip in ips_found:
        ips.add(ip)

    # DOMAIN IOC
    dom = re.findall(domain_regex, line)
    for d in dom:
        domains.add(d)

    # DNS
    if "sendto(" in line:
        dns_activity.append("DNS query detected")

    # FILE
    if "open(" in line:

        f = re.search(r'"([^"]+)"', line)

        if f:
            path = f.group(1)
            files.append(path)

            for s in sensitive_paths:
                if s in path:
                    sensitive.append(path)

# ============================
# ENRICH IPS
# ============================

network_details = []

for ip in ips:
    network_details.append(enrich_ip(ip))

# ============================
# MITRE MAPPING
# ============================

mitre = []

if ips:
    mitre.append("T1071 Application Layer Protocol")

if commands:
    mitre.append("T1059 Command Interpreter")

if sensitive:
    mitre.append("T1005 Data from Local System")

if dns_activity:
    mitre.append("T1046 Network Discovery")

# ============================
# BEHAVIOR SCORE
# ============================

score = len(ips)*3 + len(commands)*2 + len(sensitive)*4 + len(domains)*2

verdict = "CLEAN"

if score > 5:
    verdict = "SUSPICIOUS"

if score > 10:
    verdict = "MALICIOUS"

family = detect_family(commands)

# ============================
# ATTACK GRAPH
# ============================

nodes = [{"id": 1, "label": "Package"}]
edges = []

i = 2

for p in processes:

    nodes.append({"id": i, "label": p})
    edges.append({"from": 1, "to": i})

    i += 1

attack_graph = {
    "nodes": nodes,
    "edges": edges
}

# ============================
# IOC
# ============================

ioc = {
    "ips": list(ips),
    "domains": list(domains)
}

# ============================
# SAVE LOG
# ============================

os.makedirs("decoy_logs", exist_ok=True)

run_id = str(int(time.time()))
mitre = list(set(mitre))
log = {

    "run_id": run_id,

    "package": {
        "name": os.path.basename(original_input)
    },

    "runtime": runtime,

    "behavior_score": score,

    "malware_family_hint": family,

    "threat_verdict": verdict,

    "ioc": ioc,

    "commands_detected": list(commands),

    "network_activity": {
        "details": network_details
    },

    "dns_activity": dns_activity,

    "process_activity": processes,

    "filesystem": files,

    "sensitive_access": sensitive,

    "mitre": mitre,

    "attack_graph": attack_graph,

    "timeline": timeline[:40],

    "timestamp": datetime.utcnow().isoformat()

}

with open(f"decoy_logs/log_{run_id}.json", "w") as f:
    json.dump(log, f, indent=4)

with open("decoy_logs/latest.json", "w") as f:
    json.dump(log, f, indent=4)

print("Analysis finished")
