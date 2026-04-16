import sys
import os
import json
import subprocess
import time
import re
import tarfile
import tempfile
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

# ============================
# STORAGE
# ============================

captured_requests = []
captured_dns = []

# ============================
# FAKE HTTP SERVER
# ============================

class FakeHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        captured_requests.append({"method": "GET","path": self.path})
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode()

        captured_requests.append({
            "method": "POST",
            "path": self.path,
            "body": body
        })

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

def start_http():
    HTTPServer(("0.0.0.0", 8080), FakeHandler).serve_forever()

threading.Thread(target=start_http, daemon=True).start()

# ============================
# DNS SERVER
# ============================

from dnslib.server import DNSServer, BaseResolver
from dnslib import RR, A

class FakeResolver(BaseResolver):
    def resolve(self, request, handler):
        qname = str(request.q.qname)
        captured_dns.append(qname)

        reply = request.reply()
        reply.add_answer(RR(qname, rdata=A("127.0.0.1"), ttl=60))
        return reply

def start_dns():
    DNSServer(FakeResolver(), port=5353, address="0.0.0.0").start()

threading.Thread(target=start_dns, daemon=True).start()

# ============================
# INPUT
# ============================

original_input = sys.argv[1]

# ============================
# EXTRACT
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
# FIND FILES
# ============================

targets = []
for root, _, files in os.walk(file_path):
    for f in files:
        if f.endswith(".js") or f.endswith(".py"):
            targets.append(os.path.join(root, f))

env = os.environ.copy()

# ============================
# ANALYSIS
# ============================

ips = set()
domains = set()
files = []
processes = []
timeline = []
commands = []

counter = 0

for target in targets:

    run_cmd = ["node", target] if target.endswith(".js") else ["python3", target]

    process = subprocess.Popen(
        ["strace", "-ff", "-s", "200", "-e", "trace=process,network,file"] + run_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env
    )

    try:
        _, stderr = process.communicate(timeout=60)
    except:
        process.kill()
        _, stderr = process.communicate()

    for line in stderr.split("\n"):

        if not line:
            continue

        # TIMELINE
        counter += 1
        timeline.append({
            "time": round(counter * 0.01, 2),
            "event": line[:200]
        })

        # PROCESS
        if any(x in line for x in ["execve", "clone", "fork", "vfork"]):
            m = re.search(r'execve\("([^"]+)"', line)
            if m:
                processes.append(os.path.basename(m.group(1)))

        # COMMANDS
        if "execve(" in line or "system(" in line:
            m = re.search(r'"([^"]+)"', line)
            if m:
                commands.append(m.group(1))

        # ============================
        # DNS + DOMAIN (FIXED )
        # ============================
        if "connect(" in line:

            matches = re.findall(r'"([^"]+)"', line)

            for x in matches:

                # IP detection
                if re.match(r'\d+\.\d+\.\d+\.\d+', x):
                    captured_dns.append(x)
                    ips.add(x)
                    continue

                # DOMAIN detection
                if "." not in x:
                    continue

                if x.endswith((".conf", ".pem", ".res", ".so", ".json")):
                    continue

                if "/" in x:
                    continue

                domains.add(x)

            # network event
            timeline.append({
                "time": round(counter * 0.01, 2),
                "event": "NETWORK CONNECTION DETECTED"
            })

        # FILESYSTEM
        if any(x in line for x in ["open(", "read(", "write(", "access("]):
            f = re.search(r'"([^"]+)"', line)
            if f:
                file_path = f.group(1)

                # ignore system
                if file_path.startswith(("/etc", "/usr", "/lib", "/proc", "/dev")):
                    continue

                if file_path.endswith(".so"):
                    continue

                if any(x in file_path for x in [
                    "/home", "/root", "/tmp",
                    ".env", ".ssh", "id_rsa", "passwd", "shadow"
                ]):
                    files.append(file_path)

# fallback
if not processes:
    processes.append("node")

# ============================
# CLEAN DNS 
# ============================

captured_dns = list(set(captured_dns))

clean_dns = []
for ip in captured_dns:
    if ip.startswith(("127.", "0.", "10.", "192.168")):
        continue
    clean_dns.append(ip)

# ============================
# NETWORK DETAILS
# ============================

def enrich_ip(ip):
    try:
        data = json.loads(urllib.request.urlopen(f"http://ip-api.com/json/{ip}").read())
        return {
            "ip": ip,
            "country": data.get("country"),
            "isp": data.get("isp"),
            "org": data.get("org")
        }
    except:
        return {"ip": ip}

network_details = [enrich_ip(ip) for ip in ips]

# ============================
# SCORING
# ============================

score = 0
reasons = []

if len(processes) > 2:
    score += 3
    reasons.append("Multiple processes")

if len(ips) > 0:
    score += 4
    reasons.append("External connections")

if len(domains) > 1:
    score += 2
    reasons.append("Multiple domains")

if len(files) > 2:
    score += 3
    reasons.append("Sensitive file access")

# ============================
# LEVEL
# ============================

if score >= 7:
    threat_level = "HIGH RISK"
elif score >= 4:
    threat_level = "MEDIUM RISK"
else:
    threat_level = "LOW RISK"

# ============================
# SAVE
# ============================

os.makedirs("decoy_logs/decoy_runs", exist_ok=True)

log = {
    "package": os.path.basename(original_input),
    "score": score,
    "threat_level": threat_level,
    "reasons": reasons,
    "processes": processes,
    "commands": commands,
    "files": files,
    "domains": list(domains),
    "dns": clean_dns,
    "http_requests": captured_requests,
    "network_details": network_details,
    "timeline": timeline[:100]
}

run_id = str(int(time.time()))

with open(f"decoy_logs/decoy_runs/log_{run_id}.json", "w") as f:
    json.dump(log, f, indent=4)

with open("decoy_logs/latest.json", "w") as f:
    json.dump(log, f, indent=4)

print("Saved:", run_id)
