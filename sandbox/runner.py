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
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime
from collections import defaultdict

# ============================
# STORAGE
# ============================

captured_requests = []
captured_dns = []

# ============================
# FAKE API + TLS INTERCEPTION SIMULATION
# ============================

class FakeHandler(BaseHTTPRequestHandler):

    def do_GET(self):

        entry = {
            "method": "GET",
            "path": self.path,
            "headers": dict(self.headers)
        }

        #  Fake API responses
        if "/api/config" in self.path:
            response = {"mode": "active", "task": "collect_data"}

        elif "/api/command" in self.path:
            response = {"cmd": "exfiltrate"}

        else:
            response = {"status": "ok"}

        entry["response"] = response
        captured_requests.append(entry)

        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

    def do_POST(self):

        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode()

        entry = {
            "method": "POST",
            "path": self.path,
            "body": body
        }

        #  Fake login / token API
        if "/login" in self.path:
            response = {"token": "FAKE_TOKEN_123"}

        else:
            response = {"status": "received"}

        entry["response"] = response
        captured_requests.append(entry)

        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())


def start_http():
    server = HTTPServer(("0.0.0.0", 8080), FakeHandler)
    server.serve_forever()

threading.Thread(target=start_http, daemon=True).start()
print(" Fake Internet + API running on 8080")

# ============================
# FAKE DNS
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
    resolver = FakeResolver()
    server = DNSServer(resolver, port=5353, address="0.0.0.0")
    server.start()

threading.Thread(target=start_dns, daemon=True).start()
print(" Fake DNS running")

# ============================
# INPUT
# ============================

if len(sys.argv) < 2:
    sys.exit(1)

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

# ============================
# ENV
# ============================

env = os.environ.copy()

env["HTTP_PROXY"] = "http://127.0.0.1:8080"
env["HTTPS_PROXY"] = "http://127.0.0.1:8080"

env["API_KEY"] = "FAKE_API"
env["TOKEN"] = "FAKE_TOKEN"

# ============================
# ANALYSIS
# ============================

commands = set()
ips = set()
domains = set()
files = []
processes = []
timeline = []
syscalls = defaultdict(int)
decoded_payloads = []

def try_decode_base64(s):
    try:
        d = base64.b64decode(s).decode()
        if len(d) > 10:
            return d
    except:
        pass
    return None

print(" ULTIMATE SANDBOX STARTED")

start = time.time()

for target in targets:

    if target.endswith(".js"):
        run_cmd = ["node", target]
    else:
        run_cmd = ["python3", target]

    process = subprocess.Popen(
        ["strace", "-f", "-e", "trace=all"] + run_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        text=True,
        env=env
    )

    try:
        stdout, stderr = process.communicate(input="trigger\n", timeout=60)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()

    for line in stderr.split("\n"):

        if not line:
            continue

        timeline.append(line)

        if "execve(" in line:
            m = re.search(r'execve\("([^"]+)"', line)
            if m:
                processes.append(os.path.basename(m.group(1)))

        for ip in re.findall(r'\d+\.\d+\.\d+\.\d+', line):
            ips.add(ip)

        for d in re.findall(r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', line):
            domains.add(d)

        if any(x in line for x in ["open(", "write(", "unlink(", "rename("]):
            f = re.search(r'"([^"]+)"', line)
            if f:
                files.append(f.group(1))

        strings = re.findall(r'[A-Za-z0-9+/=]{20,}', line)
        for s in strings:
            d = try_decode_base64(s)
            if d:
                decoded_payloads.append(d)

# ============================
# SCORE
# ============================

score = len(processes)*2 + len(ips)*3 + len(files) + len(decoded_payloads)*4 + len(captured_requests)*5

verdict = "CLEAN"
if score > 5:
    verdict = "SUSPICIOUS"
if score > 10:
    verdict = "MALICIOUS"

# ============================
# SAVE
# ============================

os.makedirs("decoy_logs", exist_ok=True)

log = {
    "package": os.path.basename(original_input),
    "verdict": verdict,
    "score": score,
    "processes": processes,
    "files": files,
    "domains": list(domains),
    "dns": captured_dns,
    "http_requests": captured_requests,
    "decoded_payloads": decoded_payloads,
    "timestamp": datetime.utcnow().isoformat()
}

with open("decoy_logs/latest.json", "w") as f:
    json.dump(log, f, indent=4)

print(" ULTIMATE SANDBOX COMPLETE")
