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
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime
from collections import defaultdict

# ============================
# STORAGE
# ============================

captured_requests = []
captured_dns = []

# ============================
# FAKE INTERNET + API
# ============================

class FakeHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        entry = {
            "method": "GET",
            "path": self.path,
            "headers": dict(self.headers)
        }

        response = {"status": "ok"}

        if "/api/config" in self.path:
            response = {"mode": "active"}

        entry["response"] = response
        captured_requests.append(entry)

        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

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
    server = HTTPServer(("0.0.0.0", 8080), FakeHandler)
    server.serve_forever()

threading.Thread(target=start_http, daemon=True).start()

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

# ============================
# ENV
# ============================

env = os.environ.copy()
env["HTTP_PROXY"] = "http://127.0.0.1:8080"
env["HTTPS_PROXY"] = "http://127.0.0.1:8080"
env["NO_PROXY"] = ""

# ============================
# HELPERS
# ============================

def is_readable(s):
    printable = set(string.printable)
    return sum(c in printable for c in s) / len(s) > 0.85

def try_decode_base64(s):
    try:
        d = base64.b64decode(s).decode("utf-8", errors="ignore")
        if len(d) > 20 and is_readable(d):
            return d
    except:
        pass
    return None

def enrich_ip(ip):
    try:
        url = f"http://ip-api.com/json/{ip}"
        data = json.loads(urllib.request.urlopen(url).read())
        return {
            "ip": ip,
            "country": data.get("country"),
            "isp": data.get("isp"),
            "org": data.get("org")
        }
    except:
        return {"ip": ip}

# ============================
# ANALYSIS
# ============================

ips = set()
domains = set()
files = []
processes = []
timeline = []
decoded_payloads = []

start = time.time()

for target in targets:

    run_cmd = ["node", target] if target.endswith(".js") else ["python3", target]

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
    except:
        process.kill()
        stdout, stderr = process.communicate()

    for line in stderr.split("\n"):

        if not line:
            continue

        timestamp = time.time() - start

        timeline.append({
            "time": round(timestamp, 2),
            "event": line[:200]
        })

        if "execve(" in line:
            m = re.search(r'execve\("([^"]+)"', line)
            if m:
                processes.append(os.path.basename(m.group(1)))

        for ip in re.findall(r'\d+\.\d+\.\d+\.\d+', line):
            ips.add(ip)

        for d in re.findall(r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', line):
            domains.add(d)

        if "open(" in line:
            f = re.search(r'"([^"]+)"', line)
            if f:
                files.append(f.group(1))

        strings = re.findall(r'[A-Za-z0-9+/=]{20,}', line)
        for s in strings:
            d = try_decode_base64(s)
            if d:
                decoded_payloads.append(d)

# ============================
# FINAL DATA
# ============================

network_details = [enrich_ip(ip) for ip in ips]

score = len(processes)*2 + len(ips)*3 + len(decoded_payloads)*4

verdict = "CLEAN"
if score > 5:
    verdict = "SUSPICIOUS"
if score > 10:
    verdict = "MALICIOUS"

# ============================
# SAVE (KEEP LATEST + ARCHIVE)
# ============================

import time

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
    "network_details": network_details,
    "timeline": timeline[:100]
}

# (archive)
run_id = str(int(time.time()))
archive_file = f"decoy_logs/decoy_log_{run_id}.json"

with open(archive_file, "w") as f:
    json.dump(log, f, indent=4)

# 
with open("decoy_logs/latest.json", "w") as f:
    json.dump(log, f, indent=4)

print(f"Saved archive log: {archive_file}")
print("Updated latest.json")
