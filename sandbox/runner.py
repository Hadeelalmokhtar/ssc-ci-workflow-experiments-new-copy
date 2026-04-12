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
        captured_requests.append({
            "method": "GET",
            "path": self.path
        })

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

# ============================
# NETWORK ENRICHMENT
# ============================

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

        timeline.append({
            "time": round(time.time() - start, 2),
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

# ============================
# NETWORK DETAILS
# ============================

network_details = [enrich_ip(ip) for ip in ips]

# ============================
# SCORE
# ============================

score = len(processes) + len(ips)*2

# ============================
# SAVE
# ============================

os.makedirs("decoy_logs", exist_ok=True)
os.makedirs("decoy_logs/decoy_runs", exist_ok=True)

log = {
    "package": os.path.basename(original_input),
    "score": score,
    "processes": processes,
    "files": files,
    "domains": list(domains),
    "dns": captured_dns,
    "http_requests": captured_requests,
    "network_details": network_details,
    "timeline": timeline[:100]
}

run_id = str(int(time.time()))
archive_file = f"decoy_logs/decoy_runs/log_{run_id}.json"

with open(archive_file, "w") as f:
    json.dump(log, f, indent=4)

with open("decoy_logs/latest.json", "w") as f:
    json.dump(log, f, indent=4)

print("Saved:", archive_file)
