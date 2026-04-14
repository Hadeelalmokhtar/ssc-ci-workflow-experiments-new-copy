from flask import Flask, request, jsonify
from datetime import datetime
import json
import base64
import os
import requests

app = Flask(__name__)

# =====================================================
# CONFIG

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_REPO = os.getenv("GITHUB_REPO")

EVENTS_FILE = "CTI_Storage/events.json"
FEATURES_FILE = "CTI_Storage/features.json"

ABUSE_API_KEY = os.getenv("ABUSE_API_KEY")
IPQS_API_KEY = os.getenv("IPQS_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")

# =====================================================
# CACHE

CACHE = {}

def cached_lookup(ip, func):
    if ip in CACHE and func.__name__ in CACHE[ip]:
        return CACHE[ip][func.__name__]

    data = func(ip)

    if ip not in CACHE:
        CACHE[ip] = {}

    CACHE[ip][func.__name__] = data
    return data

# =====================================================
# CREDENTIAL STORE (HONEYPOTS)

CREDENTIAL_STORE = {
    "repo_admin": {"token": "ghp_pr0dRel3aseAdm1nAccess2026xYzAbC","privilege_level": 3},
    "ci_deploy": {"token": "build-prod-deploy-master-2026","privilege_level": 2},
    "legacy_registry": {"token": "ghp_LegacyRepoAccess2024Prod","privilege_level": 1}
}

# =====================================================
# IP TRACKING

IP_TRACKER = {}

def track_ip(ip):
    if ip not in IP_TRACKER:
        IP_TRACKER[ip] = {"count": 1}
    else:
        IP_TRACKER[ip]["count"] += 1
    return IP_TRACKER[ip]

# =====================================================
# ENRICHMENT

def enrich_ip(ip):
    try:
        return requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
    except:
        return {}

def enrich_abuse(ip):
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSE_API_KEY},
            params={"ipAddress": ip},
            timeout=3
        )
        return r.json().get("data", {})
    except:
        return {}

def enrich_ipqs(ip):
    try:
        return requests.get(
            f"https://ipqualityscore.com/api/json/ip/{IPQS_API_KEY}/{ip}",
            timeout=3
        ).json()
    except:
        return {}

def enrich_shodan(ip):
    try:
        return requests.get(
            f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}",
            timeout=3
        ).json()
    except:
        return {}

def enrich_vt(ip):
    try:
        headers = {"x-apikey": VT_API_KEY}
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers=headers,
            timeout=3
        )
        return r.json()
    except:
        return {}

# =====================================================
# CENTRAL HELPER (FULL DATA)
  
def build_path_event(profile_name, privilege_level, endpoint_name):

    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    ip = ip.split(",")[0].strip()

    ua = request.headers.get("User-Agent")

    ip_data = track_ip(ip)

    geo = cached_lookup(ip, enrich_ip)
    abuse = cached_lookup(ip, enrich_abuse)
    ipqs = cached_lookup(ip, enrich_ipqs)
    shodan = cached_lookup(ip, enrich_shodan)
    vt = cached_lookup(ip, enrich_vt)

    now = datetime.utcnow()

    request_count = ip_data["count"]
    burst_flag = request_count > 5

    ua_lower = (ua or "").lower()

    automation_flag = any(x in ua_lower for x in [
        "curl","bot","python","scanner","wget","httpclient"
    ])

    automation_score = int(automation_flag) * 80

    vt_stats = vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

    return {
        # Core
        "event_type": "path_trigger",
        "token_profile": profile_name,
        "privilege_level": privilege_level,

        # Request
        "ip": ip,
        "user_agent": ua,
        "method": request.method,
        "ioc_endpoint": endpoint_name,

        # Geo
        "geo": geo,
        "hosting_flag": int(geo.get("hosting", False)),

        # Threat Intel Raw
        "abuse": abuse,
        "ipqs": ipqs,
        "shodan": shodan,
        "vt": vt,

        # Extracted Features
        "abuse_score": abuse.get("abuseConfidenceScore", 0),
        "fraud_score": ipqs.get("fraud_score", 0),
        "is_vpn": int(ipqs.get("vpn", False)),
        "vt_malicious": vt_stats.get("malicious", 0),
        "vt_suspicious": vt_stats.get("suspicious", 0),
        "open_ports_count": len(shodan.get("ports", [])),

        # Behavior
        "request_count": request_count,
        "burst_flag": burst_flag,

        # Automation
        "automation_flag": automation_flag,
        "automation_score": automation_score,

        # Time
        "hour": now.hour,
        "timestamp": now.isoformat()
    }

# =====================================================
# FEATURE ENGINEERING

def build_features(event):

    return {
        "abuse_score": event["abuse_score"],
        "fraud_score": event["fraud_score"],
        "vt_malicious": event["vt_malicious"],

        "is_bot": int(event["automation_flag"]),
        "burst_flag": int(event["burst_flag"]),
        "is_cloud": int(event["hosting_flag"]),
        "is_vpn": event["is_vpn"],

        "open_ports_count": event["open_ports_count"],

        "is_known_scanner": int(
            event["automation_score"] > 50 or
            event["vt_malicious"] > 0
        ),

        "endpoint_sensitivity": 3 if event["ioc_endpoint"] == "/legacy_internal_config.yaml" else 1
    }

# =====================================================
# THREAT SCORE

def calculate_threat_score(f):
    score = 0
    score += f["abuse_score"] * 0.3
    score += f["fraud_score"] * 0.2
    score += f["burst_flag"] * 20
    score += f["is_cloud"] * 15
    score += f["vt_malicious"] * 10
    return round(score, 2)

# =====================================================
# LABELING

def generate_label(event, f):

    endpoint = event["ioc_endpoint"]

    if event.get("event_type") == "credential_misuse":
        return 1

    if endpoint == "/legacy_internal_config.yaml":
        return 1

    if "/s3/" in endpoint:
        return 1

    if f["vt_malicious"] > 2:
        return 1

    if f["abuse_score"] > 80:
        return 1

    if f["is_cloud"] == 1 and (f["is_bot"] == 1 or f["burst_flag"] == 1):
        return 1

    return 0

# =====================================================
# GITHUB STORAGE

def save_to_github(file_path, entry):

    url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{file_path}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}

    r = requests.get(url, headers=headers)

    if r.status_code == 200:
        content = r.json()
        sha = content["sha"]
        data = json.loads(base64.b64decode(content["content"]).decode())
    else:
        sha = None
        data = []

    data.append(entry)

    encoded = base64.b64encode(json.dumps(data, indent=2).encode()).decode()

    payload = {"message": "update", "content": encoded, "branch": "main"}

    if sha:
        payload["sha"] = sha

    requests.put(url, headers=headers, json=payload)

# =====================================================
# PROCESS EVENT

def process_event(event):

    features = build_features(event)
    features["threat_score"] = calculate_threat_score(features)
    features["label"] = generate_label(event, features)

    save_to_github(EVENTS_FILE, event)
    save_to_github(FEATURES_FILE, features)

# =====================================================
# ROUTES

@app.route("/legacy_internal_config.yaml", methods=["GET","POST"])
def scm():
    event = build_path_event("legacy_registry",1,"/legacy_internal_config.yaml")
    process_event(event)
    return "config exposed",200

@app.route("/s3/<bucket>", methods=["GET","POST","PUT"])
def s3(bucket):
    event = build_path_event("s3",3,f"/s3/{bucket}")
    process_event(event)
    return "denied",403

@app.route("/api/v1/session", methods=["POST"])
def session():

    token = request.headers.get("Authorization","").replace("Bearer ","")

    for name,data in CREDENTIAL_STORE.items():
        if token == data["token"]:
            event = build_path_event(name, data["privilege_level"], "/api/v1/session")
            event["event_type"] = "credential_misuse"
            process_event(event)
            return jsonify({"status":"ok"})

    return jsonify({"error":"invalid"}),403

@app.route("/health")
def health():
    return {"status":"ok"}

# =====================================================
# RUN

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT",5000)))
