from flask import Flask, request, jsonify
from datetime import datetime
import requests
import os
import json
import base64

app = Flask(__name__)

# =========================
# CONFIG
# =========================

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_REPO = os.getenv("GITHUB_REPO")

EVENTS_FILE = "CTI_Storage/events.json"
FEATURES_FILE = "CTI_Storage/features.json"

ABUSE_API_KEY = os.getenv("ABUSE_API_KEY")
IPQS_API_KEY = os.getenv("IPQS_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY")

# =========================
# CACHE
# =========================

CACHE = {}

def cached_lookup(ip, func):
    if ip in CACHE and func.__name__ in CACHE[ip]:
        return CACHE[ip][func.__name__]

    result = func(ip)

    if ip not in CACHE:
        CACHE[ip] = {}

    CACHE[ip][func.__name__] = result
    return result

# =========================
# TRACKING
# =========================

IP_TRACKER = {}

def track_ip(ip):
    if ip not in IP_TRACKER:
        IP_TRACKER[ip] = {"count": 1}
    else:
        IP_TRACKER[ip]["count"] += 1

    return IP_TRACKER[ip]

# =========================
# ENRICHMENT
# =========================

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
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=3
        )
        return r.json().get("data", {})
    except:
        return {}

def enrich_ipqs(ip):
    try:
        url = f"https://ipqualityscore.com/api/json/ip/{IPQS_API_KEY}/{ip}"
        return requests.get(url, timeout=3).json()
    except:
        return {}

def enrich_shodan(ip):
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        return requests.get(url, timeout=3).json()
    except:
        return {}

def enrich_greynoise(ip):
    try:
        r = requests.get(
            f"https://api.greynoise.io/v3/community/{ip}",
            headers={"key": GREYNOISE_API_KEY},
            timeout=3
        )
        return r.json()
    except:
        return {}

# =========================
# FEATURE ENGINEERING
# =========================

def build_features(event):

    ua = (event.get("user_agent") or "").lower()

    shodan = event.get("shodan", {})
    greynoise = event.get("greynoise", {})
    geo = event.get("geo", {})
    abuse = event.get("abuse", {})
    ipqs = event.get("ipqs", {})

    features = {

        # Threat Intel
        "abuse_score": abuse.get("abuseConfidenceScore", 0),
        "total_reports": abuse.get("totalReports", 0),
        "fraud_score": ipqs.get("fraud_score", 0),

        # Network
        "is_cloud": int(geo.get("hosting", False)),
        "is_vpn": int(ipqs.get("vpn", False)),
        "is_tor": int(ipqs.get("tor", False)),

        # User-Agent
        "is_bot": int(any(x in ua for x in ["curl","bot","python","scanner"])),
        "automation_score": 80 if any(x in ua for x in ["curl","bot","python"]) else 0,

        # Behavior
        "request_count": event.get("request_count", 1),
        "burst_flag": int(event.get("request_count", 1) > 5),

        # Time
        "hour": event.get("hour", 0),
        "is_business_hours": int(9 <= event.get("hour", 0) <= 17),

        # Endpoint
        "endpoint_sensitivity": 3 if "admin" in event.get("endpoint","") else 1,

        # Shodan
        "open_ports_count": len(shodan.get("ports", [])),
        "has_ssh": int(22 in shodan.get("ports", [])),
        "has_http": int(80 in shodan.get("ports", [])),

        # GreyNoise
        "is_known_scanner": int(greynoise.get("noise", False)),
        "is_malicious_scanner": int(greynoise.get("classification") == "malicious"),

        # Helper
        "token_misuse": int(event.get("event_type") == "credential_misuse")
    }

    return features

# =========================
# AUTO LABEL 
# =========================

def generate_label(event, features):

    if event.get("event_type") == "credential_misuse":
        return 1

    if features.get("abuse_score", 0) > 80:
        return 1

    if features.get("is_known_scanner", 0) == 1:
        return 1

    if features.get("burst_flag", 0) == 1 and features.get("is_bot", 0) == 1:
        return 1

    return 0

# =========================
# GITHUB STORAGE
# =========================

def save_to_github(file_path, new_entry):

    url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{file_path}"

    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        content = response.json()
        sha = content["sha"]
        existing = json.loads(base64.b64decode(content["content"]).decode())
    else:
        sha = None
        existing = []

    existing.append(new_entry)

    encoded = base64.b64encode(json.dumps(existing, indent=2).encode()).decode()

    payload = {
        "message": "update logs",
        "content": encoded,
        "branch": "main"
    }

    if sha:
        payload["sha"] = sha

    requests.put(url, headers=headers, json=payload)

# =========================
# MAIN
# =========================

@app.route("/", methods=["GET","POST"])
def handle():

    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    ip = ip.split(",")[0].strip()

    ua = request.headers.get("User-Agent")

    ip_data = track_ip(ip)

    geo = cached_lookup(ip, enrich_ip)
    abuse = cached_lookup(ip, enrich_abuse)
    ipqs = cached_lookup(ip, enrich_ipqs)
    shodan = cached_lookup(ip, enrich_shodan)
    greynoise = cached_lookup(ip, enrich_greynoise)

    now = datetime.utcnow()

    event = {
        "ip": ip,
        "user_agent": ua,
        "endpoint": request.path,
        "method": request.method,

        "geo": geo,
        "abuse": abuse,
        "ipqs": ipqs,
        "shodan": shodan,
        "greynoise": greynoise,

        "request_count": ip_data["count"],
        "hour": now.hour,
        "timestamp": now.isoformat(),

        "event_type": "request"
    }

    # FEATURES
    features = build_features(event)

    # LABEL
    label = generate_label(event, features)
    features["label"] = label

    # SAVE
    save_to_github(EVENTS_FILE, event)
    save_to_github(FEATURES_FILE, features)

    return jsonify({
        "status": "captured",
        "label": label,
        "features": features
    })

# =========================
# HEALTH
# =========================

@app.route("/health")
def health():
    return {"status": "ok"}

# =========================
# RUN
# =========================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
