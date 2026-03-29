from flask import Flask, request, jsonify
from datetime import datetime
import json
import base64
import os
import requests

app = Flask(__name__)

# =====================================================
# Credential Store (Honeytokens)

CREDENTIAL_STORE = {
    "repo_admin": {
        "token": "ghp_pr0dRel3aseAdm1nAccess2026xYzAbC",
        "privilege_level": 3
    },
    "ci_deploy": {
        "token": "build-prod-deploy-master-2026",
        "privilege_level": 2
    },
    "legacy_registry": {
        "token": "ghp_LegacyRepoAccess2024Prod",
        "privilege_level": 1
    }
}

# =====================================================
# IP Tracking

IP_TRACKER = {}

def track_ip(ip):
    now = datetime.utcnow()

    if ip not in IP_TRACKER:
        IP_TRACKER[ip] = {
            "count": 1,
            "first_seen": now,
            "last_seen": now
        }
    else:
        IP_TRACKER[ip]["count"] += 1
        IP_TRACKER[ip]["last_seen"] = now

    return IP_TRACKER[ip]

# =====================================================
# IP Enrichment

def enrich_ip(ip):
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,proxy,hosting,as,continent,timezone,lat,lon",
            timeout=3
        )
        data = r.json()
        if data.get("status") == "success":
            return data
    except:
        pass
    return {}

# =====================================================
# GitHub Logging

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_REPO = os.getenv("GITHUB_REPO")
FILE_PATH = "CTI_Storage/events.json"

def log_event(event):

    url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{FILE_PATH}"

    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        content = response.json()
        sha = content["sha"]
        existing_data = base64.b64decode(content["content"]).decode()
        data = json.loads(existing_data)
    else:
        sha = None
        data = []

    data.append(event)

    updated_content = base64.b64encode(
        json.dumps(data, indent=4).encode()
    ).decode()

    payload = {
        "message": "Update CTI events log",
        "content": updated_content,
        "branch": "main"
    }

    if sha:
        payload["sha"] = sha

    requests.put(url, headers=headers, json=payload)

# =====================================================
# Helper (File-based triggers)

def build_path_event(profile_name, privilege_level, endpoint_name):
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    ip = ip.split(",")[0].strip()
    ua = request.headers.get("User-Agent")

    ip_data = track_ip(ip)
    geo = enrich_ip(ip)

    hour = datetime.utcnow().hour
    is_weekend = datetime.utcnow().weekday() >= 5

    automation_flag = any(
        x in (ua or "").lower()
        for x in ["curl", "bot", "python", "scanner"]
    )

    return {
        "event_type": "path_trigger",
        "token_profile": profile_name,
        "privilege_level": privilege_level,

        # Network
        "ip": ip,
        "country": geo.get("country"),
        "city": geo.get("city"),
        "isp": geo.get("isp"),
        "asn": geo.get("as"),
        "continent": geo.get("continent"),
        "timezone": geo.get("timezone"),
        "lat": geo.get("lat"),
        "lon": geo.get("lon"),
        "proxy_flag": bool(request.headers.get("X-Forwarded-For")),
        "hosting_flag": bool(geo.get("hosting")),

        # Behavior
        "request_count": ip_data["count"],
        "burst_flag": ip_data["count"] > 5,

        # Automation
        "user_agent": ua,
        "automation_flag": automation_flag,
        "automation_score": int(automation_flag) * 80,

        # Time
        "hour_of_day": hour,
        "day_of_week": datetime.utcnow().strftime("%A"),
        "is_business_hours": 9 <= hour <= 17,

        # Threat Intel
        "attack_type": "config_access",
        "attack_stage": "discovery",
        "mitre_technique": "T1083",
        "mitre_tactic": "Discovery",

        # IOC
        "ioc_ip": ip,
        "ioc_user_agent": ua,
        "ioc_endpoint": endpoint_name,

        "timestamp": datetime.utcnow().isoformat()
    }

# =====================================================
# SCM Trigger

@app.route("/legacy_internal_config.yaml", methods=["GET", "POST"])
def scm_trigger():
    event = build_path_event("legacy_registry", 1, "/legacy_internal_config.yaml")
    log_event(event)
    return (
    "internal_registry_endpoint: https://internal-auth.local/api/v1/auth\n"
    "internal_registry_token: redacted\n"
    "backup_api_secret: redacted\n",
    200,
    {"Content-Type": "text/plain; charset=utf-8"}
)

# =====================================================
# Build Trigger
                                                                                              
@app.route("/s3/<bucket>", methods=["GET", "POST", "PUT"])
def fake_s3(bucket):
    event = {
        "type": "s3_access",
        "bucket": bucket,
        "method": request.method,
        "ip": request.headers.get("X-Forwarded-For", request.remote_addr),
        "timestamp": datetime.utcnow().isoformat()
    }

    log_event(event)

    return (
        f"<Error><Code>AccessDenied</Code><BucketName>{bucket}</BucketName></Error>",
        403,
        {"Content-Type": "application/xml"}
    )
# =====================================================
# Repository Canary (Token Misuse)

@app.route("/api/v1/session", methods=["POST"])
def validate_session():

    provided_token = request.headers.get("Authorization")
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    ip = ip.split(",")[0].strip()
    ua = request.headers.get("User-Agent")

    if not provided_token:
        return jsonify({"error": "Missing credentials"}), 400

    provided_token = provided_token.replace("Bearer ", "")

    for name, data in CREDENTIAL_STORE.items():

        if provided_token == data["token"]:

            ip_data = track_ip(ip)
            geo = enrich_ip(ip)

            hour = datetime.utcnow().hour
            is_weekend = datetime.utcnow().weekday() >= 5

            automation_flag = any(
                x in (ua or "").lower()
                for x in ["curl", "bot", "python", "scanner"]
            )

            event = {
                "event_type": "credential_misuse",
                "token_type": name,
                "token_scope": name,
                "token_length": len(provided_token),
                "token_prefix": provided_token[:5],

                # Network
                "ip": ip,
                "country": geo.get("country"),
                "city": geo.get("city"),
                "isp": geo.get("isp"),
                "asn": geo.get("as"),
                "continent": geo.get("continent"),
                "timezone": geo.get("timezone"),
                "lat": geo.get("lat"),
                "lon": geo.get("lon"),
                "proxy_flag": bool(geo.get("proxy")),
                "hosting_flag": bool(geo.get("hosting")),

                # Behavior
                "request_count": ip_data["count"],
                "burst_flag": ip_data["count"] > 5,

                # Automation
                "user_agent": ua,
                "automation_flag": automation_flag,
                "automation_score": int(automation_flag) * 80,

                # Time
                "hour_of_day": hour,
                "day_of_week": datetime.utcnow().strftime("%A"),
                "is_business_hours": 9 <= hour <= 17,

                # Threat
                "attack_type": "token_misuse",
                "attack_stage": "credential_access",
                "mitre_technique": "T1552.001",
                "mitre_tactic": "Credential Access",

                # IOC
                "ioc_ip": ip,
                "ioc_user_agent": ua,
                "ioc_endpoint": "/api/v1/session",

                "timestamp": datetime.utcnow().isoformat()
            }

            log_event(event)
            return jsonify({  "status": "ok",
                              "message": "Session validated",
                             "scope": name,
                             "expires_in": 3600
                                                 }), 200
  

    return jsonify({"status": "Invalid credentials"}), 403

# =====================================================
# Events Viewer

@app.route("/api/v1/events", methods=["GET"])
def get_events():

    url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{FILE_PATH}"

    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        content = response.json()
        decoded = base64.b64decode(content["content"]).decode()
        data = json.loads(decoded)
        return jsonify(data)

    return jsonify({"error": "Unable to fetch events"}), 500

# =====================================================
# Health

@app.route("/health")
def health():
    return {"status": "ok"}

@app.route("/")
def home():
    return {"status": "SSC Collector Running"}

# =====================================================
# Run

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
