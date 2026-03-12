from flask import Flask, request, jsonify
from datetime import datetime
import json
import os
import requests
import csv

app = Flask(__name__)

# =====================================================
#  Credential Store (Honeytokens)


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
#  Storage


EVENTS_FILE = "events.json"
DATASET_FILE = "events_dataset.csv"

if not os.path.exists(EVENTS_FILE):
    with open(EVENTS_FILE, "w") as f:
        json.dump([], f)

if not os.path.exists(DATASET_FILE):
    with open(DATASET_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "privilege_level",
            "ip_attempt_count",
            "hour_of_day",
            "weekend_flag",
            "automation_flag",
            "proxy_flag",
            "hosting_flag",
            "content_length",
            "header_count"
        ])

# =====================================================
#  IP Tracking


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
            f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,proxy,hosting,as",
            timeout=3
        )
        data = r.json()
        if data.get("status") == "success":
            return data
    except:
        pass
    return {}

# =====================================================
#  Event Logging


def log_event(event):
    with open(EVENTS_FILE, "r") as f:
        data = json.load(f)

    data.append(event)

    with open(EVENTS_FILE, "w") as f:
        json.dump(data, f, indent=4)

def append_dataset_row(row):
    with open(DATASET_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(row)

# =====================================================
# Production-style Auth Endpoint


@app.route("/api/v1/session", methods=["POST"])
def validate_session():

    provided_token = request.headers.get("Authorization")
    ip = request.remote_addr
    ua = request.headers.get("User-Agent")

    if not provided_token:
        return jsonify({"error": "Missing credentials"}), 400

    provided_token = provided_token.replace("Bearer ", "")

    for name, data in CREDENTIAL_STORE.items():

        if provided_token == data["token"]:

            privilege_level = data["privilege_level"]

            ip_data = track_ip(ip)
            geo = enrich_ip(ip)

            hour = datetime.utcnow().hour
            is_weekend = datetime.utcnow().weekday() >= 5

            automation_flag = any(
                x in (ua or "").lower()
                for x in ["curl", "bot", "python", "scanner"]
            )

            proxy_flag = bool(geo.get("proxy"))
            hosting_flag = bool(geo.get("hosting"))

            event = {
                "event_type": "credential_misuse",
                "token_profile": name,
                "privilege_level": privilege_level,

                "ip": ip,
                "country": geo.get("country"),
                "city": geo.get("city"),
                "isp": geo.get("isp"),
                "asn": geo.get("as"),
                "proxy_flag": proxy_flag,
                "hosting_flag": hosting_flag,

                "ip_attempt_count": ip_data["count"],
                "first_seen": ip_data["first_seen"].isoformat(),
                "last_seen": ip_data["last_seen"].isoformat(),

                "hour_of_day": hour,
                "weekend_flag": is_weekend,
                "automation_flag": automation_flag,

                "endpoint": "/api/v1/session",
                "method": request.method,
                "content_length": request.content_length,
                "header_count": len(request.headers),

                "timestamp": datetime.utcnow().isoformat()
            }

            log_event(event)

            append_dataset_row([
                privilege_level,
                ip_data["count"],
                hour,
                int(is_weekend),
                int(automation_flag),
                int(proxy_flag),
                int(hosting_flag),
                request.content_length or 0,
                len(request.headers)
            ])

            return jsonify({"error": "Unauthorized"}), 401

    return jsonify({"status": "Invalid credentials"}), 403

# =====================================================
#  Events Viewer                                                             



@app.route("/api/v1/events", methods=["GET"])
def get_events():
    with open(EVENTS_FILE, "r") as f:
        data = json.load(f)
    return jsonify(data)

# =====================================================
#  Health

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})

# =====================================================
# Run

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
