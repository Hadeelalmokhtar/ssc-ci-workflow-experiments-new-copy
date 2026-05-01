from flask import Flask, request, jsonify
from datetime import datetime, timezone
import json
import base64
import os
import requests
import time
import uuid

app = Flask(__name__)

# =====================================================
# CONFIG

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_REPO  = os.getenv("GITHUB_REPO")

STIX_FILE = "CTI_Storage/CTI_STIX.json"   # one STIX Bundle file, appended per hit

ABUSE_API_KEY  = os.getenv("ABUSE_API_KEY")
IPQS_API_KEY   = os.getenv("IPQS_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
VT_API_KEY     = os.getenv("VT_API_KEY")

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
# DEDUP

LAST_SEEN = {}

def is_duplicate(event):
    endpoint = event.get("ioc_endpoint", "unknown")
    ip       = event.get("ip", "unknown")
    key      = f"{ip}_{endpoint}"
    now      = time.time()
    if key in LAST_SEEN and now - LAST_SEEN[key] < 10:
        return True
    LAST_SEEN[key] = now
    return False

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
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
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
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VT_API_KEY},
            timeout=3
        )
        return r.json()
    except:
        return {}

# =====================================================
# HELPER — build raw event

def build_path_event(profile_name, privilege_level, endpoint_name):
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    ip = ip.split(",")[0].strip()

    ua        = request.headers.get("User-Agent", "")
    ip_data   = track_ip(ip)
    geo       = cached_lookup(ip, enrich_ip)
    abuse     = cached_lookup(ip, enrich_abuse)
    ipqs      = cached_lookup(ip, enrich_ipqs)
    shodan    = cached_lookup(ip, enrich_shodan)
    vt        = cached_lookup(ip, enrich_vt)

    now            = datetime.utcnow()
    request_count  = ip_data["count"]
    burst_flag     = request_count > 5
    ua_lower       = ua.lower()
    automation_flag= any(x in ua_lower for x in ["curl","bot","python","scanner","wget"])

    return {
        "event_type":      "path_trigger",
        "token_profile":   profile_name,
        "privilege_level": privilege_level,
        "ip":              ip,
        "country":         geo.get("country"),
        "city":            geo.get("city"),
        "isp":             geo.get("isp"),
        "asn":             geo.get("as"),
        "request_count":   request_count,
        "burst_flag":      burst_flag,
        "user_agent":      ua,
        "automation_flag": automation_flag,
        "automation_score":int(automation_flag) * 80,
        "hour_of_day":     now.hour,
        "day_of_week":     now.strftime("%A"),
        "ioc_endpoint":    endpoint_name,
        "method":          request.method,
        "intel": {
            "geo":            geo,
            "abuseipdb":      abuse,
            "ipqualityscore": ipqs,
            "shodan":         shodan,
            "virustotal":     vt,
        },
        "timestamp": now.isoformat()
    }

# =====================================================
# FILTER — drop empty / error fields recursively

EMPTY_VALUES = {None, "", "N/A", "Premium required.", "Requires membership or higher to access"}

def filter_empty(obj):
    """Recursively remove keys whose value is empty/null/error placeholder."""
    if isinstance(obj, dict):
        cleaned = {}
        for k, v in obj.items():
            v2 = filter_empty(v)
            # Skip if the cleaned value is itself empty
            if v2 in EMPTY_VALUES:
                continue
            if isinstance(v2, dict) and not v2:
                continue
            if isinstance(v2, list) and not v2:
                continue
            cleaned[k] = v2
        return cleaned
    elif isinstance(obj, list):
        result = []
        for item in obj:
            item2 = filter_empty(item)
            if item2 not in EMPTY_VALUES:
                result.append(item2)
        return result
    else:
        return obj

# =====================================================
# STIX HELPERS

def stix_id(obj_type):
    return f"{obj_type}--{uuid.uuid4()}"

def now_stix():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

def ts_to_stix(ts_str):
    """Convert event timestamp string to STIX format."""
    try:
        dt = datetime.fromisoformat(ts_str)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except:
        return now_stix()

# =====================================================
# STIX BUILDER

def build_stix_bundle(event):
    """
    Build a STIX 2.1 Bundle from one honeypot hit.

    Objects produced:
      - identity          (honeypot system / creator)
      - ipv4-addr         (attacker IP)
      - network-traffic   (the incoming request)
      - indicator         (pattern matching the IOC endpoint)
      - threat-actor      (inferred from intel, if high-confidence)
      - observed-data     (wraps ip + network-traffic)
      - note              (raw, filtered intel dump per source)
      - relationship      (indicator → ipv4-addr, threat-actor → indicator)
    """
    created_ts = ts_to_stix(event.get("timestamp", now_stix()))
    intel      = event.get("intel", {})

    # ---- Filter raw intel per source ----
    geo_clean    = filter_empty(intel.get("geo", {}))
    abuse_clean  = filter_empty(intel.get("abuseipdb", {}))
    ipqs_clean   = filter_empty(intel.get("ipqualityscore", {}))
    shodan_clean = filter_empty(intel.get("shodan", {}))
    vt_raw       = intel.get("virustotal", {})

    # For VT keep only attributes + last_analysis_stats + last_analysis_results
    vt_attrs = filter_empty(vt_raw.get("data", {}).get("attributes", {}))
    # Strip huge whois/rdap blobs from VT to keep bundle lean but keep stats
    for drop_key in ["whois", "rdap", "last_https_certificate"]:
        vt_attrs.pop(drop_key, None)
    vt_clean = vt_attrs  # already filtered

    # ---- Derive threat score flags ----
    abuse_score   = abuse_clean.get("abuseConfidenceScore", 0)
    fraud_score   = ipqs_clean.get("fraud_score", 0)
    is_tor        = abuse_clean.get("isTor", False) or ipqs_clean.get("tor", False)
    is_vpn        = ipqs_clean.get("vpn", False)
    is_bot        = event.get("automation_flag", False) or ipqs_clean.get("bot_status", False)
    vt_stats      = vt_clean.get("last_analysis_stats", {})
    vt_malicious  = vt_stats.get("malicious", 0)
    vt_suspicious = vt_stats.get("suspicious", 0)

    high_confidence = (abuse_score >= 80 or fraud_score >= 80 or vt_malicious >= 5)

    # ---- Labels ----
    labels = ["honeypot-hit"]
    if is_tor:        labels.append("tor-exit-node")
    if is_vpn:        labels.append("vpn")
    if is_bot:        labels.append("automated-scanner")
    if vt_malicious:  labels.append("malicious-ip")
    if "config" in event.get("ioc_endpoint", ""):  labels.append("config-exposure")
    if "/s3/" in event.get("ioc_endpoint", ""):     labels.append("cloud-storage-probe")

    # ---- IDs ----
    identity_id       = stix_id("identity")
    ip_id             = stix_id("ipv4-addr")
    net_traffic_id    = stix_id("network-traffic")
    indicator_id      = stix_id("indicator")
    observed_data_id  = stix_id("observed-data")
    note_geo_id       = stix_id("note")
    note_abuse_id     = stix_id("note")
    note_ipqs_id      = stix_id("note")
    note_shodan_id    = stix_id("note")
    note_vt_id        = stix_id("note")
    rel_ind_ip_id     = stix_id("relationship")

    objects = []

    # 1. Identity — the honeypot system
    objects.append({
        "type":            "identity",
        "spec_version":    "2.1",
        "id":              identity_id,
        "created":         created_ts,
        "modified":        created_ts,
        "name":            "SSC Honeypot Collector",
        "identity_class":  "system",
        "description":     "Honeytoken collector deployed in CI/CD workflow to detect credential misuse and path probing.",
        "labels":          ["honeypot", "threat-intelligence"]
    })

    # 2. IPv4 address — attacker
    ip_obj = {
        "type":          "ipv4-addr",
        "spec_version":  "2.1",
        "id":            ip_id,
        "value":         event.get("ip"),
    }
    if event.get("country"):  ip_obj["x_country"]  = event["country"]
    if event.get("city"):     ip_obj["x_city"]      = event["city"]
    if event.get("isp"):      ip_obj["x_isp"]       = event["isp"]
    if event.get("asn"):      ip_obj["x_asn"]       = event["asn"]
    objects.append(ip_obj)

    # 3. Network traffic — the request
    net_obj = {
        "type":          "network-traffic",
        "spec_version":  "2.1",
        "id":            net_traffic_id,
        "src_ref":       ip_id,
        "protocols":     ["http"],
        "start":         created_ts,
        "extensions": {
            "http-request-ext": {
                "request_method":  event.get("method", "GET"),
                "request_value":   event.get("ioc_endpoint", ""),
                "request_header": {
                    "User-Agent": event.get("user_agent", "")
                }
            }
        },
        "x_event_type":       event.get("event_type"),
        "x_token_profile":    event.get("token_profile"),
        "x_privilege_level":  event.get("privilege_level"),
        "x_automation_score": event.get("automation_score"),
        "x_burst_flag":       event.get("burst_flag"),
        "x_request_count":    event.get("request_count"),
        "x_hour_of_day":      event.get("hour_of_day"),
        "x_day_of_week":      event.get("day_of_week"),
    }
    objects.append(net_obj)

    # 4. Indicator — pattern on the IOC endpoint
    endpoint = event.get("ioc_endpoint", "")
    indicator_obj = {
        "type":              "indicator",
        "spec_version":      "2.1",
        "id":                indicator_id,
        "created":           created_ts,
        "modified":          created_ts,
        "created_by_ref":    identity_id,
        "name":              f"Honeytoken hit: {endpoint}",
        "description":       (
            f"Attacker IP {event.get('ip')} accessed honeytoken endpoint '{endpoint}' "
            f"via {event.get('method')} from {event.get('country', 'unknown')}. "
            f"Profile: {event.get('token_profile')}, privilege level {event.get('privilege_level')}."
        ),
        "indicator_types":   ["malicious-activity", "anomalous-activity"],
        "pattern":           f"[ipv4-addr:value = '{event.get('ip')}'] AND [network-traffic:extensions.'http-request-ext'.request_value = '{endpoint}']",
        "pattern_type":      "stix",
        "valid_from":        created_ts,
        "labels":            labels,
        "confidence":        85 if high_confidence else 55,
    }
    objects.append(indicator_obj)

    # 5. Observed-data — wraps the IP + network traffic
    objects.append({
        "type":             "observed-data",
        "spec_version":     "2.1",
        "id":               observed_data_id,
        "created":          created_ts,
        "modified":         created_ts,
        "created_by_ref":   identity_id,
        "first_observed":   created_ts,
        "last_observed":    created_ts,
        "number_observed":  event.get("request_count", 1),
        "object_refs":      [ip_id, net_traffic_id],
        "labels":           labels,
    })

    # 6. Threat-actor (only if high confidence)
    if high_confidence:
        ta_id = stix_id("threat-actor")
        sophistication = "intermediate" if is_bot else "minimal"
        ta_obj = {
            "type":            "threat-actor",
            "spec_version":    "2.1",
            "id":              ta_id,
            "created":         created_ts,
            "modified":        created_ts,
            "created_by_ref":  identity_id,
            "name":            f"Unattributed actor — {event.get('ip')}",
            "description":     (
                f"Actor detected probing honeytoken endpoints from {event.get('country', 'unknown')}. "
                f"Infrastructure: {'TOR exit node' if is_tor else 'VPN/Proxy' if is_vpn else 'direct'}. "
                f"Abuse score: {abuse_score}/100. Fraud score: {fraud_score}/100. "
                f"VT detections: {vt_malicious} malicious / {vt_suspicious} suspicious."
            ),
            "threat_actor_types": ["criminal"] if not is_tor else ["criminal", "activist"],
            "sophistication":  sophistication,
            "resource_level":  "individual",
            "labels":          labels,
        }
        objects.append(ta_obj)

        # relationship: threat-actor → indicator
        objects.append({
            "type":            "relationship",
            "spec_version":    "2.1",
            "id":              stix_id("relationship"),
            "created":         created_ts,
            "modified":        created_ts,
            "relationship_type": "uses",
            "source_ref":      ta_id,
            "target_ref":      indicator_id,
        })

    # 7. Relationship: indicator → ipv4-addr
    objects.append({
        "type":              "relationship",
        "spec_version":      "2.1",
        "id":                rel_ind_ip_id,
        "created":           created_ts,
        "modified":          created_ts,
        "relationship_type": "indicates",
        "source_ref":        indicator_id,
        "target_ref":        ip_id,
    })

    # 8. Notes — one per intel source (only if non-empty after filtering)

    def make_note(note_id, source_name, data):
        if not data:
            return None
        return {
            "type":           "note",
            "spec_version":   "2.1",
            "id":             note_id,
            "created":        created_ts,
            "modified":       created_ts,
            "created_by_ref": identity_id,
            "abstract":       f"Intel from {source_name} for {event.get('ip')}",
            "content":        json.dumps(data, indent=2, ensure_ascii=False),
            "object_refs":    [ip_id, indicator_id],
            "labels":         [source_name.lower().replace(" ", "-"), "raw-intel"],
        }

    for note_id, src, data in [
        (note_geo_id,   "GeoIP (ip-api)",  geo_clean),
        (note_abuse_id, "AbuseIPDB",       abuse_clean),
        (note_ipqs_id,  "IPQualityScore",  ipqs_clean),
        (note_shodan_id,"Shodan",          shodan_clean),
        (note_vt_id,    "VirusTotal",      vt_clean),
    ]:
        note = make_note(note_id, src, data)
        if note:
            objects.append(note)

    # ---- Assemble bundle ----
    bundle = {
        "type":         "bundle",
        "id":           stix_id("bundle"),
        "spec_version": "2.1",
        "objects":      objects,
    }
    return bundle

# =====================================================
# GITHUB SAVE — appends one bundle to a JSON array

def save_stix_to_github(bundle: dict):
    url     = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{STIX_FILE}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}

    r = requests.get(url, headers=headers)

    if r.status_code == 200:
        meta   = r.json()
        sha    = meta["sha"]
        try:
            existing = json.loads(base64.b64decode(meta["content"]).decode("utf-8"))
            if not isinstance(existing, list):
                existing = [existing]
        except:
            existing = []
    else:
        sha      = None
        existing = []

    existing.append(bundle)

    encoded = base64.b64encode(
        json.dumps(existing, indent=2, ensure_ascii=False).encode("utf-8")
    ).decode()

    payload = {"message": f"stix bundle: {bundle['id']}", "content": encoded, "branch": "main"}
    if sha:
        payload["sha"] = sha

    requests.put(url, headers=headers, json=payload)

# =====================================================
# PROCESS

def process_event(event):
    if is_duplicate(event):
        return
    bundle = build_stix_bundle(event)
    save_stix_to_github(bundle)

# =====================================================
# ROUTES

@app.route("/legacy_internal_config.yaml", methods=["GET"])
def scm():
    event = build_path_event("legacy_registry", 1, "/legacy_internal_config.yaml")
    process_event(event)
    return "config exposed", 200

@app.route("/s3/<bucket>", methods=["GET", "POST", "PUT"])
def s3(bucket):
    event = build_path_event("s3", 3, f"/s3/{bucket}")
    process_event(event)
    return "denied", 403

@app.route("/api/v1/session", methods=["POST"])
def session():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    CREDENTIAL_STORE = {
        "repo_token": {"token": "admin123", "privilege_level": 3}
    }
    for name, data in CREDENTIAL_STORE.items():
        if token == data["token"]:
            event = build_path_event(name, data["privilege_level"], "/api/v1/session")
            event["event_type"] = "credential_misuse"
            process_event(event)
            return jsonify({"status": "ok"})
    return jsonify({"error": "invalid"}), 403

@app.route("/health")
def health():
    return {"status": "ok"}

# =====================================================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
