import os
import json
import pandas as pd
from collections import Counter

# ============================================================
# PATHS
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)

DECOY_DIR  = os.path.join(ROOT_DIR, "decoy_logs", "decoy_runs")
OUTPUT_CSV = os.path.join(ROOT_DIR, "CTI_Storage", "decoy_features.csv")


# ============================================================
# HELPERS
# ============================================================

def join_list(values):
    if not values:
        return "none"
    clean = [str(v) for v in values if v is not None and str(v).strip() != ""]
    return " | ".join(clean) if clean else "none"


# ============================================================
# FEATURE EXTRACTORS
# ============================================================

def extract_behavior_features(behavior_findings, score):
    """Extract actual values + numeric signals from behavior_findings."""
    labels   = []
    tiers    = []
    weights  = []
    high_count = 0

    for item in behavior_findings:
        if not isinstance(item, dict):
            continue
        label  = item.get("label", "")
        tier   = item.get("tier", "low")
        weight = item.get("weight", 0)

        if label:  labels.append(label)
        if tier:   tiers.append(tier)
        weights.append(str(weight))

        if tier in ("high", "critical"):
            high_count += 1

    return {
        "behavior_labels":     join_list(labels),
        "behavior_tiers":      join_list(tiers),
        "behavior_weights":    join_list(weights),
        "behavior_score":      score,
        "behavior_high_count": high_count,
    }


def extract_phases(behavioral_phases):
    """Return only phases that have actual events."""
    if not behavioral_phases:
        return "none"
    active = [p for p, events in behavioral_phases.items() if events]
    return join_list(active)


def extract_static_values(static_analysis):
    entropy_values     = []
    obfuscation_values = []
    suspicious_imports = []
    dynamic_exec_calls = []

    if not static_analysis:
        return {
            "static_entropy":     "none",
            "static_obfuscation": "none",
            "suspicious_imports": "none",
            "dynamic_exec_calls": "none",
        }

    for filename, result in static_analysis.items():
        if "entropy" in result:
            entropy_values.append(f"{filename}:{result['entropy']}")
        if "has_obfuscation" in result:
            obfuscation_values.append(f"{filename}:{result['has_obfuscation']}")
        if result.get("suspicious_imports"):
            suspicious_imports.extend(result["suspicious_imports"])
        if result.get("dynamic_exec_calls"):
            dynamic_exec_calls.extend(result["dynamic_exec_calls"])

    return {
        "static_entropy":     join_list(entropy_values),
        "static_obfuscation": join_list(obfuscation_values),
        "suspicious_imports": join_list(suspicious_imports),
        "dynamic_exec_calls": join_list(dynamic_exec_calls),
    }


def extract_network_values(network_analysis):
    if not network_analysis:
        return {
            "real_domains": "none",
            "external_ips": "none",
            "ip_countries": "none",
            "ip_orgs":      "none",
        }
    external_ips = network_analysis.get("external_ips", [])
    return {
        "real_domains": join_list(network_analysis.get("real_domains", [])),
        "external_ips": join_list([ip.get("ip") for ip in external_ips]),
        "ip_countries": join_list([ip.get("country") for ip in external_ips if ip.get("country")]),
        "ip_orgs":      join_list([ip.get("org")     for ip in external_ips if ip.get("org")]),
    }


def extract_dns_features(dns_queries):
    """Extract actual DNS query values."""
    if not dns_queries:
        return {"dns_queries": "none", "dns_query_count": 0}
    clean = [q for q in dns_queries if q and str(q).strip()]
    return {
        "dns_queries":     join_list(clean),
        "dns_query_count": len(clean),
    }


def extract_http_features(http_hosts, http_methods, http_paths):
    """Extract actual HTTP request values."""
    return {
        "http_hosts":   join_list(http_hosts)   if http_hosts   else "none",
        "http_methods": join_list(http_methods) if http_methods else "none",
        "http_paths":   join_list(http_paths)   if http_paths   else "none",
    }


def extract_tracee_features(tracee_events):
    """Extract actual Tracee eBPF event values."""
    if not tracee_events:
        return {
            "tracee_event_names": "none",
            "tracee_processes":   "none",
            "tracee_event_count": 0,
        }

    event_names = [e.get("event")   for e in tracee_events if e.get("event")]
    processes   = [e.get("process") for e in tracee_events if e.get("process")]

    # Top 10 most frequent event names
    top_events = [name for name, _ in Counter(event_names).most_common(10)]

    return {
        "tracee_event_names": join_list(top_events),
        "tracee_processes":   join_list(list(set(processes))),
        "tracee_event_count": len(tracee_events),
    }


# ============================================================
# BUILD DATASET
# ============================================================

rows = []

if os.path.exists(DECOY_DIR):
    for log_name in sorted(os.listdir(DECOY_DIR)):
        if not log_name.endswith(".json"):
            continue

        log_path = os.path.join(DECOY_DIR, log_name)
        with open(log_path, "r", encoding="utf-8") as f:
            log = json.load(f)

        # Package name directly from log
        package_name = log.get("package", "unknown")

        # Map verdict to label
        raw_verdict = log.get("verdict", "unknown").upper()
        if raw_verdict == "CLEAN":
            label = "CLEAN"
        elif raw_verdict == "SUSPICIOUS":
            label = "SUSPICIOUS"
        else:
            label = "MALICIOUS"

        # Extract all features
        behavior_features = extract_behavior_features(
            log.get("behavior_findings", []),
            log.get("behavior_score", log.get("score", 0))
        )
        static_values  = extract_static_values(log.get("static_analysis", {}))
        network_values = extract_network_values(log.get("network_analysis", {}))
        dns_features   = extract_dns_features(log.get("dns_queries", []))
        http_features  = extract_http_features(
            log.get("http_hosts",   []),
            log.get("http_methods", []),
            log.get("http_paths",   []),
        )
        tracee_features = extract_tracee_features(log.get("tracee_events", []))

        row = {
            # Identity
            "package":            package_name,
            "label":              label,

            # Behavior
            **behavior_features,
            "behavioral_phases":  extract_phases(log.get("behavioral_phases", {})),
            "accessed_files":     join_list(log.get("accessed_files", [])),

            # Network
            **network_values,

            # DNS
            **dns_features,

            # HTTP
            **http_features,

            # Static
            **static_values,

            # Tracee eBPF
            **tracee_features,

            # For dedup sorting
            "_log_name":          log_name,
        }

        rows.append(row)

# Convert to DataFrame
df = pd.DataFrame(rows)

# Keep only latest run per package
df = df.sort_values("_log_name")
df = df.drop_duplicates(subset=["package"], keep="last")
df = df.drop(columns=["_log_name"])

# Save
os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
df.to_csv(OUTPUT_CSV, index=False, encoding="utf-8")

print(f"Saved decoy features to: {OUTPUT_CSV}")
print(f"Rows: {len(df)}")
