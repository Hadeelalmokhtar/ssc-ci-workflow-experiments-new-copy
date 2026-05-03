import os
import json
import tarfile
import tempfile
import re
import pandas as pd

# Define base project paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)

# Path to sandbox (decoy) logs
DECOY_DIR = os.path.join(ROOT_DIR, "decoy_logs", "decoy_runs")

# Path to stored packages (.tgz files)
PACKAGE_DIR = os.path.join(ROOT_DIR, "packages", "decoy")

# Output dataset file
OUTPUT_CSV = os.path.join(ROOT_DIR, "CTI_Storage", "decoy_features.csv")


# Convert list values into a readable string (listing format)
def join_list(values):
    if not values:
        return "none"

    clean_values = [str(v) for v in values if v is not None and str(v).strip() != ""]
    return " | ".join(clean_values) if clean_values else "none"


# Extract behavior labels from sandbox findings
def extract_behavior_labels(behavior_findings):
    labels = []

    for item in behavior_findings:
        if isinstance(item, dict):
            label = item.get("label")
            if label:
                labels.append(label)
        else:
            labels.append(str(item))

    return labels


# Extract attack phases (only phases with activity)
def extract_phases(behavioral_phases):
    if not behavioral_phases:
        return []

    phases = []

    for phase, events in behavioral_phases.items():
        if events:
            phases.append(phase)

    return phases


# Extract static analysis features
def extract_static_values(static_analysis):
    entropy_values = []
    suspicious_imports = []
    dynamic_exec_calls = []

    if not static_analysis:
        return {
            "static_entropy":     "none",
            "suspicious_imports": "none",
            "dynamic_exec_calls": "none",
        }

    for filename, result in static_analysis.items():
        if "entropy" in result:
            entropy_values.append(f"{filename}:{result['entropy']}")

        if result.get("suspicious_imports"):
            suspicious_imports.extend(result["suspicious_imports"])

        if result.get("dynamic_exec_calls"):
            dynamic_exec_calls.extend(result["dynamic_exec_calls"])

    return {
        "static_entropy":     join_list(entropy_values),
        "suspicious_imports": join_list(suspicious_imports),
        "dynamic_exec_calls": join_list(dynamic_exec_calls),
    }


# Extract network-related features
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
        "ip_orgs":      join_list([ip.get("org") for ip in external_ips if ip.get("org")]),
    }


# Extract Hybrid Analysis CTI features
def extract_ha_values(ha):
    if not ha or not ha.get("found"):
        return {
            "ha_verdict":         "none",
            "ha_threat_score":    None,
            "ha_av_detect":       None,
            "ha_malware_family":  "none",
            "ha_threat_level":    None,
            "ha_mitre_attacks":   "none",
            "ha_signatures":      "none",
            "ha_network_hosts":   "none",
            "ha_network_domains": "none",
            "ha_tags":            "none",
        }
    return {
        "ha_verdict":         ha.get("verdict", "none"),
        "ha_threat_score":    ha.get("threat_score"),
        "ha_av_detect":       ha.get("av_detect"),
        "ha_malware_family":  ha.get("malware_family", "none"),
        "ha_threat_level":    ha.get("threat_level"),
        "ha_mitre_attacks":   join_list(ha.get("mitre_attacks", [])),
        "ha_signatures":      join_list(ha.get("signatures", [])),
        "ha_network_hosts":   join_list(ha.get("network_hosts", [])),
        "ha_network_domains": join_list(ha.get("network_domains", [])),
        "ha_tags":            join_list(ha.get("tags", [])),
    }


# Build dataset from all decoy logs
rows = []

if os.path.exists(DECOY_DIR):
    for log_name in os.listdir(DECOY_DIR):
        if not log_name.endswith(".json"):
            continue

        log_path = os.path.join(DECOY_DIR, log_name)

        # Load log file
        with open(log_path, "r", encoding="utf-8") as f:
            log = json.load(f)

        # Package name is already stored in the log
        package_name = log.get("package", "unknown")

        # Extract features
        behavior_labels = extract_behavior_labels(log.get("behavior_findings", []))
        phases          = extract_phases(log.get("behavioral_phases", {}))
        static_values   = extract_static_values(log.get("static_analysis", {}))
        network_values  = extract_network_values(log.get("network_analysis", {}))
        ha_values       = extract_ha_values(log.get("hybrid_analysis", {}))

        # Map verdict to label
        raw_verdict = log.get("verdict", "unknown").upper()
        if raw_verdict == "CLEAN":
            label = "CLEAN"
        elif raw_verdict == "SUSPICIOUS":
            label = "SUSPICIOUS"
        else:
            label = "MALICIOUS"

        # Build dataset row
        row = {
            # Identity
            "package":            package_name,
            "label":              label,

            # Sandbox behavioral features
            "behavior_findings":  join_list(behavior_labels),
            "behavioral_phases":  join_list(phases),
            "accessed_files":     join_list(log.get("accessed_files", [])),

            # Network features
            "real_domains":       network_values["real_domains"],
            "external_ips":       network_values["external_ips"],
            "ip_countries":       network_values["ip_countries"],
            "ip_orgs":            network_values["ip_orgs"],

            # Static analysis features
            "static_entropy":     static_values["static_entropy"],
            "suspicious_imports": static_values["suspicious_imports"],
            "dynamic_exec_calls": static_values["dynamic_exec_calls"],

            # Hybrid Analysis CTI features
            **ha_values,
        }

        rows.append(row)

# Convert to DataFrame
df = pd.DataFrame(rows)

# Keep only the latest run per package (avoid duplicates)
df = df.drop_duplicates(subset=["package"], keep="last")

# Ensure output directory exists
os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)

# Save dataset
df.to_csv(OUTPUT_CSV, index=False, encoding="utf-8")

print(f"Saved decoy features to: {OUTPUT_CSV}")
print(f"Rows: {len(df)}")
