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


# Extract the original package name from the package file
def get_original_package_name(package_file):
    package_path = os.path.join(PACKAGE_DIR, package_file)

    # If file does not exist, return the file name
    if not os.path.exists(package_path):
        return package_file

    # Handle npm packages (.tgz)
    if package_file.endswith(".tgz") or package_file.endswith(".tar.gz"):
        try:
            # Extract to a temporary directory
            with tempfile.TemporaryDirectory() as temp_dir:
                with tarfile.open(package_path, "r:gz") as tar:
                    tar.extractall(temp_dir)

                # Search for package.json
                for root, _, files in os.walk(temp_dir):
                    if "package.json" in files:
                        pkg_json = os.path.join(root, "package.json")

                        with open(pkg_json, "r", encoding="utf-8", errors="ignore") as f:
                            data = json.load(f)

                        # Return the original package name
                        if data.get("name"):
                            return data["name"]

        except Exception:
            return package_file

    # Handle Python packages
    if package_file.endswith(".py"):
        try:
            with open(package_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Extract name from setup.py style
            match = re.search(r'name\s*=\s*["\']([^"\']+)["\']', content)
            if match:
                return match.group(1)

        except Exception:
            pass

    # Fallback
    return package_file


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
    obfuscation_values = []
    suspicious_imports = []
    dynamic_exec_calls = []

    if not static_analysis:
        return {
            "static_entropy": "none",
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
        "static_entropy": join_list(entropy_values),
        "static_obfuscation": join_list(obfuscation_values),
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
            "ip_orgs": "none",
            "http_summary": "none",
        }

    external_ips = network_analysis.get("external_ips", [])

    return {
        "real_domains": join_list(network_analysis.get("real_domains", [])),
        "external_ips": join_list([ip.get("ip") for ip in external_ips]),
        "ip_countries": join_list([ip.get("country") for ip in external_ips if ip.get("country")]),
        "ip_orgs": join_list([ip.get("org") for ip in external_ips if ip.get("org")]),
        "http_summary": json.dumps(network_analysis.get("http_summary", {})),
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

        # Extract package names
        package_name = log.get("package", "unknown") 

        # Extract features
        behavior_labels = extract_behavior_labels(log.get("behavior_findings", []))
        phases = extract_phases(log.get("behavioral_phases", {}))
        static_values = extract_static_values(log.get("static_analysis", {}))
        network_values = extract_network_values(log.get("network_analysis", {}))

        # Map verdict to label
        raw_verdict = log.get("verdict", "unknown").upper()
        if raw_verdict == "CLEAN":
            label = "CLEAN"
        elif raw_verdict == "SUSPICIOUS":
            label = "SUSPICIOUS"
        else:
            # MALICIOUS and UNKNOWN both become MALICIOUS
            label = "MALICIOUS"

        # Build dataset row
        row = {
            "package": package_name,
            "label": label,

            "behavior_findings": join_list(behavior_labels),
            "behavioral_phases": join_list(phases),
            "accessed_files":    join_list(log.get("accessed_files", [])),

            "real_domains":       network_values["real_domains"],
            "external_ips":       network_values["external_ips"],
            "ip_countries":       network_values["ip_countries"],
            "ip_orgs":            network_values["ip_orgs"],

            "static_entropy":     static_values["static_entropy"],
            "suspicious_imports": static_values["suspicious_imports"],
            "dynamic_exec_calls": static_values["dynamic_exec_calls"],
        }

        rows.append(row)

# Convert to DataFrame
df = pd.DataFrame(rows)

# Ensure output directory exists
os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)

# Save dataset
df.to_csv(OUTPUT_CSV, index=False, encoding="utf-8")

print(f"Saved decoy features to: {OUTPUT_CSV}")
print(f"Rows: {len(df)}")
