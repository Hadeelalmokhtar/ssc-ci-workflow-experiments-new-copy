import os
import json
import tarfile
import tempfile
import pandas as pd

# =========================================
# Project path configuration
# =========================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)

DECOY_DIR = os.path.join(ROOT_DIR, "decoy_logs", "decoy_runs")
PACKAGE_DIR = os.path.join(ROOT_DIR, "packages", "decoy")
OUTPUT_CSV = os.path.join(ROOT_DIR, "CTI_Storage", "decoy_features.csv")


# =========================================
# Utility: Convert list to string listing
# =========================================

def join_list(values):
    """
    Convert a list of values into a string representation.
    The original values are preserved without transformation.
    Empty values are represented as an empty string.
    """

    if not values:
        return ""

    return " | ".join(str(v) for v in values if v is not None)


# =========================================
# Extract original package name
# =========================================

def get_original_package_name(package_file):
    """
    Extract the original package name from:
    1. Extracted package folders
    2. Compressed packages (.tgz / .tar.gz)

    The function searches for 'package.json' and returns the 'name' field.
    If extraction fails, the original file name is returned.
    """

    package_path = os.path.join(PACKAGE_DIR, package_file)

    # Case 1: already extracted folder
    if os.path.isdir(package_path):
        for root, _, files in os.walk(package_path):
            if "package.json" in files:
                pkg_json = os.path.join(root, "package.json")

                try:
                    with open(pkg_json, "r", encoding="utf-8", errors="ignore") as f:
                        data = json.load(f)

                    if data.get("name"):
                        return data["name"]

                except Exception:
                    return package_file

    # Case 2: compressed package
    if os.path.isfile(package_path) and (
        package_file.endswith(".tgz") or package_file.endswith(".tar.gz")
    ):
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                with tarfile.open(package_path, "r:gz") as tar:
                    tar.extractall(temp_dir)

                for root, _, files in os.walk(temp_dir):
                    if "package.json" in files:
                        pkg_json = os.path.join(root, "package.json")

                        with open(pkg_json, "r", encoding="utf-8", errors="ignore") as f:
                            data = json.load(f)

                        if data.get("name"):
                            return data["name"]

        except Exception:
            return package_file

    # Case 3: fallback (folder exists without extension)
    folder_name = package_file.replace(".tgz", "").replace(".tar.gz", "")
    folder_path = os.path.join(PACKAGE_DIR, folder_name)

    if os.path.isdir(folder_path):
        for root, _, files in os.walk(folder_path):
            if "package.json" in files:
                pkg_json = os.path.join(root, "package.json")

                try:
                    with open(pkg_json, "r", encoding="utf-8", errors="ignore") as f:
                        data = json.load(f)

                    if data.get("name"):
                        return data["name"]

                except Exception:
                    return package_file

    return package_file


# =========================================
# Extract behavior labels
# =========================================

def extract_behavior_labels(behavior_findings):
    """
    Extract behavior labels exactly as recorded in the log.
    """

    labels = []

    for item in behavior_findings:
        if isinstance(item, dict):
            label = item.get("label")
            if label:
                labels.append(label)
        elif isinstance(item, str):
            labels.append(item)

    return labels


# =========================================
# Extract behavioral phases
# =========================================

def extract_phases(behavioral_phases):
    """
    Extract phases that contain activity.
    """

    if not behavioral_phases:
        return []

    return [phase for phase, events in behavioral_phases.items() if events]


# =========================================
# Extract static analysis values
# =========================================

def extract_static_values(static_analysis):
    """
    Extract static analysis values without modification.
    """

    entropy_values = []
    obfuscation_values = []
    suspicious_imports = []
    dynamic_exec_calls = []

    if not static_analysis:
        return {
            "static_entropy": "",
            "static_obfuscation": "",
            "suspicious_imports": "",
            "dynamic_exec_calls": "",
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


# =========================================
# Extract network values
# =========================================

def extract_network_values(network_analysis):
    """
    Extract network values exactly as recorded in the log.
    """

    if not network_analysis:
        return {
            "real_domains": "",
            "external_ips": "",
            "ip_countries": "",
            "ip_orgs": "",
            "http_summary": "",
        }

    external_ips = network_analysis.get("external_ips", [])

    return {
        "real_domains": join_list(network_analysis.get("real_domains", [])),
        "external_ips": join_list([ip.get("ip") for ip in external_ips if ip.get("ip")]),
        "ip_countries": join_list([ip.get("country") for ip in external_ips if ip.get("country")]),
        "ip_orgs": join_list([ip.get("org") for ip in external_ips if ip.get("org")]),
        "http_summary": json.dumps(network_analysis.get("http_summary", {})),
    }


# =========================================
# Build dataset
# =========================================

rows = []

if os.path.exists(DECOY_DIR):
    for log_name in os.listdir(DECOY_DIR):
        if not log_name.endswith(".json"):
            continue

        log_path = os.path.join(DECOY_DIR, log_name)

        with open(log_path, "r", encoding="utf-8") as f:
            log = json.load(f)

        package_file = log.get("package_file") or log.get("package", "")
        package_name = get_original_package_name(package_file)

        behavior_labels = extract_behavior_labels(log.get("behavior_findings", []))
        phases = extract_phases(log.get("behavioral_phases", {}))
        static_values = extract_static_values(log.get("static_analysis", {}))
        network_values = extract_network_values(log.get("network_analysis", {}))

        row = {
            "package": package_name,
            "package_file": package_file,
            "label": log.get("verdict", ""),

            "behavior_findings": join_list(behavior_labels),
            "behavioral_phases": join_list(phases),
            "accessed_files": join_list(log.get("accessed_files", [])),

            **network_values,
            **static_values,
        }

        rows.append(row)


df = pd.DataFrame(rows)

os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
df.to_csv(OUTPUT_CSV, index=False, encoding="utf-8")

print(f"Saved decoy features to: {OUTPUT_CSV}")
print(f"Rows: {len(df)}")
