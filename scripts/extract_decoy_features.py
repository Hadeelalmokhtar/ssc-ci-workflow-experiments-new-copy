import os
import json
import ipaddress
import pandas as pd


DECOY_DIR = "decoy_logs/decoy_runs"
OUTPUT_CSV = "CTI_Storage/decoy_features.csv"

def is_private_or_local(ip: str) -> int:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return int(
            ip_obj.is_private or
            ip_obj.is_loopback or
            ip_obj.is_link_local or
            ip_obj.is_multicast
        )
    except Exception:
        return 0

def is_public(ip: str) -> int:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return int(not (
            ip_obj.is_private or
            ip_obj.is_loopback or
            ip_obj.is_link_local or
            ip_obj.is_multicast
        ))
    except Exception:
        return 0

def extract_one(log: dict) -> dict:
    package = log.get("package", "unknown")

    processes = log.get("processes", []) or []
    files = log.get("files", []) or []
    domains = log.get("domains", []) or []
    dns = log.get("dns", []) or []
    http_requests = log.get("http_requests", []) or []
    decoded_payloads = log.get("decoded_payloads", []) or []
    network_details = log.get("network_details", []) or []
    timeline = log.get("timeline", []) or []

    ips = [x.get("ip") for x in network_details if isinstance(x, dict) and x.get("ip")]
    countries = [x.get("country") for x in network_details if isinstance(x, dict) and x.get("country")]

    timeline_events = [t.get("event", "") for t in timeline if isinstance(t, dict)]

    num_public_ips = sum(is_public(ip) for ip in ips)
    num_private_or_local_ips = sum(is_private_or_local(ip) for ip in ips)

    has_node_process = int(any("node" == str(p).strip().lower() for p in processes))
    has_execve = int(any("execve(" in e for e in timeline_events))
    has_openat = int(any("openat(" in e for e in timeline_events))
    has_access_ld_preload = int(any("/etc/ld.so.preload" in e for e in timeline_events))

    row = {
        "package_name": package,

        # counts
        "decoy_num_processes": len(processes),
        "decoy_num_files": len(files),
        "decoy_num_domains": len(domains),
        "decoy_num_dns": len(dns),
        "decoy_num_http_requests": len(http_requests),
        "decoy_num_payloads": len(decoded_payloads),
        "decoy_timeline_length": len(timeline),
        "decoy_num_network_ips": len(ips),
        "decoy_num_public_ips": num_public_ips,
        "decoy_num_private_or_local_ips": num_private_or_local_ips,
        "decoy_num_countries": len(set(countries)),

        # binary flags
        "decoy_has_processes": int(len(processes) > 0),
        "decoy_has_files": int(len(files) > 0),
        "decoy_has_domains": int(len(domains) > 0),
        "decoy_has_dns": int(len(dns) > 0),
        "decoy_has_http_requests": int(len(http_requests) > 0),
        "decoy_has_payloads": int(len(decoded_payloads) > 0),
        "decoy_has_network": int(len(ips) > 0),
        "decoy_has_timeline": int(len(timeline) > 0),

        # behavioral indicators
        "decoy_has_node_process": has_node_process,
        "decoy_has_execve": has_execve,
        "decoy_has_openat": has_openat,
        "decoy_has_access_ld_preload": has_access_ld_preload,
    }

    return row

def main():
    rows = []

    os.makedirs("CTI_Storage", exist_ok=True)

    for fname in os.listdir(DECOY_DIR):
        if not fname.endswith(".json"):
            continue

        fpath = os.path.join(DECOY_DIR, fname)
        with open(fpath, "r", encoding="utf-8") as f:
            log = json.load(f)

        rows.append(extract_one(log))

    df = pd.DataFrame(rows)
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"Saved {len(df)} rows to {OUTPUT_CSV}")

if __name__ == "__main__":
    main()
