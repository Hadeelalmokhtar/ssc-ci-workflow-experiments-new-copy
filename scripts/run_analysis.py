import sys
import os
import json
import joblib
import subprocess 
import time
import ast
import math
import re
import tarfile
import tempfile
from datetime import datetime

# ======================================
# IMPORT SAP EXTRACTORS
# ======================================
from scripts.sap_feature_engine.pypi_feature_extractor import PyPI_Feature_Extractor
from scripts.sap_feature_engine.npm_feature_extractor import NPM_Feature_Extractor
from scripts.package_adapter import PackageAdapter

# ======================================
# PATHS
# ======================================
model_path = "ml/malicious_model.pkl"
preprocess_path = "ml/preprocess.pkl"

# ======================================
# INPUT
# ======================================
if len(sys.argv) < 2:
    print("Usage: python -m scripts.run_analysis <file_or_folder>")
    sys.exit(1)

original_input = sys.argv[1]

# ======================================
# HANDLE COMPRESSED PACKAGES
# ======================================
def extract_package_if_needed(path):
    if path.endswith(".tgz") or path.endswith(".tar.gz"):
        temp_dir = tempfile.mkdtemp()
        with tarfile.open(path, "r:gz") as tar:
            tar.extractall(temp_dir)
        return temp_dir
    return path

file_path = extract_package_if_needed(original_input)

# ======================================
# BUILD PACKAGE STRUCTURE
# ======================================
adapter = PackageAdapter()

if os.path.isfile(file_path):
    package_root = adapter.build_from_single_file(file_path)
else:
    package_root = file_path

# ======================================
# SELECT CORRECT EXTRACTOR (STABLE FIX)
# ======================================

def contains_package_json(path):
    for root, _, files in os.walk(path):
        if "package.json" in files:
            return True
    return False

if contains_package_json(file_path):
    extractor = NPM_Feature_Extractor()
    repo_name = "NPM"
else:
    extractor = PyPI_Feature_Extractor()
    repo_name = "PyPI"

# IMPORTANT: ALWAYS DEFINE FEATURES
features = extractor.extract_features(package_root)
features["Package Repository"] = repo_name

# ======================================
# LOAD MODEL
# ======================================
preprocess = joblib.load(preprocess_path)
model = joblib.load(model_path)

X = preprocess.transform(features)

pred = int(model.predict(X)[0])
proba = float(model.predict_proba(X)[0][1]) if hasattr(model, "predict_proba") else 0.0

print("Prediction:", pred)
print("Malicious Probability:", proba)

# ======================================
# FIND EXECUTABLE FILE FOR DYNAMIC
# ======================================
analysis_target = None

if os.path.isdir(file_path):
    for root, dirs, files in os.walk(file_path):
        for fname in files:
            if original_input.endswith(".tgz") and fname.endswith(".js"):
                analysis_target = os.path.join(root, fname)
                break
            elif fname.endswith(".py"):
                analysis_target = os.path.join(root, fname)
                break
        if analysis_target:
            break

if analysis_target is None:
    print("No executable file found for dynamic analysis.")
    sys.exit(0)

# ======================================
# ENTROPY
# ======================================
def calculate_entropy(data):
    if not data:
        return 0
    prob = [float(data.count(c)) / len(data) for c in set(data)]
    return -sum(p * math.log2(p) for p in prob)

with open(analysis_target, "r", errors="ignore") as f:
    content = f.read()

file_entropy = round(calculate_entropy(content), 4)

# ======================================
# STRACE SANDBOX
# ======================================
print("Starting sandbox execution with strace...")

start_time = time.time()

process = subprocess.Popen(
    ["strace", "-f", "-e", "trace=execve,open,connect,write,fork",
     "node" if repo_name == "NPM" else "python",
     analysis_target],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

try:
    stdout, stderr = process.communicate(timeout=15)
except subprocess.TimeoutExpired:
    process.kill()
    stdout, stderr = process.communicate()

execution_time = round(time.time() - start_time, 3)

# ======================================
# SAVE LOG
# ======================================
os.makedirs("decoy_logs", exist_ok=True)

run_id = str(int(time.time()))

dynamic_log = {
    "run_id": run_id,
    "package": original_input,
    "risk_probability": proba,
    "prediction": pred,
    "file_entropy": file_entropy,
    "execution_time": execution_time,
    "timestamp": datetime.utcnow().isoformat()
}

with open(f"decoy_logs/log_{run_id}.json", "w") as f:
    json.dump(dynamic_log, f, indent=4)

with open("decoy_logs/latest.json", "w") as f:
    json.dump(dynamic_log, f, indent=4)

print("Logs saved.")

sys.exit(1 if pred == 1 else 0)
