import sys
import os
import json
import joblib
import time
import ast
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
# SELECT CORRECT EXTRACTOR
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

# ======================================
# FEATURE EXTRACTION
# ======================================
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
# DEBUG: PRINT FEATURES
# ======================================
print("\n=== FEATURES ===")
try:
    print(features.to_dict())
except:
    print(features)

# ======================================
# DEBUG: SHAP EXPLANATION
# ======================================
top_shap = []

try:
    import shap

    explainer = shap.Explainer(model)
    shap_values = explainer(X)

    feature_names = preprocess.get_feature_names_out()

    shap_dict = dict(zip(feature_names, shap_values.values[0]))

    top_shap = sorted(shap_dict.items(), key=lambda x: abs(x[1]), reverse=True)[:10]

    print("\n=== TOP SHAP FEATURES ===")
    for k, v in top_shap:
        print(f"{k}: {v}")

except Exception as e:
    print("SHAP error:", e)

# ======================================
# SAVE LOG 
# ======================================

os.makedirs("decoy_logs", exist_ok=True)
os.makedirs("decoy_logs/ml_logs", exist_ok=True)

run_id = str(int(time.time()))

ml_log = {
    "run_id": str(run_id),
    "package": str(original_input),
    "risk_probability": float(proba),
    "prediction": int(pred),
    "timestamp": str(datetime.utcnow().isoformat()),
    "top_shap": [(str(k), float(v)) for k, v in top_shap]
}

with open(f"decoy_logs/ml_logs/log_{run_id}.json", "w") as f:
    json.dump(ml_log, f, indent=4)

with open("decoy_logs/latest.json", "w") as f:
    json.dump(ml_log, f, indent=4)

print(f"Saved ML log: decoy_logs/ml_logs/log_{run_id}.json")
print("Updated decoy_logs/latest.json")

# exit code
sys.exit(1 if pred == 1 else 0)
