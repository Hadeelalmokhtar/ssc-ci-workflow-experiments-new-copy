import os
import subprocess
import socket
import base64
import time
import sys
import requests

# ===============================
# Fake Obfuscation Section
# ===============================

encoded_payload = base64.b64encode(b"SensitiveData123").decode()

hex_string = "\\x41\\x42\\x43\\x44"

def decode_payload(data):
    return base64.b64decode(data).decode()

# ===============================
# Suspicious Execution Functions
# ===============================

def run_system_command():
    os.system("echo Running system command")

def run_subprocess():
    subprocess.Popen(["echo", "Subprocess execution"])

def exec_code():
    code = "print('Dynamic exec triggered')"
    exec(code)

def eval_code():
    expression = "2 + 2"
    result = eval(expression)
    print("Eval result:", result)

# ===============================
# Network Simulation
# ===============================

def simulate_network():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(("example.com", 80))
        s.close()
    except:
        pass

def fake_http_request():
    try:
        requests.get("http://example.com", timeout=2)
    except:
        pass

# ===============================
# Persistence Simulation
# ===============================

def create_fake_file():
    with open("temp_artifact.txt", "w") as f:
        f.write("This is a test artifact")

# ===============================
# Main Execution Flow
# ===============================

if __name__ == "__main__":

    print("Starting malicious simulation...")
 
    decoded = decode_payload(encoded_payload)
    print("Decoded:", decoded)

    run_system_command()
    run_subprocess()
    exec_code()
    eval_code()
    simulate_network()
    fake_http_request()
    create_fake_file()

    time.sleep(1)

    print("Simulation completed.")  
 
