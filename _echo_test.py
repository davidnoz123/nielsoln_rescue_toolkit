import subprocess, sys
result = subprocess.run(["echo", "hello from RescueZilla"], capture_output=True, text=True, shell=True)
print(result.stdout.strip())
print("Python:", sys.version)
print("Host:", subprocess.run(["hostname"], capture_output=True, text=True).stdout.strip())
