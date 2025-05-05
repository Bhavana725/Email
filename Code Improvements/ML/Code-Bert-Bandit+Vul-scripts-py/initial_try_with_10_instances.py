import os
import subprocess
import tempfile
import pandas as pd
from tqdm import tqdm

# Config
insecure_csv = "insecure_30k.csv"
vul_scripts_dir = "scripts"  # Folder where your scripts like SSRF.py, injection.py, etc. are

# Load the first 10 insecure instances
df = pd.read_csv(insecure_csv)
df = df.head(10)

# Collect all vulnerability script paths
script_paths = [
    os.path.join(vul_scripts_dir, f)
    for f in os.listdir(vul_scripts_dir)
    if f.endswith('.py')
]

print(f"\nRunning vulnerability scripts on {len(df)} insecure instances...\n")

# Iterate through each code snippet
for idx, row in tqdm(df.iterrows(), total=len(df), desc="Checking vulnerability labels"):
    code = row['code']
    if not isinstance(code, str) or not code.strip():
        continue

    print(f"\n--- Instance {idx + 1} ---")

    # Write code snippet to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as tmp:
        tmp.write(code)
        tmp_path = tmp.name

    matched_labels = []

    # Run each vulnerability script
    for script in script_paths:
        script_name = os.path.splitext(os.path.basename(script))[0]

        try:
            # Run the script and capture output
            result = subprocess.run(['python3', script, tmp_path],
                                    capture_output=True, text=True, timeout=10)

            output = result.stdout.strip()

            # Look for line indicators in output (you can customize this)
            if "line" in output.lower() or "Line" in output:
                matched_labels.append(script_name)
                print(f"[+] {script_name} matched!")
                print("Output:")
                print(output)
        except subprocess.TimeoutExpired:
            print(f"[!] {script_name} timed out.")
        except Exception as e:
            print(f"[!] Error running {script_name}: {e}")

    if not matched_labels:
        print("[-] No vulnerabilities found for this instance.")

    # Remove temp file
    os.remove(tmp_path)

