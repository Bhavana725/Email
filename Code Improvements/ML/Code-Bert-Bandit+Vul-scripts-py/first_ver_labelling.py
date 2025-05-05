import os
import subprocess
import tempfile
import pandas as pd
from tqdm import tqdm

# File paths
input_csv = "insecure_30k.csv"
vul_scripts_dir = "scripts"
output_labeled_csv = "labeled_ver1.csv"
output_no_vul_csv = "no_vul.csv"

# Load the dataset
df = pd.read_csv(input_csv)

# Collect all script paths from the folder
script_paths = [
    os.path.join(vul_scripts_dir, f)
    for f in os.listdir(vul_scripts_dir)
    if f.endswith('.py')
]

print(f"Found {len(script_paths)} vulnerability scripts.")
print(f"Processing {len(df)} code snippets...\n")

# Prepare result lists
labeled_rows = []
no_vul_rows = []

# Process each code snippet
for idx, row in tqdm(df.iterrows(), total=len(df), desc="Analyzing"):
    code = row.get('code', '')
    if not isinstance(code, str) or not code.strip():
        no_vul_rows.append(row)
        continue

    # Save code to a temp .py file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as tmp:
        tmp.write(code)
        tmp_path = tmp.name

    matched_labels = []

    # Run each vulnerability script
    for script in script_paths:
        script_name = os.path.splitext(os.path.basename(script))[0]

        try:
            result = subprocess.run(['python3', script, tmp_path],
                                    capture_output=True, text=True, timeout=10)
            output = result.stdout.strip()

            # If script gives any output (vul found), label it
            if output and "line" in output.lower():
                matched_labels.append(script_name)
        except Exception as e:
            print(f"[!] {script_name} failed on instance {idx}: {e}")

    # Remove temp file
    os.remove(tmp_path)

    # Add labels to the row or sort it into no-vul
    if matched_labels:
        row['vul_labels'] = ",".join(matched_labels)
        labeled_rows.append(row)
    else:
        no_vul_rows.append(row)

# Save results
pd.DataFrame(labeled_rows).to_csv(output_labeled_csv, index=False)
pd.DataFrame(no_vul_rows).to_csv(output_no_vul_csv, index=False)

print(f"\n✅ Done! Labeled {len(labeled_rows)} vulnerable instances to '{output_labeled_csv}'")
print(f"❌ {len(no_vul_rows)} instances had no detected vulnerabilities. Saved to '{output_no_vul_csv}'")

