import pandas as pd
import os
import subprocess
import tempfile
from tqdm import tqdm

# === Step 1: Load and Sample 1 Lakh from the cleaned dataset ===
input_csv = "output_staq_cleaned.csv"
sampled_csv = "sampled_30k.csv"
sample_size = 30_000

df = pd.read_csv(input_csv)
sampled_df = df.sample(n=sample_size, random_state=42)
sampled_df.to_csv(sampled_csv, index=False)
print(f"[Step 1] Sampled {sample_size} rows and saved to '{sampled_csv}'.")

# === Step 2: Run Bandit on each snippet to label secure/insecure ===
secure_rows = []
insecure_rows = []

print(f"[Step 2] Running Bandit on {len(sampled_df)} code snippets...")

for idx, row in tqdm(sampled_df.iterrows(), total=len(sampled_df), desc="Analyzing with Bandit"):
    code = row.get('code', '')
    
    if not isinstance(code, str):
        code = str(code) if pd.notnull(code) else ""
    if not code.strip():
        continue

    # Write code to a temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as tmp:
        tmp.write(code)
        tmp_path = tmp.name

    try:
        result = subprocess.run(['bandit', '-q', '-f', 'json', tmp_path],
                                capture_output=True, text=True, timeout=10)
        output = result.stdout

        if '"results": []' in output:
            secure_rows.append(row)
        else:
            insecure_rows.append(row)
    except Exception as e:
        print(f"Bandit error at index {idx}: {e}")
        insecure_rows.append(row)

    os.remove(tmp_path)

# Save secure and insecure files
secure_csv = "secure_30k.csv"
insecure_csv = "insecure_30k.csv"

pd.DataFrame(secure_rows).to_csv(secure_csv, index=False)
pd.DataFrame(insecure_rows).to_csv(insecure_csv, index=False)

# === Step 3: Print counts ===
print(f"\n[Step 3] Done:")
print(f"✅ Secure instances saved:   {len(secure_rows)} to '{secure_csv}'")
print(f"❌ Insecure instances saved: {len(insecure_rows)} to '{insecure_csv}'")

