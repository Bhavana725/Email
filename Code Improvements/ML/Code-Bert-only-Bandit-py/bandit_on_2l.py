import pandas as pd
import os
import uuid
import subprocess
import tempfile
from tqdm import tqdm

# Load CSV
input_csv = "output_staq_cleaned.csv"
df = pd.read_csv(input_csv)

# Output lists
secure_rows = []
insecure_rows = []

print(f"Running Bandit on {len(df)} code snippets...")

for idx, row in tqdm(df.iterrows(), total=len(df), desc="Analyzing with Bandit"):
    # Ensure 'code' column contains a valid string
    code = row['code']
    
    if not isinstance(code, str):  # Check if it's not a string
        code = str(code) if pd.notnull(code) else ""  # Convert to string if possible, or make it empty
    
    if not code.strip():  # Skip empty or whitespace-only code
        print(f"Skipping invalid code at index {idx}.")
        continue
    
    # Create a temp file with the code
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as tmp:
        tmp.write(code)
        tmp_path = tmp.name

    # Run Bandit
    try:
        result = subprocess.run(['bandit', '-q', '-f', 'json', tmp_path],
                                capture_output=True, text=True, timeout=10)
        output = result.stdout

        # Check if issues found
        if '"results": []' in output:
            secure_rows.append(row)
        else:
            insecure_rows.append(row)
    except Exception as e:
        print(f"Bandit failed for snippet {idx}: {e}")
        # Treat unknowns as insecure to be safe
        insecure_rows.append(row)
    
    # Cleanup temp file
    os.remove(tmp_path)

# Save to CSVs
pd.DataFrame(secure_rows).to_csv("secure_dataset.csv", index=False)
pd.DataFrame(insecure_rows).to_csv("insecure_dataset.csv", index=False)

print(f"\nDone. Saved {len(secure_rows)} secure and {len(insecure_rows)} insecure code snippets.")

