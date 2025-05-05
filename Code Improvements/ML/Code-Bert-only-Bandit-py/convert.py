import pandas as pd
import json

# Read the .jsonl file line by line
data = []
with open('staqc-py-cleaned.jsonl', 'r') as f:
    for line in f:
        data.append(json.loads(line))

# Convert to DataFrame
df = pd.DataFrame(data)

# Save as CSV
df.to_csv('output_staq.csv', index=False)

