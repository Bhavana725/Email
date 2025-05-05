import pandas as pd

# Load the dataset
file_path = 'output_staq_cleaned.csv'  # Replace with your actual path if needed
df = pd.read_csv(file_path)

# Check the column names (optional)
print("Columns in the dataset:", df.columns.tolist())

# Shuffle and select 1000 random rows
sampled_df = df.sample(n=1000, random_state=42)

# Save to a new CSV
sampled_df.to_csv('sampled_1k_snippets.csv', index=False)

print("✅ 1000 code snippets saved to 'sampled_1k_snippets.csv'")

