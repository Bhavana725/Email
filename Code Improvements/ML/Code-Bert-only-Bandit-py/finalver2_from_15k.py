import pandas as pd

# Load datasets
insecure_df = pd.read_csv("insecure_dataset.csv")
secure_df = pd.read_csv("secure_dataset.csv")

# Get number of insecure instances
n = len(insecure_df)

# Trim to only 'code' column and add labels
insecure_df = insecure_df[['code']].copy()
insecure_df['label'] = 1

secure_df = secure_df[['code']].sample(n=n, random_state=42).copy()
secure_df['label'] = 0

# Combine and shuffle
final_df = pd.concat([insecure_df, secure_df], ignore_index=True)
final_df = final_df.sample(frac=1, random_state=42).reset_index(drop=True)

# Save to CSV
final_df.to_csv("final_ver2.csv", index=False)

# Print class distribution
print("Class distribution:")
print(final_df['label'].value_counts())

