import pandas as pd

# Replace with your actual file path
file_path = r'labeled_output_staq_cleaned.csv'

# Read the CSV file
df = pd.read_csv(file_path)

# Display first 10 rows before merging
pd.set_option('display.max_columns', None)
print("First 10 rows (before merging labels):")
print(df.head(10))

# Merge 'maybe' and 'insecure' into a single 'insecure' label
df['label'] = df['label'].replace({'maybe': 'insecure'})

# Display first 10 rows after merging
print("\nFirst 10 rows (after merging 'maybe' into 'insecure'):")
print(df.head(10))

# Display class distribution after merging
print("\nNumber of instances in each class after merging:")
print(df['label'].value_counts())

# Save the modified DataFrame to a new CSV file
df.to_csv('final.csv', index=False)
print("\nDataset saved as final.csv")

