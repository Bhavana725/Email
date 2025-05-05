import pandas as pd

# Load the final dataset
df = pd.read_csv('final.csv')

# Convert label values: 'secure' → 0, 'insecure' → 1
df['label'] = df['label'].map({'secure': 0, 'insecure': 1})

# Display first few rows to verify
print("First 10 rows after label conversion:")
print(df.head(10))

# Check value counts
print("\nNumber of instances per class after conversion:")
print(df['label'].value_counts())

# Save the updated dataset
df.to_csv('final.csv', index=False)
print("\nUpdated dataset saved as final.csv")

