import pandas as pd

# Load the input dataset
input_csv = "output_staq_cleaned.csv"
df = pd.read_csv(input_csv)

# Extract the first 15,000 rows (or use random sampling if preferred)
subset_df = df.head(15000)  # or use df.sample(n=15000, random_state=42) for random rows

# Save to a new CSV file
subset_df.to_csv("15k_dataset.csv", index=False)

print("Saved 15,000 instances to 15k_dataset.csv")

