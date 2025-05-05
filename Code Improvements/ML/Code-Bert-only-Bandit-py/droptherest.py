import pandas as pd

# Load the dataset
df = pd.read_csv("final.csv")

# Keep only 'code' and 'label' columns
df = df[['code', 'label']]

# Save the cleaned dataset
df.to_csv("final_cleaned.csv", index=False)

print("✅ Saved final_cleaned.csv with only 'code' and 'label' columns.")

