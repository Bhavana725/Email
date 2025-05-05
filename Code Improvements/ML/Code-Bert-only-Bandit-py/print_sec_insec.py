import pandas as pd

# Load the datasets
insecure_df = pd.read_csv("insecure_dataset.csv")
secure_df = pd.read_csv("secure_dataset.csv")

# Print column names
print("Columns in insecure_dataset.csv:")
print(insecure_df.columns.tolist())

print("\nColumns in secure_dataset.csv:")
print(secure_df.columns.tolist())

