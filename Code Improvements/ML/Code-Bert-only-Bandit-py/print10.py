import pandas as pd

# Replace 'your_file.csv' with the path to your CSV file
file_path = r'output_staq.csv'

# Read the CSV file
df = pd.read_csv(file_path)

# Print the first 10 rows with all columns
pd.set_option('display.max_columns', None)  # Ensures all columns are shown
print("First 10 rows (before dropping columns):")
print(df.head(10))

# Get the number of rows and columns before dropping columns
num_rows, num_columns = df.shape
print(f"\nNumber of rows: {num_rows}")
print(f"Number of columns: {num_columns}")

# Print the names of the columns (features) before dropping
print("\nColumn names (before dropping):")
print(df.columns.tolist())

# Drop the 'rawDescription' and 'attribution' columns
df = df.drop(['rawDescription', 'attribution'], axis=1)

# Print the first 10 rows after dropping the columns
print("\nFirst 10 rows (after dropping columns):")
print(df.head(10))

# Get the updated number of rows and columns
num_rows, num_columns = df.shape
print(f"\nUpdated number of rows: {num_rows}")
print(f"Updated number of columns: {num_columns}")

# Print the updated names of the columns (features)
print("\nUpdated column names (after dropping):")
print(df.columns.tolist())

# Save the modified DataFrame to a new CSV file
new_file_path = r'output_staq_cleaned.csv'  # Specify your new file name or path
df.to_csv(new_file_path, index=False)

print(f"\nDataset saved as {new_file_path}")

