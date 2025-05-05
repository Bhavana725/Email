import pandas as pd

# Replace 'your_file.csv' with the path to your CSV file
file_path = r'labeled_output_staq_cleaned.csv'

# Read the CSV file
df = pd.read_csv(file_path)

# Print the first 10 rows with all columns
pd.set_option('display.max_columns', None)  # Ensures all columns are shown
print("First 10 rows (before dropping columns):")
print(df.head(10))


