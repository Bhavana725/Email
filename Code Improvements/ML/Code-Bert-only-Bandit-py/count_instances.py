import pandas as pd

def count_instances_csv(file_path):
    df = pd.read_csv(file_path)
    return len(df)

file_path = 'secure_dataset.csv'  # Replace with your file path
print(f"Number of instances: {count_instances_csv(file_path)}")

