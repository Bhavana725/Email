import pandas as pd

# Load your dataset
df = pd.read_csv('labeled_output_staq_cleaned.csv')  # Replace with your actual filename

# Check if 'label' column exists
if 'label' in df.columns:
    unique_labels = df['label'].unique()
    print("Unique classes in 'label' column:")
    print(unique_labels)

    print("\nNumber of instances in each class:")
    print(df['label'].value_counts())
else:
    print("'label' column not found in the dataset.")

