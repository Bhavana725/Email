import pandas as pd
import subprocess
import tempfile

# Load the dataset
df = pd.read_csv('sampled_1k_snippets.csv')

# Function to label code snippets
def label_with_bandit(code_snippet, idx):
    print(f"Processing snippet {idx}...")  # Debugging statement to show progress
    
    # Create a temporary file for each code snippet
    with tempfile.NamedTemporaryFile('w', suffix='.py', delete=False) as tmp:
        tmp.write(code_snippet)
        tmp_path = tmp.name
    
    # Run Bandit on the temporary file
    print(f"Running Bandit on snippet {idx}...")  # Debugging statement
    result = subprocess.run(
        ['bandit', '-q', '-f', 'json', tmp_path],
        capture_output=True, text=True
    )

    output = result.stdout
    # Check Bandit output and label based on severity
    if '"issue_confidence": "HIGH"' in output or '"issue_severity": "HIGH"' in output:
        print(f"Snippet {idx} marked as insecure")  # Debugging statement
        return 'insecure'
    elif '"results": []' in output:
        print(f"Snippet {idx} marked as secure")  # Debugging statement
        return 'secure'
    else:
        print(f"Snippet {idx} marked as maybe")  # Debugging statement
        return 'maybe'

# Apply Bandit to the 'code' column and label each snippet
print("Starting to label code snippets...")
df['label'] = df['code'].apply(lambda x: label_with_bandit(x, df['code'].index[df['code'] == x].tolist()[0]))

# Save the labeled dataset
df.to_csv('labeled_output_staq_cleaned.csv', index=False)

print("Dataset labeled and saved as 'labeled_output_staq_cleaned.csv'")

