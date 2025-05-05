#Tested on real time file - codebert model -solely based on bandit
# Step 1: Imports
import torch
from transformers import RobertaTokenizer, RobertaForSequenceClassification
import os

# Step 2: Configuration
MODEL_DIR = "/content/codebert-secure-classifier/codebert-secure-classifier"  # Your saved model path
MAX_LEN = 512
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# Step 3: Load tokenizer and model
tokenizer = RobertaTokenizer.from_pretrained("microsoft/codebert-base")  # Load the correct tokenizer
model = RobertaForSequenceClassification.from_pretrained(MODEL_DIR)  # Load your fine-tuned model
model.to(DEVICE)
model.eval()

# Step 4: Prediction function
def classify_code_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            code = f.read()
    except Exception as e:
        print(f" Error reading file: {e}")
        return

    # Tokenize input
    tokens = tokenizer(code, return_tensors='pt', truncation=True, padding=True, max_length=MAX_LEN)
    tokens = {key: val.to(DEVICE) for key, val in tokens.items()}

    # Predict
    with torch.no_grad():
        outputs = model(**tokens)
        probs = torch.softmax(outputs.logits, dim=1)
        pred = torch.argmax(probs, dim=1).item()
        confidence = probs[0][pred].item()

    label = "INSECURE" if pred == 1 else "SECURE"
    print(f"\n Prediction: {label} (Confidence: {confidence:.2f})")

# Step 5: File input
filepath = input("Enter the Python file path to analyze (e.g., /content/test.py): ")
classify_code_file(filepath)

