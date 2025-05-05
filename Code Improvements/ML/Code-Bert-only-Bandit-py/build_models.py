import pandas as pd
import torch
from transformers import RobertaTokenizer, RobertaModel
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import classification_report, accuracy_score
import xgboost as xgb
import joblib
from tqdm import tqdm

# Load dataset
print("Loading dataset...")
df = pd.read_csv("final_ver2.csv")
X = df['code']
y = df['label']
print(f"Label distribution:\n{y.value_counts()}\n")

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
print(f"Training size: {len(X_train)}, Test size: {len(X_test)}")

# Load CodeBERT base model (not classifier) for embedding extraction
tokenizer = RobertaTokenizer.from_pretrained('microsoft/codebert-base')
model = RobertaModel.from_pretrained('microsoft/codebert-base')
model.eval()

# Move to GPU if available
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model.to(device)

# Function to get embeddings in batches
def get_embeddings(texts, batch_size=16):
    embeddings = []
    for i in tqdm(range(0, len(texts), batch_size), desc="Embedding batches"):
        batch_texts = texts[i:i+batch_size]
        tokens = tokenizer(batch_texts.tolist(), padding=True, truncation=True,
                           max_length=512, return_tensors='pt')
        tokens = {k: v.to(device) for k, v in tokens.items()}

        with torch.no_grad():
            outputs = model(**tokens)
            cls_embeddings = outputs.last_hidden_state.mean(dim=1)  # Mean pooling

        embeddings.append(cls_embeddings.cpu())
    return torch.cat(embeddings, dim=0)

print("Generating embeddings for training data...")
train_embeddings = get_embeddings(X_train)

print("Generating embeddings for test data...")
test_embeddings = get_embeddings(X_test)

# Define models
models = {
    "Logistic Regression": LogisticRegression(max_iter=1000),
    "Random Forest": RandomForestClassifier(),
    "SVM": SVC(),
    "XGBoost": xgb.XGBClassifier(use_label_encoder=False, eval_metric='logloss')
}

# Train and evaluate
for name, clf in models.items():
    print(f"\nTraining {name}...")
    clf.fit(train_embeddings, y_train)
    joblib.dump(clf, f"{name.replace(' ', '_')}_model.joblib")
    print(f"Model saved: {name.replace(' ', '_')}_model.joblib")

    y_pred = clf.predict(test_embeddings)
    print(f"\n{name} Evaluation Report:")
    print(classification_report(y_test, y_pred))
    print(f"Accuracy: {accuracy_score(y_test, y_pred)}")

# Save the CodeBERT model
torch.save(model.state_dict(), "codebert_encoder.pth")
print("\nCodeBERT encoder saved as 'codebert_encoder.pth'")

