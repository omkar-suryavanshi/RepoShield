
from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split

DATA_PATH = Path("data/reposhield_dataset.csv")
MODEL_PATH = Path("models/reposhield_model.joblib")

# Load the labeled dataset.
df = pd.read_csv(DATA_PATH).dropna(
    subset=["source_code", "label"]
)

X = df["source_code"].astype(str)
y = df["label"].astype(int)

# Recreate the same test split used during training.
_, X_test, _, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y,
)

# Load the trained model.
model = joblib.load(MODEL_PATH)

# Predict the test samples.
predictions = model.predict(X_test)

print("\n===== RepoShield Model Evaluation =====")
print(f"Total labeled samples: {len(df)}")
print(f"Test samples: {len(X_test)}")

print(f"\nAccuracy: {accuracy_score(y_test, predictions):.4f}")

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["Non-vulnerable", "Vulnerable"],
        zero_division=0,
    )
)

print("Confusion Matrix:")
print(confusion_matrix(y_test, predictions, labels=[0, 1]))

print("\nEvaluation complete.")
print("Results apply to this test split, not all Python code.")
