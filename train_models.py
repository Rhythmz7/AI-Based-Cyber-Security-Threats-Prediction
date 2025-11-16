import pandas as pd
import pickle
import joblib
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

print("Starting model training script...")

# Define paths
PROCESSED_DATA_PATH = "data/processed/processed_data.pkl"
MODEL_SAVE_PATH = "models/threat_model.pkl"
MODEL_DIR = "models"

# Create models directory if it doesn't exist
os.makedirs(MODEL_DIR, exist_ok=True)

# 1. Load processed data
try:
    with open(PROCESSED_DATA_PATH, "rb") as f:
        data = pickle.load(f)
    
    X_train = data['X_train']
    y_train = data['y_train']
    X_test = data['X_test']
    y_test = data['y_test']
    attack_map = data['attack_types']
    
    print(f"Loaded processed data. Training with {len(y_train)} samples.")
    
except FileNotFoundError:
    print(f"Error: Processed data file not found at {PROCESSED_DATA_PATH}")
    print("Please run preprocess.py first.")
    exit()
except Exception as e:
    print(f"An error occurred loading data: {e}")
    exit()

# 2. Train the Random Forest Model
# We use Random Forest as it's a great balance of speed and accuracy
print("Training Random Forest model...")
model = RandomForestClassifier(
    n_estimators=100,  # 100 trees is a good default
    random_state=42, 
    n_jobs=-1,         # Use all available CPU cores
    max_depth=20       # Prevents overfitting
)

model.fit(X_train, y_train)
print("Model training complete.")

# 3. Evaluate the model
print("Evaluating model performance on test set...")
y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
print(f"\nModel Accuracy: {accuracy * 100:.2f}%")

# Create string labels for the report
target_names = [attack_map.get(i, "Unknown") for i in range(len(attack_map))]
try:
    report = classification_report(y_test, y_pred, target_names=target_names, zero_division=0)
    print("\nClassification Report:")
    print(report)
except Exception:
    # Fallback if labels are mismatched
    report = classification_report(y_test, y_pred, zero_division=0)
    print("\nClassification Report (Numeric Labels):")
    print(report)


# 4. Save the trained model
print(f"Saving model to {MODEL_SAVE_PATH}...")
joblib.dump(model, MODEL_SAVE_PATH)
print("✅ Model saved successfully.")