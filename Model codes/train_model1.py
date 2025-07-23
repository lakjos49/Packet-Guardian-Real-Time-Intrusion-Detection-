import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os


np.random.seed(42)
MODEL_DIR = "model"
os.makedirs(MODEL_DIR, exist_ok=True)


packet_lengths = np.random.choice(
    [64, 128, 256, 512, 1024, 1500], 
    size=1000, 
    p=[0.2, 0.2, 0.15, 0.15, 0.15, 0.15]
) + np.random.normal(0, 10, 1000)

protocols = np.random.choice([1, 6, 17 , 2], size=1000, p=[0.05, 0.7, 0.15,0.1])


df = pd.DataFrame({
    "length": packet_lengths.astype(int),
    "proto": protocols
})

# Normalize 
scaler = StandardScaler()
X_scaled = scaler.fit_transform(df)


X_scaled_df = pd.DataFrame(X_scaled, columns=["length", "proto"])

# Train Isolation Forest model
model = IsolationForest(
    n_estimators=200,    
    contamination=0.02,   # 2%
    random_state=42
)
model.fit(X_scaled_df)


joblib.dump(model, f"{MODEL_DIR}/model.pkl")
joblib.dump(scaler, f"{MODEL_DIR}/scaler.pkl")

print("✅ Model and scaler saved successfully.")
