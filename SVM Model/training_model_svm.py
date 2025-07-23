import pandas as pd
import numpy as np
from sklearn.svm import OneClassSVM
import joblib
import os
from sklearn.preprocessing import StandardScaler

# Simulate benign traffic
np.random.seed(42)
packet_lengths = np.random.normal(loc=100, scale=20, size=500)
protocols = np.random.choice([1, 6, 17], size=500)  # ICMP, TCP, UDP

df = pd.DataFrame({
    "length": packet_lengths,
    "proto": protocols
})

# Normalize features
scaler = StandardScaler()
df_scaled = scaler.fit_transform(df)

# Train One-Class SVM
model = OneClassSVM(kernel='rbf', gamma='auto', nu=0.05)
model.fit(df_scaled)

# Save the model and scaler
os.makedirs("model", exist_ok=True)
joblib.dump(model, "model/model1.pkl")
joblib.dump(scaler, "model/scaler1.pkl")
print("✅ One-Class SVM model and scaler saved to model/model.pkl and model/scaler.pkl")
