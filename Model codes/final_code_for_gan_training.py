

!pip install scikit-learn tensorflow joblib


import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.layers import Dropout
import joblib
import os


from google.colab import files
uploaded = files.upload()

df = pd.read_csv("binary_labeled_data.csv")


features = ["Dst Port", "Flow Duration", "Protocol", "Pkt Len Mean"]
X = df[features]
y = df["Label"]

# Scale data
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)


os.makedirs("model", exist_ok=True)
joblib.dump(scaler, "model/scaler.pkl")


iso = IsolationForest(contamination=0.05, random_state=42)
iso.fit(X_scaled)
joblib.dump(iso, "model/model.pkl")


from tensorflow.keras.layers import LeakyReLU


X_benign = X_scaled[y == 1]


input_dim = X_benign.shape[1]
latent_dim = 16  # Size of noise vector

#  Generator model
def build_generator():
    noise = Input(shape=(latent_dim,))
    x = Dense(32, activation='relu')(noise)
    x = Dense(64, activation='relu')(x)
    output = Dense(input_dim, activation='linear')(x)
    return Model(noise, output, name="Generator")

#  Discriminator model
def build_discriminator():
    data = Input(shape=(input_dim,))
    x = Dense(64)(data)
    x = LeakyReLU(0.2)(x)
    x = Dropout(0.3)(x)
    x = Dense(32)(x)
    x = LeakyReLU(0.2)(x)
    x = Dropout(0.3)(x)
    out = Dense(1, activation='sigmoid')(x)
    model = Model(data, out, name="Discriminator")
    model.compile(optimizer=Adam(0.0002), loss='binary_crossentropy', metrics=['accuracy'])
    return model

generator = build_generator()
discriminator = build_discriminator()


discriminator.trainable = False

# GAN combined model
z = Input(shape=(latent_dim,))
fake = generator(z)
validity = discriminator(fake)

gan = Model(z, validity)
gan.compile(optimizer=Adam(0.0002), loss='binary_crossentropy')

# GAN training loop
epochs = 200
batch_size = 32

for epoch in range(epochs):
    # Train Discriminator
    idx = np.random.randint(0, X_benign.shape[0], batch_size)
    real_samples = X_benign[idx]
    noise = np.random.normal(0, 1, (batch_size, latent_dim))
    generated_samples = generator.predict(noise, verbose=0)


    real_labels = np.ones((batch_size, 1))

    fake_labels = np.zeros((batch_size, 1))

    d_loss_real = discriminator.train_on_batch(real_samples, real_labels)
    d_loss_fake = discriminator.train_on_batch(generated_samples, fake_labels)
    d_loss = 0.5 * np.add(d_loss_real, d_loss_fake)

    #  Train Generator
    noise = np.random.normal(0, 1, (batch_size, latent_dim))
    valid_labels = np.ones((batch_size, 1))  # Try to fool the discriminator
    g_loss = gan.train_on_batch(noise, valid_labels)


    if epoch % 20 == 0:
        print(f"Epoch {epoch} | D Loss: {d_loss[0]:.4f}, Acc: {d_loss[1]*100:.2f}% | G Loss: {g_loss:.4f}")


generator.save("model/gan_generator.h5")
discriminator.save("model/gan_discriminator.h5")


!zip -r model_files.zip model


files.download("model_files.zip")