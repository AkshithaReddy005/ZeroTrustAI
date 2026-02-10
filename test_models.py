import os
import sys

# Add detector path
sys.path.append('services/detector/app')

print('Current working directory:', os.getcwd())
print('Model dir env:', os.getenv('MODEL_DIR', "C:\\Users\\akshi\\OneDrive\\Documents\\AKKI\\projects\\ZeroTrust-AI\\models"))
print('Absolute model path:', os.path.abspath(os.getenv('MODEL_DIR', "C:\\Users\\akshi\\OneDrive\\Documents\\AKKI\\projects\\ZeroTrust-AI\\models")))

# Check if model files exist
model_dir = os.path.abspath(os.getenv('MODEL_DIR', "C:\\Users\\akshi\\OneDrive\\Documents\\AKKI\\projects\\ZeroTrust-AI\\models"))
print(f'Files in {model_dir}:')
for file in os.listdir(model_dir):
    print(f'  {file}')

# Check specific model files
model_files = [
    'scaler.joblib',
    'isoforest.joblib', 
    'pytorch_mlp.pt',
    'tcn_classifier.pth',
    'autoencoder.pth',
    'ae_threshold.txt'
]

for file in model_files:
    path = os.path.join(model_dir, file)
    exists = os.path.exists(path)
    print(f'{file}: {"EXISTS" if exists else "MISSING"}')
