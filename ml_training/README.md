# Cyber Guard ML Training Pack

This directory contains reproducible dataset download and model-training entry points for Cyber Guard.

## Models

| Module | Dataset | Model |
|---|---|---|
| Voice deepfake | 500-sample MLAAD-tiny subset (250 real + 250 spoof) | MFCC/audio features + Random Forest baseline |
| Voice replay | ASVspoof 2021 PA | AASIST-style anti-spoofing pipeline |
| Image deepfake | FaceForensics++ | EfficientNet-B0 transfer learning |
| Video deepfake | Skipped for current Cyber Guard scope | — |
| Network anomaly | CIC-IDS2017 | XGBoost |
| Malware | EMBER 2018 | LightGBM |
| Phishing URL | PhishTank + benign URL corpus | LightGBM |
| Phishing email | SpamAssassin + phishing email corpus | TF-IDF + Logistic Regression baseline |
| Login/behavior anomaly | Cyber Guard application logs | Isolation Forest |

These are practical training choices for the current Cyber Guard codebase; they are not a claim that one architecture is universally state-of-the-art.

## Important

The datasets themselves are NOT committed to GitHub. Several are multi-GB, and FaceForensics++ requires acceptance of its terms. The download script creates the local dataset folders and downloads only sources that can be downloaded without an interactive access step.

After downloading, train with:

    python -m ml_training.train_all

Or train one module:

    python -m ml_training.train_tabular --network
    python -m ml_training.train_tabular --malware
    python -m ml_training.train_tabular --phishing-url

For current deepfake and voice training:

    python -m ml_training.train_media --image
    python ml_training/prepare_voice.py
    python -m ml_training.train_voice_small --max-samples 500

Video deepfake training is intentionally skipped in the current scope.

Outputs are stored under:

    trained_models/
    training_results/

Both folders are ignored by Git.
