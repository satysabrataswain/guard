# Cyber Guard Dataset Setup

Large binary datasets are intentionally not stored directly in GitHub. The project uses official/public sources and bounded local subsets.

Targets:
- Phishing URL: up to 20,000 rows
- Phishing Email: up to 20,000 rows
- Deepfake Image: up to 10,000 images
- Deepfake Video: up to 10,000 videos
- Voice synthetic detection: up to 10,000 audio files

Sources/access:
- PhishTank: official verified/online phishing URL feed.
- ASVspoof 2021: bona fide and spoofed speech, including speech deepfake data.
- FaceForensics++: manipulated video data; access requires accepting its terms and receiving the download script.
- Meta DFDC: large deepfake-video dataset; full access requires AWS account/IAM setup.

Downloaded archives and large media files should stay out of normal Git history. Put local data under datasets/ and use the bounded training scripts.