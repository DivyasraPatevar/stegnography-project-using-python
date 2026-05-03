# 🔒 AI-Powered Steganography Threat Detection System

## 📌 Overview
This project is an advanced cybersecurity tool that combines **Steganography**, **Artificial Intelligence**, and **Threat Detection** to identify hidden and malicious content inside images, videos, and audio files.

It not only extracts hidden messages but also analyzes them for:
- Fake links
- Malware APK references
- Third-party app distribution
- Deepfake media (image, video, audio)
- AI-generated/manipulated content

---

## 🚀 Features

### 🔐 Steganography
- Encode secret messages into images using LSB technique
- Decode hidden messages with password protection

### 🔗 Link & APK Detection
- Detects:
  - Fake / shortened links (bit.ly, tinyurl, etc.)
  - Suspicious domains (.tk, .xyz, etc.)
  - APK file references
  - Third-party app sources (mod APKs, cracked apps)

### 🧠 AI Threat Detection
- Deepfake image detection
- Deepfake video detection
- AI-generated audio detection
- AI manipulation detection

### ⚠️ Risk Analysis System
- Threat score calculation
- Risk classification:
  - Low Risk
  - Medium Risk
  - High Risk
- Spam and phishing keyword detection

### 🔍 Advanced Security Checks
- Hidden APK metadata detection
- QR code detection (optional)
- Malware keyword detection
- Behavioral phishing detection

---

## 🧰 Technologies Used

- Python
- Streamlit
- OpenCV
- NumPy
- Pillow
- Transformers (Hugging Face)
- PyTorch
- Librosa
- MoviePy

---

## 📂 Project Structure 
---

## ⚙️ Installation

```bash
git clone https://github.com/yourusername/your-repo-name.git
cd your-repo-name
pip install -r requirements.txt

**##To run**
streamlit run app.py


##**🧪 Use Cases**
Cybersecurity analysis
Digital forensics
Malware detection
Deepfake detection
Secure communication

##**🎯 Future Enhancements**
Real-time camera deepfake detection
Live microphone AI voice detection
Threat visualization dashboard
Cloud deployment


An advanced AI-based steganography and cybersecurity tool that extracts hidden data from media files and detects fake links, malicious APKs, third-party apps, and deepfake image, video, and audio content using multi-layer threat analysis.
