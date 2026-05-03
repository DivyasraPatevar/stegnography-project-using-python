# -*- coding: utf-8 -*-
import streamlit as st
import streamlit.components.v1 as components
from pathlib import Path
from PIL import Image
import io
import os
import wave
import numpy as np
import re
from urllib.parse import urlparse 
import tempfile
import librosa
import moviepy.editor as mp

LINK_PATTERN = re.compile(r'https?://[^\s"\']+|www\.[^\s"\']+', re.IGNORECASE)
APK_PATTERN = re.compile(r'\b[\w\-/]+\.apk\b', re.IGNORECASE)
SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "tinyurl", "ow.ly", "t.co", "buff.ly",
    "adf.ly", "goo.gl", "cutt.ly", "rebrand.ly", "shorturl.at",
    "is.gd", "soo.gd", "shorte.st", "rb.gy", "clicky.me"
]
SUSPICIOUS_DOMAINS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz"]
SUSPICIOUS_LINK_PATTERN = re.compile(
    r'(@)|(?://[^/\s]*@)|(?:\b\d{1,3}(?:\.\d{1,3}){3}\b)|(?:xn--)|(?:%[0-9A-Fa-f]{2})',
    re.IGNORECASE
)

THIRD_PARTY_KEYWORDS = [
    "mod apk", "cracked apk", "premium unlocked", "third party app",
    "download from telegram", "download from whatsapp",
    "unknown source", "install from chrome", "outside playstore",
    "mirror download", "direct download", "paid app free", "no ads",
    "patched apk", "unofficial store", "apk mirror", "hacked apk"
]

THIRD_PARTY_APK_SOURCES = [
    "apkmod", "apkdone", "apkpure", "apk4fun", "revdl",
    "happymod", "moddroid", "rexdl", "apkcombo", "apkmonk"
]

FAKE_LINK_DOMAINS = [
    "bit.ly", "tinyurl.com", "tinyurl", "grabify", "iplogger",
    "shorturl.at", "cutt.ly", "rebrand.ly", "is.gd", "soo.gd",
    "t.me", "telegram.me", "wa.me", "t.co", "ow.ly", "adf.ly",
    "goo.gl"
]

try:
    import torch
    import cv2
    from transformers import pipeline
except ImportError:
    torch = None
    cv2 = None
    pipeline = None

st.set_page_config(
    page_title="Steganography Tool",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Utility functions
def string_to_binary(message):
    """Convert string to binary string"""
    binary = ''
    for char in message:
        binary += format(ord(char), '08b')
    return binary + '00000000'  # Null terminator

def binary_to_string(binary):
    """Convert binary string back to string"""
    chars = []
    for i in range(0, len(binary), 8):
        byte = binary[i:i+8]
        if byte == '00000000':  # Null terminator
            break
        chars.append(chr(int(byte, 2)))
    return ''.join(chars)


def detect_suspicious_filename(filename: str) -> list:
    suspicious_patterns = [
        r'\bfree\b', r'\bdownload\b', r'\bclick\b', r'\burgent\b',
        r'\bapk\b', r'\bhack\b', r'\bcrack\b', r'\bmod\b',
        r'\bpromo\b', r'\bvirus\b', r'\bmalware\b', r'\bspyware\b'
    ]
    return [pattern.strip('\\b') for pattern in suspicious_patterns if re.search(pattern, filename, re.IGNORECASE)]


def detect_media_spam_alerts(file_name: str, issues: list) -> list:
    alerts = []
    suspicious_keywords = [
        "free", "download", "click", "urgent", "hack", "crack", "mod",
        "promo", "virus", "malware", "scam", "phishing", "alert", "verify",
        "bank", "credit", "prize", "winner"
    ]
    if any(keyword in file_name.lower() for keyword in suspicious_keywords):
        alerts.append("File name uses spammy or scam-like keywords.")
    if any("deepfake" in issue.lower() or "fake" in issue.lower() or "synthetic" in issue.lower() or "ai generated" in issue.lower() for issue in issues):
        alerts.append("Media analysis detected deepfake, AI-generated, or synthetic content indicators.")
    if any("apk" in issue.lower() for issue in issues):
        alerts.append("Hidden APK metadata or APK references detected.")
    if any("shortened link" in issue.lower() or "suspicious link" in issue.lower() for issue in issues):
        alerts.append("Potential phishing/scam link patterns detected.")
    return alerts


def detect_scam_alert(file_name: str, issues: list, spam_alerts: list, risk: dict) -> tuple[bool, list]:
    reasons = []
    if any(keyword in file_name.lower() for keyword in ["scam", "fraud", "account", "password", "bank", "credit", "verify", "urgent", "winner", "prize", "claim", "alert"]):
        reasons.append("Filename resembles phishing or scam bait.")
    if any("link" in alert.lower() and "suspicious" in alert.lower() or "shortened" in alert.lower() or "phishing" in alert.lower() for alert in spam_alerts):
        reasons.append("Hidden or suspicious links were identified.")
    if any("fake" in issue.lower() or "deepfake" in issue.lower() or "ai" in issue.lower() or "synthetic" in issue.lower() for issue in issues):
        reasons.append("Media analysis found AI/deepfake or synthetic content indicators.")
    if risk.get("level") in ["High", "Critical"]:
        reasons.append("Overall media risk score is high.")
    return (len(reasons) > 0, reasons)


def prepare_uploaded_bytes(uploaded_file):
    try:
        uploaded_file.seek(0)
    except Exception:
        pass
    return uploaded_file.read()


def is_audio_file(filename: str) -> bool:
    return filename.lower().endswith(('.wav', '.mp3', '.ogg', '.flac', '.m4a'))


def is_video_file(filename: str) -> bool:
    return filename.lower().endswith(('.mp4', '.mov', '.avi', '.mkv', '.webm'))


def convert_to_wav_bytes(uploaded_file):
    data = prepare_uploaded_bytes(uploaded_file)
    suffix = Path(getattr(uploaded_file, 'name', 'file')).suffix.lower()
    if suffix == '.wav':
        return data

    temp_in = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    temp_out = None
    try:
        temp_in.write(data)
        temp_in.close()
        audio_clip = mp.AudioFileClip(temp_in.name)
        temp_out = tempfile.NamedTemporaryFile(delete=False, suffix='.wav')
        temp_out.close()
        audio_clip.write_audiofile(temp_out.name, logger=None)
        audio_clip.close()
        with open(temp_out.name, 'rb') as f:
            wav_data = f.read()
        return wav_data
    finally:
        try:
            temp_in.close()
            os.remove(temp_in.name)
        except Exception:
            pass
        if temp_out is not None:
            try:
                os.remove(temp_out.name)
            except Exception:
                pass


def encode_audio(uploaded_file, message, password):
    wav_bytes = convert_to_wav_bytes(uploaded_file)
    full_message = f"{password}::{message}"
    binary_message = string_to_binary(full_message)

    with wave.open(io.BytesIO(wav_bytes), 'rb') as reader:
        params = reader.getparams()
        frames = reader.readframes(params.nframes)

    dtype_map = {1: np.uint8, 2: np.int16, 4: np.int32}
    if params.sampwidth not in dtype_map:
        raise ValueError("Unsupported audio sample width for steganography. Use WAV audio with 8/16/32-bit samples.")

    samples = np.frombuffer(frames, dtype=dtype_map[params.sampwidth])
    if len(binary_message) > len(samples):
        raise ValueError("Message is too long for this audio file")

    flat_samples = samples.copy()
    for i, bit in enumerate(binary_message):
        flat_samples[i] = (flat_samples[i] & ~1) | int(bit)

    output = io.BytesIO()
    with wave.open(output, 'wb') as writer:
        writer.setparams(params)
        writer.writeframes(flat_samples.tobytes())
    output.seek(0)
    return output.read()


def encode_video(uploaded_file, message, password):
    data = prepare_uploaded_bytes(uploaded_file)
    suffix = Path(getattr(uploaded_file, 'name', 'video')).suffix.lower()
    temp_in = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    temp_out = tempfile.NamedTemporaryFile(delete=False, suffix='.mp4')
    try:
        temp_in.write(data)
        temp_in.close()
        clip = mp.VideoFileClip(temp_in.name)
        encoded_frame = None
        try:
            frame = clip.get_frame(0)
            frame_img = Image.fromarray(np.clip(frame, 0, 255).astype('uint8'))
            encoded_frame = encode_message(frame_img, message, password)
            encoded_frame_arr = np.array(encoded_frame)
            frames = [encoded_frame_arr]
            for i, frame in enumerate(clip.iter_frames()):
                if i == 0:
                    continue
                frames.append(frame)
            new_clip = mp.ImageSequenceClip(frames, fps=clip.fps)
            if clip.audio is not None:
                new_clip = new_clip.set_audio(clip.audio)
            new_clip.write_videofile(temp_out.name, codec='libx264', audio_codec='aac', fps=clip.fps, logger=None)
        finally:
            clip.close()
        with open(temp_out.name, 'rb') as f:
            return f.read()
    finally:
        try:
            temp_in.close()
            os.remove(temp_in.name)
        except Exception:
            pass
        try:
            temp_out.close()
            os.remove(temp_out.name)
        except Exception:
            pass


def decode_video(uploaded_file, password):
    data = prepare_uploaded_bytes(uploaded_file)
    suffix = Path(getattr(uploaded_file, 'name', 'video')).suffix.lower()
    temp_in = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    try:
        temp_in.write(data)
        temp_in.close()
        clip = mp.VideoFileClip(temp_in.name)
        try:
            for t in [0, 1 / max(1, clip.fps), 2 / max(1, clip.fps)]:
                if t >= clip.duration:
                    break
                frame = clip.get_frame(t)
                decoded_message = decode_message(Image.fromarray(np.clip(frame, 0, 255).astype('uint8')), password)
                if decoded_message:
                    return decoded_message
        finally:
            clip.close()
    finally:
        try:
            temp_in.close()
            os.remove(temp_in.name)
        except Exception:
            pass
    return None


def decode_audio(uploaded_file, password):
    wav_bytes = convert_to_wav_bytes(uploaded_file)
    with wave.open(io.BytesIO(wav_bytes), 'rb') as reader:
        params = reader.getparams()
        frames = reader.readframes(params.nframes)

    dtype_map = {1: np.uint8, 2: np.int16, 4: np.int32}
    if params.sampwidth not in dtype_map:
        return None

    samples = np.frombuffer(frames, dtype=dtype_map[params.sampwidth])
    binary_message = ''.join(str(sample & 1) for sample in samples)
    decoded = binary_to_string(binary_message)
    if "::" in decoded:
        stored_password, hidden_message = decoded.split("::", 1)
        if stored_password == password:
            return hidden_message
    return None


def render_threat_summary(media_type: str, file_name: str, filename_issues: list, hidden_apk_flag: bool, risk: dict, spam_alerts: list, scam_alert: bool = False, scam_reasons: list = None, show_level: bool = True):
    st.markdown("---")
    st.markdown("### 🛡️ Threat Summary")
    st.markdown(f"**Media type:** {media_type.capitalize()}")
    st.markdown(f"**File name:** {file_name}")
    if filename_issues:
        st.markdown("**Suspicious filename hints:** " + ", ".join(filename_issues))
    if spam_alerts:
        st.markdown("**Spam / alert indicators:** " + ", ".join(spam_alerts))
    if hidden_apk_flag:
        st.markdown("**Hidden APK metadata detected:** Yes")
    if scam_alert:
        st.error("🚨 Scam Alert: This media may be part of a scam or fraudulent AI attack.")
        if scam_reasons:
            st.markdown("**Scam alert reasons:**")
            for reason in scam_reasons:
                st.write(f"- {reason}")
    if show_level:
        st.markdown(f"**Overall risk:** {risk['level']} (score {risk['score']})")
        if risk['level'] in ['High', 'Critical']:
            st.markdown("**Action:** Do not trust or share this file. Verify the source before opening.")
        elif risk['level'] == 'Medium':
            st.markdown("**Action:** Treat this as suspicious and validate before use.")
        else:
            st.markdown("**Action:** Lower risk, but still remain cautious.")
    else:
        st.markdown(f"**Risk score:** {risk['score']}")
        if risk['issues'] or spam_alerts or hidden_apk_flag or scam_alert:
            st.markdown("**Action:** Treat this as suspicious and validate before use.")
        else:
            st.markdown("**Action:** Lower risk, but still remain cautious.")


def generate_threat_report(media_type: str, label: str, score: float, issues: list, file_name: str, filename_issues: list, hidden_apk_flag: bool, spam_alerts: list, scam_alert: bool = False, scam_reasons: list = None) -> str:
    report_lines = [
        f"Threat Report for {media_type.capitalize()} file: {file_name}",
        f"Detection label: {label}",
        f"Detection score: {score:.2f}",
        f"Hidden APK metadata: {'Yes' if hidden_apk_flag else 'No'}",
        f"Suspicious filename hints: {', '.join(filename_issues) if filename_issues else 'None'}",
        f"Spam/alert warnings: {', '.join(spam_alerts) if spam_alerts else 'None'}",
        f"Scam alert: {'Yes' if scam_alert else 'No'}",
    ]
    if scam_reasons:
        report_lines.append("Scam alert reasons:")
        report_lines.extend([f"- {reason}" for reason in scam_reasons])
    report_lines.append("Analysis notes:")
    report_lines.extend([f"- {issue}" for issue in issues])
    return "\n".join(report_lines)


def compute_media_risk_summary(media_type: str, deepfake_flag: bool, deepfake_score: float, ai_manipulation_flag: bool, hidden_apk: bool, filename_issues: list) -> dict:
    score = 0
    issues = []
    if deepfake_flag:
        score += 4
        issues.append("Deepfake model flagged the media")
    if deepfake_score >= 0.5:
        score += 2
        issues.append(f"Model confidence is high ({deepfake_score:.2f})")
    if ai_manipulation_flag:
        score += 3
        issues.append("AI manipulation signature detected in pixel/noise analysis")
    if hidden_apk:
        score += 2
        issues.append("Suspicious hidden APK-related metadata found")
    if filename_issues:
        score += len(filename_issues)
        issues.append("Suspicious filename hints: " + ", ".join(filename_issues))

    if media_type == "audio" and deepfake_flag is False and ai_manipulation_flag:
        score += 1
        issues.append("Audio waveform looks unusually synthetic")

    if score >= 8:
        level = "Critical"
    elif score >= 5:
        level = "High"
    elif score >= 3:
        level = "Medium"
    else:
        level = "Low"

    return {"score": score, "level": level, "issues": issues}


def format_risk_label(risk: dict) -> str:
    return f"{risk['level']} Risk (score {risk['score']})"


def display_media_risk(risk: dict, show_level: bool = True):
    if show_level:
        if risk["level"] in ["Critical", "High"]:
            st.error(f"⚠️ {format_risk_label(risk)}")
        elif risk["level"] == "Medium":
            st.warning(f"⚠️ {format_risk_label(risk)}")
        else:
            st.success(f"✅ {format_risk_label(risk)}")
    else:
        if risk["issues"]:
            st.warning("⚠️ Potential media risk indicators were found.")
        else:
            st.success("✅ No significant media risk indicators were detected.")
    if risk["issues"]:
        st.markdown("**Risk indicators:**")
        for issue in risk["issues"]:
            st.write(f"- {issue}")


def detect_deepfake_audio(audio_file):
    try:
        temp_audio = tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(getattr(audio_file, 'name', 'audio.wav'))[1])
        temp_audio.write(audio_file.read())
        temp_audio.close()

        y, sr = librosa.load(temp_audio.name, sr=None)
        try:
            spectral_centroid = np.mean(librosa.feature.spectral_centroid(y=y, sr=sr))
            zero_crossing = np.mean(librosa.feature.zero_crossing_rate(y))
            spectral_bandwidth = np.mean(librosa.feature.spectral_bandwidth(y=y, sr=sr))
            rms = np.mean(librosa.feature.rms(y=y))
        finally:
            try:
                os.remove(temp_audio.name)
            except Exception:
                pass

        issues = []
        score = 0
        if spectral_centroid > 4000:
            score += 2
            issues.append(f"High spectral centroid ({spectral_centroid:.1f}) suggests synthetic tonal quality")
        if zero_crossing < 0.01:
            score += 2
            issues.append(f"Low zero-crossing rate ({zero_crossing:.4f}) suggests smoother synthetic voice")
        if spectral_bandwidth < 1000:
            score += 1
            issues.append(f"Narrow bandwidth ({spectral_bandwidth:.1f}) may indicate generated audio")
        if rms < 0.01:
            score += 1
            issues.append(f"Very low energy ({rms:.4f}) in audio signal")

        duplicate_flag, duplicate_issues = detect_duplicate_audio(y, sr)
        if duplicate_flag:
            score += 2
            issues.extend(duplicate_issues)

        is_fake = score >= 3
        if duplicate_flag and not is_fake:
            label = "Possible duplicated / AI-generated audio"
        else:
            label = "Possible AI generated voice" if is_fake else "Audio looks real"
        return is_fake, label, score, issues

    except Exception:
        return False, "Audio detection error", 0.0, ["Could not analyze audio sample"]


def detect_deepfake_video(video_file):

    if cv2 is None or pipeline is None:
        return False, "Video model unavailable", 0.0, ["Required computer vision/transformers libraries are missing"]

    try:
        model = load_deepfake_model()
        temp_video = tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(getattr(video_file, 'name', 'video.mp4'))[1])
        temp_video.write(video_file.read())
        temp_video.close()

        cap = cv2.VideoCapture(temp_video.name)
        frame_count = 0
        fake_score = 0
        suspicious_frame_count = 0
        issues = []

        while cap.isOpened():
            ret, frame = cap.read()
            if not ret:
                break

            if frame_count % 30 == 0:  # check every 30 frames
                frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                pil_img = Image.fromarray(frame_rgb)
                result = model(pil_img)

                for res in result:
                    label = str(res['label']).lower()
                    score = float(res['score'])
                    if "fake" in label or "deepfake" in label or "ai" in label:
                        fake_score += score
                        issues.append(f"Frame {frame_count} flagged: {label} ({score:.2f})")

                low_noise, noise_value = detect_ai_video_signature(frame)
                if low_noise:
                    suspicious_frame_count += 1
                    if suspicious_frame_count <= 3:
                        issues.append(f"Frame {frame_count} low visual noise ({noise_value:.1f}) suggests synthetic generation")

            frame_count += 1

        cap.release()
        try:
            os.remove(temp_video.name)
        except Exception:
            pass

        if suspicious_frame_count >= 2:
            fake_score += 1.5
            issues.append("Multiple sampled frames have unnaturally low edge variance, indicating possible AI-generated video.")

        if fake_score > 1:
            return True, "Deepfake video detected", fake_score, issues or ["Video model flagged potential deepfake frames"]

        return False, "Video looks real", fake_score, issues

    except Exception:
        try:
            os.remove(temp_video.name)
        except Exception:
            pass
        return False, "Video detection error", 0.0, ["Failed to analyze video file"]
def encode_message(image, message, password):
    """Encode message with password into image using LSB steganography"""
    if image.mode != 'RGB':
        image = image.convert('RGB')

    full_message = f"{password}::{message}"
    pixels = np.array(image)
    binary_message = string_to_binary(full_message)

    if len(binary_message) > pixels.size:
        raise ValueError("Message is too long for this image")

    flat_pixels = pixels.flatten()
    for i, bit in enumerate(binary_message):
        flat_pixels[i] = (flat_pixels[i] & 0xFE) | int(bit)

    new_pixels = flat_pixels.reshape(pixels.shape)
    encoded_image = Image.fromarray(new_pixels.astype('uint8'), 'RGB')
    return encoded_image

def decode_message(image, password):
    """Decode message from image, check password"""
    if image.mode != 'RGB':
        image = image.convert('RGB')

    pixels = np.array(image)
    flat_pixels = pixels.flatten()

    binary_message = ''
    for pixel in flat_pixels:
        binary_message += str(pixel & 1)

    decoded = binary_to_string(binary_message)
    if "::" in decoded:
        stored_password, hidden_message = decoded.split("::", 1)
        if stored_password == password:
            return hidden_message
    return None


def contains_link(message: str) -> bool:
    return bool(LINK_PATTERN.search(message))


def contains_apk_reference(message: str) -> bool:
    return bool(APK_PATTERN.search(message) or re.search(
        r'\b(?:apk file|apk download|download apk|android package|install apk)\b',
        message, re.IGNORECASE
    ))


def extract_risky_matches(message: str) -> dict:
    return {
        "links": LINK_PATTERN.findall(message),
        "apks": APK_PATTERN.findall(message)
               + re.findall(r'\b(?:apk file|apk download|download apk|android package|install apk)\b',
                            message, re.IGNORECASE)
    }


def is_spam(message: str) -> bool:
    """Check if hidden message contains risky links or suspicious keywords"""
    patterns = [
        r'https?://[^\s]+',
        r'www\.[^\s]+',
        r'\bphishing\b',
        r'\bmalware\b',
        r'\bclickme\b',
        r'\bfree[-\s]?money\b',
        r'\bhack\b',
        r'\battack\b',
        r'\bdeep[\s-]?fake\b',
        r'\bai[\s-]?(generated|manipulated)\b',
        r'\b(?:android\s+package|apk\s+file|apk\s+download|install\s+apk)\b',
        r'\b[\w\-]+\.apk\b',
        r'\bdownload\s+apk\b',
        r'\bclick here\b',
        r'\bfree download\b',
        r'\binstall now\b',
        r'\burgent\b',
        r'\bdownload now\b'
    ]
    for pattern in patterns:
        if re.search(pattern, message, re.IGNORECASE):
            return True
    return False


def detect_fake_links(message: str) -> list:
    found = []
    for link in LINK_PATTERN.findall(message):
        normalized = link if link.startswith(("http://", "https://")) else f"https://{link}"
        try:
            parts = urlparse(normalized)
            domain = parts.netloc.lower().strip()
            if domain.startswith("www."):
                domain = domain[4:]
            if any(short_domain in domain for short_domain in SHORTENER_DOMAINS):
                found.append(f"{link} (shortened link)")
            if SUSPICIOUS_LINK_PATTERN.search(link):
                found.append(f"{link} (suspicious link structure)")
            if any(susp in domain for susp in SUSPICIOUS_DOMAINS):
                found.append(f"{link} (suspicious domain)")
        except Exception:
            continue
    if not found:
        for domain in FAKE_LINK_DOMAINS:
            if domain in message.lower():
                found.append(f"{domain} (known shortener)")
    return list(dict.fromkeys(found))


# Third Party App Detection
def detect_third_party_apps(message: str) -> list:
    detected = [keyword for keyword in THIRD_PARTY_KEYWORDS if keyword in message.lower()]
    return list(dict.fromkeys(detected))


def detect_third_party_apk(message: str) -> list:
    detected = [source for source in THIRD_PARTY_APK_SOURCES if source in message.lower()]
    extra = [keyword for keyword in THIRD_PARTY_KEYWORDS if keyword in message.lower() and keyword not in detected]
    return list(dict.fromkeys(detected + extra))


def detect_suspicious_domains(message: str) -> list:
    detected = [domain for domain in SUSPICIOUS_DOMAINS if domain in message.lower()]
    return list(dict.fromkeys(detected))


def detect_payload_type(message: str) -> str:
    has_link = contains_link(message)
    has_apk = contains_apk_reference(message)
    if has_link and has_apk:
        return "Mixed (URL + APK)"
    if has_apk:
        return "APK reference"
    if has_link:
        return "URL"
    return "Text / other"


def evaluate_message_risk(message: str) -> dict:
    detected = []
    score = 0
    links = LINK_PATTERN.findall(message)
    apks = APK_PATTERN.findall(message)
    fake_links = detect_fake_links(message)
    third_party = detect_third_party_apps(message)
    third_party_apk = detect_third_party_apk(message)
    suspicious_domains = detect_suspicious_domains(message)
    spam = is_spam(message)

    if links:
        score += 2
        detected.append(f"Link count: {len(links)}")
    if apks:
        score += 2
        detected.append(f"APK reference count: {len(apks)}")
    if fake_links:
        score += 3
        detected.append("Fake/shortened links detected")
    if third_party:
        score += 2
        detected.append("Third-party app distribution detected")
    if third_party_apk:
        score += 2
        detected.append("Third-party APK source detected")
    if suspicious_domains:
        score += 2
        detected.append("Suspicious domain patterns detected")
    if spam:
        score += 3
        detected.append("Spam or phishing wording detected")

    if score >= 8:
        level = "High"
    elif score >= 4:
        level = "Medium"
    else:
        level = "Low"

    return {
        "score": score,
        "level": level,
        "issues": detected,
        "links": links,
        "apks": apks,
        "fake_links": fake_links,
        "third_party_apps": third_party,
        "third_party_apks": third_party_apk,
        "suspicious_domains": suspicious_domains,
        "spam": spam
    }


def render_decoded_output(decoded_message: str):
    if contains_link(decoded_message) or contains_apk_reference(decoded_message):
        st.error("⚠️ Spam Alert: risky hidden content detected. The decoded payload is blocked for safety.")
        return

    payload_type = detect_payload_type(decoded_message)
    risk = evaluate_message_risk(decoded_message)

    if payload_type == "URL":
        st.markdown("**Payload type:** 🔗 URL")
    elif payload_type == "APK reference":
        st.markdown("**Payload type:** 📦 APK reference")
    elif payload_type == "Mixed (URL + APK)":
        st.markdown("**Payload type:** 🔗📦 Mixed URL + APK reference")
    else:
        st.markdown("**Payload type:** 📝 Text / other")

    if risk["issues"]:
        st.warning("⚠️ Suspicious indicators were detected in decoded content.")
    else:
        st.success("Decoded message appears clean.")

    if risk["issues"]:
        st.markdown("**Detected issues:**")
        for issue in risk["issues"]:
            st.write(f"- {issue}")

    if risk["spam"]:
        st.error("🚨 Spam wording detected in decoded content.")

    st.markdown('<div class="result-box">', unsafe_allow_html=True)
    st.markdown(f"**Hidden Message:** {decoded_message}")
    st.markdown('</div>', unsafe_allow_html=True)

# Deepfake Detection Model
@st.cache_resource
def load_deepfake_model():
    if pipeline is None:
        return None

    try:
        model = pipeline(
            "image-classification",
            model="prithivMLmods/Deepfake-Detection"
        )
        return model
    except Exception:
        return None


def detect_deepfake_image(image):
    if pipeline is None:
        return False, "Model unavailable", 0.0, ["Required model libraries are unavailable"]

    try:
        model = load_deepfake_model()
        if model is None:
            return False, "Model not loaded", 0.0, ["Deepfake model failed to initialize"]

        image = image.convert("RGB")
        result = model(image)
        issues = []
        hidden_apk = detect_hidden_apk(image)
        ai_manipulation_flag = detect_ai_manipulation(image)

        if hidden_apk:
            issues.append("Hidden APK metadata detected in image")
        if ai_manipulation_flag:
            issues.append("Low noise / possible AI manipulation signature detected")

        if not isinstance(result, list) or len(result) == 0:
            return False, "No result", 0.0, issues or ["Model returned no result"]

        has_fake = False
        fake_score = 0.0
        label = str(result[0].get('label', 'real')).lower()
        score = float(result[0].get('score', 0.0))
        if "fake" in label or "deepfake" in label or "ai" in label:
            has_fake = True
            fake_score = score
            issues.append(f"Model label indicates fake content: {label}")
        if has_fake:
            return True, label, fake_score, issues

        return False, label, score, issues
    except Exception:
        return False, "Detection Error", 0.0, ["Image detection error"]
    
def detect_hidden_apk(image):
    try:
        metadata = str(image.info)
        apk_patterns = [
            ".apk",
            "android package",
            "apk file",
            "install apk",
            "download apk"
        ]
        lower_meta = metadata.lower()
        for pattern in apk_patterns:
            if pattern in lower_meta:
                return True
    except Exception:
        pass
    return False

def detect_ai_manipulation(image):
    if cv2 is None:
        return False

    try:
        img = np.array(image.convert("RGB"))
        noise = cv2.Laplacian(img, cv2.CV_64F).var()
        return noise < 5
    except Exception:
        return False


def detect_duplicate_audio(y: np.ndarray, sr: int) -> tuple[bool, list]:
    if len(y) < sr * 2:
        return False, []

    segment_length = int(sr)
    hop = max(int(segment_length // 2), 1)
    segments = [y[i:i + segment_length] for i in range(0, len(y) - segment_length + 1, hop)]
    if len(segments) < 2:
        return False, []

    mfccs = []
    for segment in segments[:10]:
        try:
            mfcc = np.mean(librosa.feature.mfcc(y=segment, sr=sr, n_mfcc=13), axis=1)
            mfccs.append(mfcc)
        except Exception:
            continue

    if len(mfccs) < 2:
        return False, []

    mfccs = np.vstack(mfccs)
    norms = np.linalg.norm(mfccs, axis=1, keepdims=True) + 1e-9
    similarity = np.dot(mfccs, mfccs.T) / (norms * norms.T)
    duplicate_pairs = np.sum(similarity > 0.96) - len(mfccs)

    if duplicate_pairs >= 2:
        return True, ["Duplicate audio segments detected; content may be reused, looped, or generated."]
    return False, []


def detect_ai_video_signature(frame):
    try:
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        noise = cv2.Laplacian(gray, cv2.CV_64F).var()
        return noise < 30, noise
    except Exception:
        return False, 0.0


def landing_page():
    html_path = Path(__file__).resolve().parent / "webpage.html"
    if not html_path.exists():
        st.error("webpage.html not found. Make sure this file exists in the same folder as dddd.py.")
        return

    html_code = html_path.read_text(encoding="utf-8")
    components.html(html_code, height=1200, scrolling=True)

# Main App
def main():
    st.markdown('<h1 class="main-header">🔒 Steganography Tool</h1>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">Hide and reveal secret messages in images</p>', unsafe_allow_html=True)

    # Sidebar
    st.sidebar.title("📋 Navigation")
    page = st.sidebar.radio("Choose a function:", ["Landing Page", "Analyze Text / Link", "Deepfake Detection", "Encode Message", "Encode Link/APK", "Decode Message", "Decode Link/APK"])

    st.sidebar.markdown("---")
    st.sidebar.markdown("### How it works")
    st.sidebar.markdown("""
    This app uses Least Significant Bit (LSB) steganography to hide text messages within image files.
    The changes are invisible to the human eye but can be extracted later.
    """)

    if page == "Landing Page":
        landing_page()

    elif page == "Analyze Text / Link":
        st.header("🔎 Analyze Text, Link or APK Reference")
        message = st.text_area("Enter text, a URL, or APK reference to scan:", height=180)
        if st.button("Analyze message", key="analyze"):
            if not message.strip():
                st.error("Please enter some text to analyze.")
            else:
                risk = evaluate_message_risk(message.strip())
                st.markdown(f"**Risk level:** {risk['level']} (score {risk['score']})")
                if risk["issues"]:
                    st.markdown("**Issues detected:**")
                    for issue in risk["issues"]:
                        st.write(f"- {issue}")
                if risk["links"]:
                    st.markdown("**Links found:** " + ", ".join(risk["links"]))
                if risk["fake_links"]:
                    st.markdown("**Fake/shortened links:** " + ", ".join(risk["fake_links"]))
                if risk["apks"]:
                    st.markdown("**APK references:** " + ", ".join(risk["apks"]))
                if risk["third_party_apps"]:
                    st.warning("Third-party app indicators: " + ", ".join(risk["third_party_apps"]))
                if risk["third_party_apks"]:
                    st.warning("Third-party APK sources: " + ", ".join(risk["third_party_apks"]))
                if risk["suspicious_domains"]:
                    st.error("Suspicious domains: " + ", ".join(risk["suspicious_domains"]))
                if risk["spam"]:
                    st.error("Spam or phishing wording detected.")
                st.markdown("---")
                st.markdown("**Original message:**")
                st.code(message.strip())

    elif page == "Deepfake Detection":
        st.header("🤖 Deepfake / AI Manipulation Detection")
        st.markdown("Upload an image, video, or audio file to scan for deepfake traits and AI-generated behavior.")

        file = st.file_uploader(
            "Upload Image / Video / Audio",
            type=["png", "jpg", "jpeg", "mp4", "mov", "avi", "wav", "mp3"]
        )

        if file:
            file_name = getattr(file, 'name', 'uploaded_file')
            filename_issues = detect_suspicious_filename(file_name)
            file_type = file.type

            uploaded_bytes = prepare_uploaded_bytes(file)
            uploaded_bytes = prepare_uploaded_bytes(file)
            report_target_image = None
            spam_alerts = []
            report_text = ""

            if "image" in file_type:
                image = Image.open(io.BytesIO(uploaded_bytes))
                st.image(image, caption="Uploaded Image")
                fake, label, score, issues = detect_deepfake_image(image)
                hidden_apk_flag = detect_hidden_apk(image)
                manipulation_flag = detect_ai_manipulation(image) or any("ai" in issue.lower() or "synthetic" in issue.lower() for issue in issues)
                spam_alerts = detect_media_spam_alerts(file_name, issues)
                scam_alert, scam_reasons = detect_scam_alert(file_name, issues, spam_alerts, compute_media_risk_summary(
                    "image", fake, score, manipulation_flag, hidden_apk_flag, filename_issues
                ))
                if spam_alerts or filename_issues or hidden_apk_flag or scam_alert:
                    st.warning("⚠️ Potential risk indicators found for this image. Open it carefully and verify the source.")
                if scam_alert:
                    st.error("🚨 Scam Alert detected for this image.")
                if fake:
                    st.error(f"⚠️ Deepfake Detected ({label})")
                else:
                    st.success("Image looks Real")
                    if manipulation_flag:
                        st.warning("⚠️ AI manipulation signature found in the image noise profile.")
                media_risk = compute_media_risk_summary(
                    "image", fake, score, manipulation_flag, hidden_apk_flag, filename_issues
                )
                display_media_risk(media_risk, show_level=False)
                render_threat_summary("image", file_name, filename_issues, hidden_apk_flag, media_risk, spam_alerts, scam_alert, scam_reasons, show_level=False)
                if issues:
                    st.markdown("**Deepfake / image analysis notes:**")
                    for note in issues:
                        st.write(f"- {note}")
                report_target_image = image
                report_text = generate_threat_report("image", label, score, issues, file_name, filename_issues, hidden_apk_flag, spam_alerts, scam_alert, scam_reasons)

            elif "video" in file_type:
                st.video(uploaded_bytes)
                with st.spinner("Analyzing Video..."):
                    fake, label, score, issues = detect_deepfake_video(io.BytesIO(uploaded_bytes))
                spam_alerts = detect_media_spam_alerts(file_name, issues)
                video_ai_flag = fake or any("low visual noise" in issue.lower() or "synthetic" in issue.lower() or "ai" in issue.lower() for issue in issues)
                scam_alert, scam_reasons = detect_scam_alert(file_name, issues, spam_alerts, compute_media_risk_summary(
                    "video", fake, score, video_ai_flag, False, filename_issues
                ))
                if spam_alerts or filename_issues or scam_alert:
                    st.warning("⚠️ Potential risk indicators found for this video. Open it carefully and verify the source.")
                if scam_alert:
                    st.error("🚨 Scam Alert detected for this video.")
                if fake:
                    st.error(f"⚠️ Deepfake Video Detected ({label})")
                else:
                    st.success("Video looks Real")
                filename_risk = compute_media_risk_summary(
                    "video", fake, score, video_ai_flag, False, filename_issues
                )
                display_media_risk(filename_risk, show_level=False)
                render_threat_summary("video", file_name, filename_issues, False, filename_risk, spam_alerts, scam_alert, scam_reasons, show_level=False)
                if issues:
                    st.markdown("**Video analysis notes:**")
                    for note in issues:
                        st.write(f"- {note}")
                report_text = generate_threat_report("video", label, score, issues, file_name, filename_issues, False, spam_alerts, scam_alert, scam_reasons)

            elif "audio" in file_type:
                st.audio(uploaded_bytes)
                with st.spinner("Analyzing Audio..."):
                    fake, label, score, issues = detect_deepfake_audio(io.BytesIO(uploaded_bytes))
                spam_alerts = detect_media_spam_alerts(file_name, issues)
                audio_ai_flag = fake or any("duplicate audio" in issue.lower() or "generated" in issue.lower() or "synthetic" in issue.lower() for issue in issues)
                scam_alert, scam_reasons = detect_scam_alert(file_name, issues, spam_alerts, compute_media_risk_summary(
                    "audio", fake, score, audio_ai_flag, False, filename_issues
                ))
                if spam_alerts or filename_issues or scam_alert:
                    st.warning("⚠️ Potential risk indicators found for this audio file. Open it carefully and verify the source.")
                if scam_alert:
                    st.error("🚨 Scam Alert detected for this audio file.")
                if fake:
                    st.error(f"⚠️ AI Generated Voice Detected ({label})")
                else:
                    st.success("Audio looks Real")
                audio_risk = compute_media_risk_summary(
                    "audio", fake, score, audio_ai_flag, False, filename_issues
                )
                display_media_risk(audio_risk, show_level=False)
                render_threat_summary("audio", file_name, filename_issues, False, audio_risk, spam_alerts, scam_alert, scam_reasons, show_level=False)
                if issues:
                    st.markdown("**Audio analysis notes:**")
                    for note in issues:
                        st.write(f"- {note}")
                report_text = generate_threat_report("audio", label, score, issues, file_name, filename_issues, False, spam_alerts, scam_alert, scam_reasons)

            else:
                st.info("Unsupported file type for deepfake detection.")

            if report_text:
                st.markdown("---")
                st.markdown("### 📄 Generated Threat Report")
                st.code(report_text)

                st.markdown("### 🔐 Encode Threat Report into Image")
                if report_target_image is not None:
                    st.info("Using the analyzed image as cover image for report encoding.")
                    cover_image = report_target_image
                else:
                    cover_image = st.file_uploader(
                        "Upload a cover image to embed the threat report into:",
                        type=['png', 'jpg', 'jpeg', 'bmp'],
                        key='cover_image'
                    )
                password = st.text_input("Set a password for report encoding:", type="password", key="report_password")
                if st.button("Encode Threat Report", key="encode_report"):
                    if cover_image is None:
                        st.error("Please upload a cover image to embed the report.")
                    elif not password.strip():
                        st.error("Please enter a password for encoding.")
                    else:
                        try:
                            cover_img = cover_image if isinstance(cover_image, Image.Image) else Image.open(cover_image)
                            encoded_image = encode_message(cover_img, report_text, password.strip())
                            buf = io.BytesIO()
                            encoded_image.save(buf, format='PNG')
                            buf.seek(0)
                            st.success("Threat report encoded into image successfully!")
                            st.download_button(
                                label="📥 Download Threat Report Image",
                                data=buf,
                                file_name="threat_report_image.png",
                                mime="image/png"
                            )
                        except Exception as e:
                            st.error(f"Encoding error: {str(e)}")

                st.markdown("### 🕵️‍♂️ Decode Threat Report from Image")
                decode_image = st.file_uploader(
                    "Upload a stego image containing a threat report:",
                    type=['png', 'jpg', 'jpeg', 'bmp'],
                    key='decode_report'
                )
                decode_password = st.text_input("Enter password to decode report:", type="password", key="decode_password")
                if st.button("Decode Threat Report", key="decode_report_btn"):
                    if decode_image is None:
                        st.error("Please upload a stego image to decode.")
                    elif not decode_password.strip():
                        st.error("Please enter the decode password.")
                    else:
                        try:
                            result = decode_message(Image.open(decode_image), decode_password.strip())
                            if result:
                                st.success("Threat report decoded successfully!")
                                st.code(result)
                            else:
                                st.error("Wrong password or no hidden report found.")
                        except Exception as e:
                            st.error(f"Decoding error: {str(e)}")

    elif page == "Encode Message":
        st.header("📝 Encode Message")

        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Input")
            uploaded_file = st.file_uploader(
                "Choose a cover image, audio, or video file", 
                type=['png', 'jpg', 'jpeg', 'bmp', 'wav', 'mp3', 'ogg', 'flac', 'm4a', 'mp4', 'mov', 'avi', 'mkv', 'webm']
            )
            message = st.text_area("Enter your secret message:", height=100)
            password = st.text_input("Set a password:", type="password")

            st.markdown("Enter any secret text to hide within the image or audio file. The decoder will classify the hidden payload later.")
            if uploaded_file is not None:
                file_name = getattr(uploaded_file, 'name', '')
                if is_audio_file(file_name):
                    uploaded_file.seek(0)
                    st.audio(uploaded_file.read())
                elif is_video_file(file_name):
                    uploaded_file.seek(0)
                    st.video(uploaded_file.read())
                else:
                    image = Image.open(uploaded_file)
                    st.image(image, caption="Original Image", use_column_width=True)

        with col2:
            st.subheader("Output")
            if st.button("🔐 Encode & Download", key="encode"):
                if uploaded_file is None:
                    st.error("Please upload a cover file")
                elif not message.strip():
                    st.error("Please enter a message")
                elif not password.strip():
                    st.error("Please set a password")
                else:
                    try:
                        with st.spinner("Encoding message..."):
                            file_name = getattr(uploaded_file, 'name', '')
                            if is_audio_file(file_name):
                                encoded_bytes = encode_audio(uploaded_file, message.strip(), password.strip())
                                buf = io.BytesIO(encoded_bytes)
                                buf.seek(0)
                                st.success("Message encoded into audio successfully!")
                                st.audio(buf.read())
                                buf.seek(0)
                                download_name = "stego_audio.wav"
                                mime = "audio/wav"
                            elif is_video_file(file_name):
                                encoded_bytes = encode_video(uploaded_file, message.strip(), password.strip())
                                buf = io.BytesIO(encoded_bytes)
                                buf.seek(0)
                                st.success("Message encoded into video successfully!")
                                st.video(buf.read())
                                buf.seek(0)
                                download_name = "stego_video.mp4"
                                mime = "video/mp4"
                            else:
                                image = Image.open(uploaded_file)
                                encoded_image = encode_message(image, message.strip(), password.strip())
                                buf = io.BytesIO()
                                encoded_image.save(buf, format='PNG')
                                buf.seek(0)
                                st.success("Message encoded into image successfully!")
                                st.image(encoded_image, caption="Encoded Image", use_column_width=True)
                                download_name = "stego_image.png"
                                mime = "image/png"

                        st.download_button(
                            label="📥 Download Encoded File",
                            data=buf,
                            file_name=download_name,
                            mime=mime
                        )
                    except Exception as e:
                        st.error(f"Error: {str(e)}")

    elif page == "Encode Link/APK":
        st.header("🔗 Encode Link / APK Message")
        st.markdown("Use this mode to encode only URLs or APK references into an image, audio, or video file.")

        col1, col2 = st.columns(2)
        carrier_image = None

        with col1:
            st.subheader("Input")
            uploaded_file = st.file_uploader(
                "Choose a cover image, audio, or video file", 
                type=['png', 'jpg', 'jpeg', 'bmp', 'wav', 'mp3', 'ogg', 'flac', 'm4a', 'mp4', 'mov', 'avi', 'mkv', 'webm']
            )
            message = st.text_area("Enter a URL or APK reference:", height=140)
            password = st.text_input("Set a password:", type="password")

            st.markdown("This page is optimized for URL or APK payloads, but you can encode the payload into image or audio carriers.")
            if uploaded_file is not None:
                file_name = getattr(uploaded_file, 'name', '')
                if is_audio_file(file_name):
                    uploaded_file.seek(0)
                    st.audio(uploaded_file.read())
                elif is_video_file(file_name):
                    uploaded_file.seek(0)
                    st.video(uploaded_file.read())
                else:
                    carrier_image = Image.open(uploaded_file)
                    st.image(carrier_image, caption="Original Image", use_column_width=True)

        with col2:
            st.subheader("Output")
            if st.button("🔐 Encode Link/APK", key="encode_links"):
                if uploaded_file is None:
                    st.error("Please upload a cover file")
                elif not message.strip():
                    st.error("Please enter a link or APK reference")
                elif not password.strip():
                    st.error("Please set a password")
                else:
                    try:
                        with st.spinner("Encoding link/APK message..."):
                            file_name = getattr(uploaded_file, 'name', '')
                            if is_audio_file(file_name):
                                encoded_bytes = encode_audio(uploaded_file, message.strip(), password.strip())
                                buf = io.BytesIO(encoded_bytes)
                                buf.seek(0)
                                st.success("Link/APK message encoded into audio successfully!")
                                st.audio(buf.read())
                                buf.seek(0)
                                download_name = "stego_link_apk_audio.wav"
                                mime = "audio/wav"
                            elif is_video_file(file_name):
                                encoded_bytes = encode_video(uploaded_file, message.strip(), password.strip())
                                buf = io.BytesIO(encoded_bytes)
                                buf.seek(0)
                                st.success("Link/APK message encoded into video successfully!")
                                st.video(buf.read())
                                buf.seek(0)
                                download_name = "stego_link_apk_video.mp4"
                                mime = "video/mp4"
                            else:
                                encoded_image = encode_message(carrier_image, message.strip(), password.strip())
                                buf = io.BytesIO()
                                encoded_image.save(buf, format='PNG')
                                buf.seek(0)
                                st.success("Link/APK message encoded into image successfully!")
                                st.image(encoded_image, caption="Encoded Image", use_column_width=True)
                                download_name = "stego_link_apk_image.png"
                                mime = "image/png"

                        st.download_button(
                            label="📥 Download Encoded File",
                            data=buf,
                            file_name=download_name,
                            mime=mime
                        )
                    except Exception as e:
                        st.error(f"Error: {str(e)}")

    elif page == "Decode Link/APK":
        st.header("🔍 Decode Link / APK Message")
        st.markdown("Upload a stego-image or stego-audio file and enter the password to decode a URL or APK reference.")

        col1, col2 = st.columns(2)
        carrier_file = None

        with col1:
            st.subheader("Input")
            uploaded_file = st.file_uploader(
                "Choose a stego carrier file", 
                type=['png', 'jpg', 'jpeg', 'bmp', 'wav', 'mp3', 'ogg', 'flac', 'm4a', 'mp4', 'mov', 'avi', 'mkv', 'webm']
            )
            password = st.text_input("Enter password to decode:", type="password")

            if uploaded_file is not None:
                file_name = getattr(uploaded_file, 'name', '')
                if is_audio_file(file_name):
                    uploaded_file.seek(0)
                    st.audio(uploaded_file.read())
                elif is_video_file(file_name):
                    uploaded_file.seek(0)
                    st.video(uploaded_file.read())
                else:
                    carrier_file = Image.open(uploaded_file)
                    st.image(carrier_file, caption="Stego Image", use_column_width=True)

        with col2:
            st.subheader("Output")
            if st.button("🔍 Decode Link/APK", key="decode_links"):
                if uploaded_file is None:
                    st.error("Please upload a carrier file")
                elif not password.strip():
                    st.error("Please enter the password")
                else:
                    try:
                        with st.spinner("Decoding link/APK message..."):
                            file_name = getattr(uploaded_file, 'name', '')
                            if is_audio_file(file_name):
                                decoded_message = decode_audio(uploaded_file, password.strip())
                            elif is_video_file(file_name):
                                decoded_message = decode_video(uploaded_file, password.strip())
                            else:
                                decoded_message = decode_message(carrier_file, password.strip())

                        if decoded_message:
                            render_decoded_output(decoded_message)
                            if not (contains_link(decoded_message) or contains_apk_reference(decoded_message)):
                                st.info("Decoded content does not appear to be a URL or APK reference, but it is still decoded successfully.")
                        else:
                            st.error("Wrong password or no hidden message found.")
                    except Exception as e:
                        st.error(f"Error: {str(e)}")

    else:  # Decode Message
        st.header("🔓 Decode Message")

        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Input")
            uploaded_file = st.file_uploader(
                "Choose a stego carrier file", 
                type=['png', 'jpg', 'jpeg', 'bmp', 'wav', 'mp3', 'ogg', 'flac', 'm4a', 'mp4', 'mov', 'avi', 'mkv', 'webm', 'mp4', 'mov', 'avi', 'mkv', 'webm']
            )
            password = st.text_input("Enter password to decode:", type="password")

            if uploaded_file is not None:
                file_name = getattr(uploaded_file, 'name', '')
                if is_audio_file(file_name):
                    uploaded_file.seek(0)
                    st.audio(uploaded_file.read())
                elif is_video_file(file_name):
                    uploaded_file.seek(0)
                    st.video(uploaded_file.read())
                else:
                    image = Image.open(uploaded_file)
                    st.image(image, caption="Stego Image", use_column_width=True)

        with col2:
            st.subheader("Output")
            if st.button("🔍 Decode Message", key="decode"):
                if uploaded_file is None:
                    st.error("Please upload a carrier file")
                elif not password.strip():
                    st.error("Please enter the password")
                else:
                    try:
                        with st.spinner("Decoding message..."):
                            file_name = getattr(uploaded_file, 'name', '')
                            if is_audio_file(file_name):
                                decoded_message = decode_audio(uploaded_file, password.strip())
                            elif is_video_file(file_name):
                                decoded_message = decode_video(uploaded_file, password.strip())
                            else:
                                image = Image.open(uploaded_file)
                                decoded_message = decode_message(image, password.strip())

                        if decoded_message:
                            render_decoded_output(decoded_message)
                        else:
                            st.error("Wrong password or no hidden message found.")
                    except Exception as e:
                        st.error(f"Error: {str(e)}")

    # Footer
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center; color: #666;'>
        <p>Built with ❤️ using Python, Streamlit, and Pillow</p>
        <p>© 2026 Steganography Web App</p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()