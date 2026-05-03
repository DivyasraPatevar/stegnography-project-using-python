import streamlit as st
import streamlit.components.v1 as components
from PIL import Image
import io
import numpy as np
import re

st.set_page_config(
    page_title="StegSecure Tool",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# -------------------------------
# Utility functions
# -------------------------------
def string_to_binary(message):
    binary = ''
    for char in message:
        binary += format(ord(char), '08b')
    return binary + '00000000'  # Null terminator

def binary_to_string(binary):
    chars = []
    for i in range(0, len(binary), 8):
        byte = binary[i:i+8]
        if byte == '00000000':  # Null terminator
            break
        chars.append(chr(int(byte, 2)))
    return ''.join(chars)

def encode_message(image, message, password):
    if image.mode != 'RGB':
        image = image.convert('RGB')
    pixels = np.array(image)
    combined_message = password + "::" + message
    binary_message = string_to_binary(combined_message)
    if len(binary_message) > pixels.size:
        raise ValueError("Message is too long for this image")
    flat_pixels = pixels.flatten()
    for i, bit in enumerate(binary_message):
        flat_pixels[i] = (flat_pixels[i] & 0xFE) | int(bit)
    new_pixels = flat_pixels.reshape(pixels.shape)
    encoded_image = Image.fromarray(new_pixels.astype('uint8'), 'RGB')
    return encoded_image

def decode_message(image, password):
    if image.mode != 'RGB':
        image = image.convert('RGB')
    pixels = np.array(image)
    flat_pixels = pixels.flatten()
    binary_message = ''.join(str(pixel & 1) for pixel in flat_pixels)
    decoded_text = binary_to_string(binary_message)
    if "::" in decoded_text:
        stored_password, hidden_message = decoded_text.split("::", 1)
        if stored_password == password:
            return hidden_message
        else:
            return None
    return None
def is_spam(message: str) -> bool:
    url_pattern = re.compile(r'(https?://[^\s]+)')
    urls = url_pattern.findall(message)
    risky_keywords = ["phishing", "malware", "clickme", "free-money", "hack", "attack"]
    if urls:
        return True
    for keyword in risky_keywords:
        if keyword.lower() in message.lower():
            return True
    return False

# -------------------------------
# Landing Page (HTML)
# -------------------------------
def landing_page():
    html_code = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>StegSecure - Detecting Hidden Threats</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --primary-color: #0f172a;
            --secondary-color: #1e293b;
            --accent-color: #3b82f6;
            --accent-light: #60a5fa;
            --text-primary: #f1f5f9;
            --text-secondary: #cbd5e1;
            --border-color: #334155;
            --success-color: #10b981;
            --warning-color: #f59e0b;
        }

        html {
            scroll-behavior: smooth;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background-color: var(--primary-color);
            color: var(--text-primary);
            line-height: 1.6;
        }

        a {
            text-decoration: none;
            color: inherit;
        }

        button {
            cursor: pointer;
            border: none;
            font-family: inherit;
            transition: all 0.3s ease;
        }

        /* Navigation */
        nav {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            background-color: rgba(15, 23, 42, 0.95);
            backdrop-filter: blur(10px);
            border-bottom: 1px solid var(--border-color);
            z-index: 1000;
            padding: 1rem 2rem;
        }

        nav .container {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .logo {
            font-size: 1.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--accent-color), var(--accent-light));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        nav ul {
            display: flex;
            list-style: none;
            gap: 2rem;
        }

        nav a {
            font-size: 0.9rem;
            color: var(--text-secondary);
            transition: color 0.3s ease;
        }

        nav a:hover {
            color: var(--accent-color);
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 2rem;
        }

        /* Hero Section */
        .hero {
            margin-top: 80px;
            padding: 120px 0;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            background: linear-gradient(135deg, rgba(15, 23, 42, 1) 0%, rgba(30, 41, 59, 0.5) 100%);
            border-bottom: 1px solid var(--border-color);
        }

        .hero-content {
            text-align: center;
            max-width: 700px;
        }

        .hero h1 {
            font-size: 3.5rem;
            font-weight: 800;
            margin-bottom: 1.5rem;
            line-height: 1.2;
            color: var(--text-primary);
        }

        .hero h1 .highlight {
            background: linear-gradient(135deg, var(--accent-color), var(--accent-light));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .hero p {
            font-size: 1.25rem;
            color: var(--text-secondary);
            margin-bottom: 2rem;
            line-height: 1.8;
        }

        .hero-buttons {
            display: flex;
            gap: 1rem;
            justify-content: center;
            flex-wrap: wrap;
        }

        .btn {
            padding: 12px 32px;
            border-radius: 6px;
            font-weight: 600;
            font-size: 1rem;
            transition: all 0.3s ease;
        }

        .btn-primary {
            background-color: var(--accent-color);
            color: white;
        }

        .btn-primary:hover {
            background-color: var(--accent-light);
            transform: translateY(-2px);
            box-shadow: 0 10px 30px rgba(59, 130, 246, 0.3);
        }

        .btn-secondary {
            background-color: transparent;
            border: 2px solid var(--border-color);
            color: var(--text-primary);
        }

        .btn-secondary:hover {
            border-color: var(--accent-color);
            color: var(--accent-color);
        }

        /* Section Styling */
        section {
            padding: 80px 0;
            border-bottom: 1px solid var(--border-color);
        }

        .section-title {
            text-align: center;
            margin-bottom: 3rem;
        }

        .section-title h2 {
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
            color: var(--text-primary);
        }

        .section-title .subtitle {
            font-size: 1.1rem;
            color: var(--text-secondary);
        }

        /* About Section */
        .about {
            background-color: var(--secondary-color);
        }

        .about-content {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 3rem;
            align-items: center;
        }

        .about-text h3 {
            font-size: 1.8rem;
            margin-bottom: 1.5rem;
            color: var(--text-primary);
        }

        .about-text p {
            font-size: 1.1rem;
            color: var(--text-secondary);
            margin-bottom: 1rem;
            line-height: 1.8;
        }

        .about-features {
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }

        .feature-item {
            background-color: var(--primary-color);
            padding: 1.5rem;
            border-radius: 8px;
            border-left: 3px solid var(--accent-color);
            transition: all 0.3s ease;
        }

        .feature-item:hover {
            background-color: rgba(59, 130, 246, 0.1);
            transform: translateX(5px);
        }

        .feature-item strong {
            color: var(--accent-light);
            display: block;
            margin-bottom: 0.5rem;
        }

        .feature-item p {
            font-size: 0.95rem;
            margin: 0;
        }

        /* How It Works */
        .how-it-works {
            background-color: var(--primary-color);
        }

        .process-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 2rem;
            margin-top: 2rem;
        }

        .process-card {
            background-color: var(--secondary-color);
            padding: 2rem;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            text-align: center;
            transition: all 0.3s ease;
        }

        .process-card:hover {
            border-color: var(--accent-color);
            background-color: rgba(59, 130, 246, 0.05);
        }

        .process-number {
            font-size: 3rem;
            font-weight: 800;
            color: var(--accent-color);
            margin-bottom: 1rem;
        }

        .process-card h3 {
            font-size: 1.3rem;
            margin-bottom: 1rem;
            color: var(--text-primary);
        }

        .process-card p {
            font-size: 0.95rem;
            color: var(--text-secondary);
            line-height: 1.6;
        }

        /* Features Section */
        .features {
            background-color: var(--secondary-color);
        }

        .features-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 2rem;
        }

        .feature-card {
            background: linear-gradient(135deg, var(--secondary-color) 0%, rgba(59, 130, 246, 0.1) 100%);
            padding: 2rem;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            transition: all 0.3s ease;
        }

        .feature-card:hover {
            border-color: var(--accent-color);
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(59, 130, 246, 0.15);
        }

        .feature-icon {
            font-size: 2.5rem;
            margin-bottom: 1rem;
            width: 60px;
            height: 60px;
            display: flex;
            align-items: center;
            justify-content: center;
            background-color: rgba(59, 130, 246, 0.1);
            border-radius: 6px;
            color: var(--accent-color);
        }

        .feature-card h3 {
            font-size: 1.3rem;
            margin-bottom: 0.8rem;
            color: var(--text-primary);
        }

        .feature-card p {
            font-size: 0.95rem;
            color: var(--text-secondary);
            line-height: 1.6;
        }

        /* Use Cases Section */
        .use-cases {
            background-color: var(--primary-color);
        }

        .use-cases-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 1.5rem;
        }

        .use-case-card {
            background-color: var(--secondary-color);
            padding: 2rem;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            transition: all 0.3s ease;
        }

        .use-case-card:hover {
            border-color: var(--accent-color);
            background-color: rgba(59, 130, 246, 0.05);
        }

        .use-case-icon {
            font-size: 2.5rem;
            margin-bottom: 1rem;
        }

        .use-case-card h3 {
            font-size: 1.2rem;
            margin-bottom: 0.8rem;
            color: var(--accent-light);
        }

        .use-case-card p {
            font-size: 0.95rem;
            color: var(--text-secondary);
            line-height: 1.6;
        }

        /* Why StegSecure */
        .why-stegsecure {
            background-color: var(--secondary-color);
        }

        .comparison {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 2rem;
            margin-top: 2rem;
        }

        .comparison-card {
            background-color: var(--primary-color);
            padding: 2rem;
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }

        .comparison-card.stegsecure {
            border-color: var(--accent-color);
            background: linear-gradient(135deg, rgba(59, 130, 246, 0.1) 0%, transparent 100%);
        }

        .comparison-card h3 {
            font-size: 1.5rem;
            margin-bottom: 1.5rem;
            color: var(--text-primary);
        }

        .comparison-list {
            list-style: none;
        }

        .comparison-list li {
            padding: 0.8rem 0;
            padding-left: 1.5rem;
            position: relative;
            color: var(--text-secondary);
            font-size: 0.95rem;
        }

        .comparison-list li::before {
            content: "✓";
            position: absolute;
            left: 0;
            color: var(--success-color);
            font-weight: bold;
            font-size: 1.2rem;
        }

        .comparison-card.stegsecure .comparison-list li::before {
            color: var(--accent-light);
        }

        /* Footer */
        footer {
            background-color: var(--primary-color);
            border-top: 1px solid var(--border-color);
            padding: 3rem 0;
        }

        .footer-content {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 2rem;
            margin-bottom: 2rem;
        }

        .footer-section h4 {
            color: var(--text-primary);
            margin-bottom: 1rem;
            font-size: 0.95rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .footer-section ul {
            list-style: none;
        }

        .footer-section a {
            color: var(--text-secondary);
            font-size: 0.9rem;
            transition: color 0.3s ease;
            display: block;
            padding: 0.5rem 0;
        }

        .footer-section a:hover {
            color: var(--accent-color);
        }

        .footer-bottom {
            border-top: 1px solid var(--border-color);
            padding-top: 2rem;
            text-align: center;
        }

        .disclaimer {
            background-color: rgba(59, 130, 246, 0.1);
            border: 1px solid var(--accent-color);
            border-radius: 6px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            font-size: 0.95rem;
            color: var(--text-secondary);
            line-height: 1.6;
        }

        .disclaimer strong {
            color: var(--accent-light);
        }

        .copyright {
            color: var(--text-secondary);
            font-size: 0.9rem;
        }

        /* Responsive */
        @media (max-width: 768px) {
            nav ul {
                display: none;
            }

            .hero h1 {
                font-size: 2.5rem;
            }

            .hero p {
                font-size: 1rem;
            }

            .hero-buttons {
                flex-direction: column;
                align-items: center;
            }

            .btn {
                width: 100%;
                max-width: 200px;
            }

            .section-title h2 {
                font-size: 2rem;
            }

            .about-content {
                grid-template-columns: 1fr;
            }

            .comparison {
                grid-template-columns: 1fr;
            }

            section {
                padding: 50px 0;
            }

            .hero {
                padding: 80px 0;
                margin-top: 60px;
            }
        }

        @media (max-width: 480px) {
            .hero h1 {
                font-size: 1.8rem;
            }

            .section-title h2 {
                font-size: 1.5rem;
            }

            .hero p {
                font-size: 0.95rem;
            }

            nav {
                padding: 0.75rem 1rem;
            }

            .logo {
                font-size: 1.2rem;
            }

            section {
                padding: 40px 0;
            }
        }
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav>
        <div class="container">
            <div class="logo">🔒 StegSecure</div>
            <ul>
                <li><a href="#about">About</a></li>
                <li><a href="#how-it-works">How It Works</a></li>
                <li><a href="#features">Features</a></li>
                <li><a href="#use-cases">Use Cases</a></li>
                <li><a href="#why">Why StegSecure</a></li>
            </ul>
        </div>
    </nav>

    <!-- Hero Section -->
    <section class="hero">
        <div class="container">
            <div class="hero-content">
                <h1>StegSecure – <span class="highlight">Detecting Hidden Threats</span> in Everyday Files</h1>
                <p>A cybersecurity solution that detects hidden data and malware concealed within media files using steganography techniques.</p>
                <div class="hero-buttons">
                    <button class="btn btn-primary">🔍 Scan File</button>
                    <button class="btn btn-secondary">Learn More</button>
                </div>
            </div>
        </div>
    </section>

    <!-- About Section -->
    <section class="about" id="about">
        <div class="container">
            <div class="section-title">
                <h2>About StegSecure</h2>
                <p class="subtitle">Smarter detection for hidden threats</p>
            </div>
            <div class="about-content">
                <div class="about-text">
                    <h3>What We Do</h3>
                    <p>StegSecure analyzes images, audio, and video files using a multi-layered detection approach. We employ statistical analysis to identify unusual patterns in file structures, signature-based detection to recognize known threats, and anomaly detection to spot suspicious behavior that doesn't match normal file characteristics.</p>
                    <p>Our solution provides clear, actionable insights without overwhelming users with technical jargon. Whether a file is safe to open or potentially suspicious, you get a straightforward assessment.</p>
                </div>
                <div class="about-features">
                    <div class="feature-item">
                        <strong>📊 Statistical Analysis</strong>
                        <p>Examines pixel distributions, audio frequency patterns, and metadata anomalies</p>
                    </div>
                    <div class="feature-item">
                        <strong>🎯 Signature Detection</strong>
                        <p>Identifies known hidden threats and malware signatures embedded in media</p>
                    </div>
                    <div class="feature-item">
                        <strong>⚠️ Anomaly Detection</strong>
                        <p>Flags unusual patterns that deviate from normal file behavior</p>
                    </div>
                    <div class="feature-item">
                        <strong>⚡ Real-Time Processing</strong>
                        <p>Instant analysis without compromising accuracy</p>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- How It Works -->
    <section class="how-it-works" id="how-it-works">
        <div class="container">
            <div class="section-title">
                <h2>How It Works</h2>
                <p class="subtitle">Three simple steps to threat detection</p>
            </div>
            <div class="process-container">
                <div class="process-card">
                    <div class="process-number">1</div>
                    <h3>Upload Media</h3>
                    <p>Submit your image, audio, or video files for analysis. We support all common formats and process files securely.</p>
                </div>
                <div class="process-card">
                    <div class="process-number">2</div>
                    <h3>Pattern Analysis</h3>
                    <p>StegSecure runs statistical checks, signature matching, and anomaly detection across multiple detection layers.</p>
                </div>
                <div class="process-card">
                    <div class="process-number">3</div>
                    <h3>Get Results</h3>
                    <p>Receive a clear assessment: Safe or Suspicious, with detailed analysis of any detected threats.</p>
                </div>
            </div>
        </div>
    </section>

    <!-- Features Section -->
    <section class="features" id="features">
        <div class="container">
            <div class="section-title">
                <h2>Key Features</h2>
                <p class="subtitle">Built for modern security needs</p>
            </div>
            <div class="features-grid">
                <div class="feature-card">
                    <div class="feature-icon">🔐</div>
                    <h3>Steganography Detection</h3>
                    <p>Specialized algorithms designed to uncover hidden data compression, LSB modifications, and advanced concealment techniques.</p>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">⚡</div>
                    <h3>Lightweight & Fast</h3>
                    <p>Minimal resource usage with quick processing times. Scan files without slowing down your system or workflow.</p>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">🤖</div>
                    <h3>Prototype Anomaly Detection</h3>
                    <p>Machine learning-based detection identifies abnormal patterns and behavioral indicators in media files.</p>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">🔄</div>
                    <h3>Real-Time Scanning</h3>
                    <p>Instant analysis at the concept level, providing immediate threat assessment as files arrive.</p>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">📊</div>
                    <h3>Detailed Reports</h3>
                    <p>Comprehensive analysis results with confidence scores and technical insights for security professionals.</p>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">🛡️</div>
                    <h3>Secure by Default</h3>
                    <p>Files never leave your system. All analysis runs locally with no external data transmission.</p>
                </div>
            </div>
        </div>
    </section>

    <!-- Use Cases -->
    <section class="use-cases" id="use-cases">
        <div class="container">
            <div class="section-title">
                <h2>Use Cases</h2>
                <p class="subtitle">Protecting what matters most</p>
            </div>
            <div class="use-cases-grid">
                <div class="use-case-card">
                    <div class="use-case-icon">🚨</div>
                    <h3>Prevent Data Exfiltration</h3>
                    <p>Stop sensitive data from being smuggled out of organizations through hidden channels in seemingly innocent media files.</p>
                </div>
                <div class="use-case-card">
                    <div class="use-case-icon">🐛</div>
                    <h3>Detect Hidden Malware</h3>
                    <p>Identify malicious payloads concealed within image or video files before they can compromise your system.</p>
                </div>
                <div class="use-case-card">
                    <div class="use-case-icon">📧</div>
                    <h3>Improve Email Security</h3>
                    <p>Scan attachments and downloaded files for hidden threats that traditional antivirus solutions might miss.</p>
                </div>
                <div class="use-case-card">
                    <div class="use-case-icon">🎓</div>
                    <h3>Cybersecurity Learning</h3>
                    <p>Educational tool for security students and professionals to understand steganography and advanced threat detection methods.</p>
                </div>
            </div>
        </div>
    </section>

    <!-- Why StegSecure -->
    <section class="why-stegsecure" id="why">
        <div class="container">
            <div class="section-title">
                <h2>Why StegSecure?</h2>
                <p class="subtitle">When traditional tools aren't enough</p>
            </div>
            <p style="text-align: center; color: var(--text-secondary); margin-bottom: 2rem; max-width: 800px; margin-left: auto; margin-right: auto; font-size: 1.1rem;">
                Traditional cybersecurity tools are excellent at detecting visible threats—malware, viruses, phishing attacks. But they miss an entire category of risk: <strong>hidden threats concealed in plain sight</strong> within media files.
            </p>
            <div class="comparison">
                <div class="comparison-card">
                    <h3>Traditional Tools</h3>
                    <ul class="comparison-list">
                        <li>Scan for known malware signatures</li>
                        <li>Monitor network traffic</li>
                        <li>Analyze executable code</li>
                        <li>Block suspicious domains</li>
                        <li>Endpoint protection</li>
                    </ul>
                </div>
                <div class="comparison-card stegsecure">
                    <h3>StegSecure</h3>
                    <ul class="comparison-list">
                        <li>Detects hidden data patterns</li>
                        <li>Analyzes statistical anomalies</li>
                        <li>Identifies steganographic techniques</li>
                        <li>Flags suspicious modifications</li>
                        <li>Uncovers concealed payloads</li>
                    </ul>
                </div>
            </div>
        </div>
    </section>

    <!-- Footer -->
    <footer>
        <div class="container">
            <div class="disclaimer">
                <strong>⚠️ Prototype Disclaimer:</strong> This is a prototype built for demonstration purposes. StegSecure is in active development and should not be used as a sole security solution in production environments. Always combine with comprehensive cybersecurity strategies and professional security tools.
            </div>
            <div class="footer-content">
                <div class="footer-section">
                    <h4>Product</h4>
                    <ul>
                        <li><a href="#features">Features</a></li>
                        <li><a href="#how-it-works">How It Works</a></li>
                        <li><a href="#use-cases">Use Cases</a></li>
                        <li><a href="">Pricing</a></li>
                    </ul>
                </div>
                <div class="footer-section">
                    <h4>Company</h4>
                    <ul>
                        <li><a href="">About Us</a></li>
                        <li><a href="">Blog</a></li>
                        <li><a href="">Careers</a></li>
                        <li><a href="">Contact</a></li>
                    </ul>
                </div>
                <div class="footer-section">
                    <h4>Resources</h4>
                    <ul>
                        <li><a href="">Documentation</a></li>
                        <li><a href="">API Docs</a></li>
                        <li><a href="">Security</a></li>
                        <li><a href="">Support</a></li>
                    </ul>
                </div>
                <div class="footer-section">
                    <h4>Legal</h4>
                    <ul>
                        <li><a href="">Privacy Policy</a></li>
                        <li><a href="">Terms of Service</a></li>
                        <li><a href="">Disclaimer</a></li>
                        <li><a href="">Cookies</a></li>
                    </ul>
                </div>
            </div>
            <div class="footer-bottom">
                <p class="copyright">&copy; 2026 StegSecure. All rights reserved. | Built for security-conscious organizations.</p>
            </div>
        </div>
    </footer>
</body>
</html>"""
    
    components.html(html_code, height=500, scrolling=True)

# -------------------------------
# Main App
# -------------------------------
def main():
    st.sidebar.title("📋 Navigation")
    page = st.sidebar.radio("Choose a page:", ["Landing Page", "Encode Message", "Decode Message"])

    if page == "Landing Page":
        landing_page()

    elif page == "Encode Message":
        st.header("📝 Encode Message")
        col1, col2 = st.columns(2)
        with col1:
            uploaded_file = st.file_uploader("Choose an image", type=['png', 'jpg', 'jpeg', 'bmp'])
            message = st.text_area("Enter your secret message:", height=100)
            password = st.text_input("Set a password:", type="password")
            if uploaded_file is not None:
                image = Image.open(uploaded_file)
                st.image(image, caption="Original Image", use_column_width=True)
        with col2:
            if st.button("🔐 Encode & Download", key="encode"):
                if uploaded_file is None:
                    st.error("Please upload an image")
                elif not message.strip():
                    st.error("Please enter a message")
                elif not password.strip():
                    st.error("Please set a password")
                elif is_spam(message.strip()):
                    st.error("⚠️ Spam Alert: Risky content detected in your message. Encoding blocked.")
                else:
                    try:
                        encoded_image = encode_message(image, message.strip(), password.strip())
                        buf = io.BytesIO()
                        encoded_image.save(buf, format='PNG')
                        buf.seek(0)
                        st.success("Message encoded successfully!")
                        st.image(encoded_image, caption="Encoded Image", use_column_width=True)
                        st.download_button(
                            label="📥 Download Encoded Image",
                            data=buf,
                            file_name="stego_image.png",
                            mime="image/png"
                        )
                    except Exception as e:
                        st.error(f"Error: {str(e)}")

    else:  # Decode Message
        st.header("🔓 Decode Message")
        col1, col2 = st.columns(2)
        with col1:
            uploaded_file = st.file_uploader("Choose a stego-image", type=['png', 'jpg', 'jpeg', 'bmp'])
            password = st.text_input("Enter password to decode:", type="password")
            if uploaded_file is not None:
                image = Image.open(uploaded_file)
                st.image(image, caption="Stego-Image", use_column_width=True)
        with col2:
            if st.button("🔍 Decode Message", key="decode"):
                if uploaded_file is None:
                    st.error("Please upload an image")
                elif not password.strip():
                    st.error("Please enter the password")
                else:
                    try:
                        decoded_message = decode_message(image, password.strip())
                        if decoded_message:
                            if is_spam(decoded_message):
                                st.error("⚠️ Spam Alert: Risky content detected in hidden message!")
                            else:
                                st.success("Message decoded successfully!")
                                st.markdown(f"**Hidden Message:** {decoded_message}")
                        else:
                            st.warning("No hidden message found or incorrect password.")
                    except Exception as e:
                        st.error(f"Error: {str(e)}")

    st.markdown("---")
    st.markdown("<div style='text-align:center; color:#666;'>© 2026 StegSecure Web App</div>", unsafe_allow_html=True)

if __name__ == "__main__":
    main()
