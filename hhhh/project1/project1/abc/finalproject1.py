import streamlit as st
from PIL import Image
import io
import numpy as np
import re

st.set_page_config(
    page_title="Steganography Tool",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        text-align: center;
        color: #1f77b4;
        font-size: 3rem;
        margin-bottom: 2rem;
        text-shadow: 2px 2px 4px rgba(0,0,0,0.1);
    }
    .sub-header {
        color: #2c3e50;
        font-size: 1.5rem;
        margin-bottom: 1rem;
    }
    .stButton>button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        padding: 0.75rem 1.5rem;
        border-radius: 0.5rem;
        font-weight: bold;
        transition: all 0.3s ease;
    }
    .stButton>button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
    }
    .result-box {
        background: #f0f4f8;
        border-left: 4px solid #667eea;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 1rem 0;
    }
    .sidebar .sidebar-content {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
    }
</style>
""", unsafe_allow_html=True)

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

def encode_message(image, message, password):
    """Encode message into image using LSB steganography with password"""
    if image.mode != 'RGB':
        image = image.convert('RGB')

    pixels = np.array(image)
    # Store password + "::" + message
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
    """Decode message from image with password check"""
    if image.mode != 'RGB':
        image = image.convert('RGB')

    pixels = np.array(image)
    flat_pixels = pixels.flatten()

    binary_message = ''
    for pixel in flat_pixels:
        binary_message += str(pixel & 1)

    decoded_text = binary_to_string(binary_message)

    if "::" in decoded_text:
        stored_password, hidden_message = decoded_text.split("::", 1)
        if stored_password == password:
            return hidden_message
        else:
            return None
    return None

def is_spam(message: str) -> bool:
    """Check if hidden message contains risky links or suspicious keywords"""
    url_pattern = re.compile(r'(https?://[^\s]+)')
    urls = url_pattern.findall(message)

    risky_keywords = ["phishing", "malware", "clickme", "free-money", "hack", "attack"]

    if urls:
        return True
    for keyword in risky_keywords:
        if keyword.lower() in message.lower():
            return True
    return False

# Main App
def main():
    st.markdown('<h1 class="main-header">🔒 Steganography Tool</h1>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">Hide and reveal secret messages in images with password protection</p>', unsafe_allow_html=True)

    # Sidebar
    st.sidebar.title("📋 Navigation")
    page = st.sidebar.radio("Choose a function:", ["Encode Message", "Decode Message"])

    st.sidebar.markdown("---")
    st.sidebar.markdown("### How it works")
    st.sidebar.markdown("""
    This app uses Least Significant Bit (LSB) steganography to hide text messages within image files.
    A password is required to decode the hidden message.
    """)

    if page == "Encode Message":
        st.header("📝 Encode Message")

        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Input")
            uploaded_file = st.file_uploader("Choose an image", type=['png', 'jpg', 'jpeg', 'bmp'])
            message = st.text_area("Enter your secret message:", height=100)
            password = st.text_input("Set a password:", type="password")

            if uploaded_file is not None:
                image = Image.open(uploaded_file)
                st.image(image, caption="Original Image", use_column_width=True)

        with col2:
            st.subheader("Output")
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
                        with st.spinner("Encoding message..."):
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
            st.subheader("Input")
            uploaded_file = st.file_uploader("Choose a stego-image", type=['png', 'jpg', 'jpeg', 'bmp'])
            password = st.text_input("Enter password to decode:", type="password")

            if uploaded_file is not None:
                image = Image.open(uploaded_file)
                st.image(image, caption="Stego-Image", use_column_width=True)

        with col2:
            st.subheader("Output")
            if st.button("🔍 Decode Message", key="decode"):
                if uploaded_file is None:
                    st.error("Please upload an image")
                elif not password.strip():
                    st.error("Please enter the password")
                else:
                    try:
                        with st.spinner("Decoding message..."):
                            decoded_message = decode_message(image, password.strip())

                        if decoded_message:
                            if is_spam(decoded_message):
                                st.error("⚠️ Spam Alert: Risky content detected in hidden message!")
                            else:
                                st.success("Message decoded successfully!")
                                st.markdown('<div class="result-box">', unsafe_allow_html=True)
                                st.markdown(f"**Hidden Message:** {decoded_message}")
                                st.markdown('</div>', unsafe_allow_html=True)
                        else:
                            st.warning("No hidden message found or incorrect password.")
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
