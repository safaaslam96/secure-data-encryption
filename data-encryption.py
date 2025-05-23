import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# ========== Constants ==========
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60

# ========== Session State ==========
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# ========== Functions ==========
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as file:
            return json.load(file)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as file:
        json.dump(data, file)

def generate_key(passkey):
    key = pbkdf2_hmac("sha256", passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), SALT, 100000).hex()

def encrypt_text(text, passkey):
    cipher = Fernet(generate_key(passkey))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(enc_text, passkey):
    try:
        cipher = Fernet(generate_key(passkey))
        return cipher.decrypt(enc_text.encode()).decode()
    except:
        return None

# ========== Load Data ==========
stored_data = load_data()

# ========== Custom CSS ==========
st.markdown("""
<style>
/* Background with neon glow */
body, .stApp {
    background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
    font-family: 'Segoe UI', sans-serif;
    animation: fadeIn 1s ease-in-out;
}

@keyframes fadeIn {
    from {opacity: 0;}
    to {opacity: 1;}
}

/* Sidebar glassmorphism */
[data-testid="stSidebar"] {
    background: rgba(255, 255, 255, 0.05);
    border-right: 2px solid rgba(255, 255, 255, 0.1);
    backdrop-filter: blur(12px);
    box-shadow: 4px 0 25px rgba(0, 255, 255, 0.15);
    transition: all 0.4s ease-in-out;
    border-top-right-radius: 20px;
    border-bottom-right-radius: 20px;
}

.stTextInput>div>input, .stTextArea>div>textarea {
    border-radius: 12px;
    padding: 10px;
    background: rgba(255, 255, 255, 0.05);
    border: 1px solid rgba(255, 255, 255, 0.2);
    backdrop-filter: blur(10px);
    color: #fff;
}

/* Buttons */
.stButton>button {
    background: linear-gradient(135deg, rgba(0,255,255,0.2), rgba(128,0,255,0.3));
    border: 1px solid rgba(255,255,255,0.2);
    border-radius: 15px;
    backdrop-filter: blur(12px);
    color: #fff;
    padding: 10px 20px;
    transition: 0.3s ease;
    width: 100%;
    box-shadow: 0 0 12px rgba(0,255,255,0.2);
}

.stButton>button:hover {
    background: rgba(128, 0, 255, 0.5);
    transform: scale(1.05);
    box-shadow: 0 0 25px rgba(128, 0, 255, 0.5);
    color: #fff;
}

/* Headers and text */
h1, h2, h3, p, label, .css-10trblm, .css-1v0mbdj {
    color: #f0f0f0 !important;
    text-shadow: 0 0 5px rgba(0,255,255,0.3);
}

hr {
    border-top: 1px solid rgba(255,255,255,0.2);
}
</style>
""", unsafe_allow_html=True)

# ========== Sidebar ==========
st.sidebar.markdown("<h1 style='text-align:center;'>🔐</h1>", unsafe_allow_html=True)
st.sidebar.markdown("<h3 style='text-align:center; color:#fff;'>Secure Encryption</h3>", unsafe_allow_html=True)
nav = st.sidebar.radio("", ["🏠 Home", "📝 Register", "🔑 Login", "🔒 Encrypt", "🔓 Decrypt"], label_visibility="collapsed")

# ========== Navigation ==========
if nav == "🏠 Home":
    st.header("🔏 Welcome to Secure Encryption")
    st.markdown("""
    - Register & login securely  
    - Encrypt your private data using AES  
    - Decrypt anytime with your key  
    - 🌐 Everything stays local (no cloud)
    """)

elif nav == "📝 Register":
    st.header("🧾 Register")
    username = st.text_input("👤 Username")
    password = st.text_input("🔑 Password", type="password")
    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("⚠️ User already exists.")
            else:
                stored_data[username] = {"password": hash_password(password), "data": []}
                save_data(stored_data)
                st.success("✅ Registered successfully!")
        else:
            st.error("All fields required!")

elif nav == "🔑 Login":
    st.header("🔐 Login")
    if time.time() < st.session_state.lockout_time:
        st.error(f"⏳ Locked! Wait {int(st.session_state.lockout_time - time.time())} seconds.")
        st.stop()

    username = st.text_input("👤 Username")
    password = st.text_input("🔒 Password", type="password")
    if st.button("Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"✅ Welcome {username}!")
        else:
            st.session_state.failed_attempts += 1
            attempts_left = 3 - st.session_state.failed_attempts
            st.error(f"❌ Invalid credentials. Attempts left: {attempts_left}")
            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.stop()

elif nav == "🔒 Encrypt":
    if not st.session_state.authenticated_user:
        st.warning("🔑 Please login first.")
    else:
        st.header("🔐 Encrypt & Store")
        data = st.text_area("📝 Enter data")
        passkey = st.text_input("🔑 Encryption Key", type="password")
        if st.button("Encrypt and Save"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("🔒 Encrypted and saved!")
            else:
                st.error("All fields required.")

elif nav == "🔓 Decrypt":
    if not st.session_state.authenticated_user:
        st.warning("🔑 Please login first.")
    else:
        st.header("🔓 Decrypt Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])
        if not user_data:
            st.info("ℹ️ No data available.")
        else:
            st.write("🧾 Encrypted Entries:")
            for i, item in enumerate(user_data):
                st.code(item, language="text")

            enc_input = st.text_input("🔐 Encrypted Text")
            passkey = st.text_input("🔑 Passkey", type="password")
            if st.button("Decrypt"):
                result = decrypt_text(enc_input, passkey)
                if result:
                    st.success(f"✅ Decrypted: {result}")
                else:
                    st.error("❌ Incorrect passkey or corrupted data.")
