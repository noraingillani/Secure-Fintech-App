import streamlit as st
import bcrypt
from cryptography.fernet import Fernet
import os
import time
import re
import pandas as pd
import plotly.express as px

# ------------------ PAGE SETTINGS ------------------
st.set_page_config(page_title="Secure FinTech by Norain 🛡️", page_icon="💸", layout="wide")

USER_DB = "fintech_users.csv"
LOG_DIR = "logs"

os.makedirs(LOG_DIR, exist_ok=True)

# ------------------ UTILITIES ------------------
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password, hashed):
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False

def encrypt_data(data):
    key = Fernet.generate_key()
    cipher = Fernet(key)
    token = cipher.encrypt(data.encode()).decode()
    return token, key.decode()

def decrypt_data(token, key):
    try:
        cipher = Fernet(key.encode())
        return cipher.decrypt(token.encode()).decode()
    except Exception:
        return None

def save_user(username, email, hashed_pw):
    df = pd.DataFrame([[username, email, hashed_pw]], columns=["username", "email", "password"])
    if not os.path.exists(USER_DB):
        df.to_csv(USER_DB, index=False)
    else:
        df.to_csv(USER_DB, mode='a', header=False, index=False)

def load_users():
    if not os.path.exists(USER_DB):
        return pd.DataFrame(columns=["username", "email", "password"])
    return pd.read_csv(USER_DB)

def record_action(username, action):
    log_path = os.path.join(LOG_DIR, f"{username}_activity.log")
    with open(log_path, "a") as file:
        file.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {action}\n")

# ------------------ STYLING ------------------
st.markdown("""
<style>
h1, h2, h3 { color: #005b63; font-family: 'Poppins'; }
div.stButton > button {
    background-color: #007b83; color: white; border-radius: 8px;
    font-weight: 500; padding: 8px 18px; border: none;
}
div.stButton > button:hover { background-color: #00a6a6; transform: scale(1.03); }
footer { position: fixed; bottom: 0; width: 100%; background: #005b63; color: white;
         text-align: center; padding: 6px; font-size: 13px; border-radius: 0; }
</style>
""", unsafe_allow_html=True)

# ------------------ SESSION SETUP ------------------
if "logged" not in st.session_state:
    st.session_state.logged = False
if "user" not in st.session_state:
    st.session_state.user = None
if "last_active" not in st.session_state:
    st.session_state.last_active = time.time()

# Session timeout
SESSION_TIMEOUT = 300
if st.session_state.logged and (time.time() - st.session_state.last_active > SESSION_TIMEOUT):
    st.warning("⏳ Session timed out. Please log in again.")
    record_action(st.session_state.user, "Session Timeout")
    st.session_state.logged = False
    st.session_state.user = None
    st.stop()

# ------------------ SIDEBAR MENU ------------------
menu = ["🏠 Home", "🧾 Register", "🔐 Login", "💬 Encrypt / Decrypt", "🧮 Input Validation", "📊 Activity Log"]
choice = st.sidebar.radio("Navigation", menu)

if st.session_state.logged:
    st.sidebar.markdown(f"👤 **{st.session_state.user}**")
    if st.sidebar.button("Logout 🚪"):
        record_action(st.session_state.user, "Logged Out")
        st.session_state.logged = False
        st.session_state.user = None
        st.success("You have successfully logged out.")
        st.stop()

# ------------------ HOME ------------------
if choice == "🏠 Home":
    st.title("💸 Secure FinTech Portal by Norain")
    st.write("""
    Welcome to a **simple and secure FinTech application** that demonstrates core cybersecurity concepts:
    - 🔐 User Authentication & Password Hashing  
    - 💾 Secure Data Storage  
    - 🧩 Encryption / Decryption Demo  
    - 🕵️ Audit Logging & Validation  
    """)
    st.info("Built with Streamlit, bcrypt, and cryptography for CY4053 – Cybersecurity for FinTech")

# ------------------ REGISTER ------------------
elif choice == "🧾 Register":
    st.header("🧾 Create Your Secure Account")
    uname = st.text_input("Username")
    email = st.text_input("Email")
    pw = st.text_input("Password", type="password")
    confirm = st.text_input("Confirm Password", type="password")

    if st.button("Register"):
        users = load_users()
        email_regex = r"^[\w\.-]+@[\w\.-]+\.\w+$"

        if uname in users["username"].values:
            st.warning("Username already exists. Try another one.")
        elif not uname or not email or not pw:
            st.warning("Please fill out all fields.")
        elif not re.match(email_regex, email):
            st.warning("Invalid email format.")
        elif pw != confirm:
            st.error("Passwords do not match.")
        elif len(pw) < 8 or not re.search(r"\d", pw) or not re.search(r"[A-Za-z]", pw):
            st.warning("Password must be 8+ chars, include a letter & a number.")
        else:
            hashed = hash_password(pw)
            save_user(uname, email, hashed)
            st.success(f"Account created successfully for {uname} ✅")
            record_action(uname, "Registered")

# ------------------ LOGIN ------------------
elif choice == "🔐 Login":
    st.header("🔐 Secure Login")
    uname = st.text_input("Username")
    pw = st.text_input("Password", type="password")

    if "attempts" not in st.session_state:
        st.session_state.attempts = 0

    if st.button("Login"):
        users = load_users()
        if uname not in users["username"].values:
            st.error("No such user found.")
        else:
            hashed = users.loc[users["username"] == uname, "password"].values[0]
            if verify_password(pw, hashed):
                st.session_state.logged = True
                st.session_state.user = uname
                st.session_state.last_active = time.time()
                st.session_state.attempts = 0
                st.success(f"Welcome back, {uname} 👋")
                record_action(uname, "Logged In")
            else:
                st.session_state.attempts += 1
                st.error(f"Wrong password. Attempt {st.session_state.attempts}/3")
                if st.session_state.attempts >= 3:
                    st.error("Account temporarily locked for security reasons.")
                    record_action(uname, "Account Locked")

# ------------------ ENCRYPT / DECRYPT ------------------
elif choice == "💬 Encrypt / Decrypt":
    st.header("🔒 Data Encryption & Decryption")
    if not st.session_state.logged:
        st.warning("Please login first to use this feature.")
        st.stop()

    option = st.radio("Choose Action:", ["Encrypt Data", "Decrypt Data"])
    text = st.text_area("Enter text:")
    key_input = st.text_input("Enter key (for decryption only):")

    if st.button("Run"):
        st.session_state.last_active = time.time()
        if option == "Encrypt Data":
            if not text.strip():
                st.warning("Please enter text to encrypt.")
            else:
                encrypted, key = encrypt_data(text)
                st.success("✅ Data encrypted successfully!")
                st.text_area("Encrypted Output", encrypted, height=130)
                st.info("Keep your encryption key safe:")
                st.code(key)
                record_action(st.session_state.user, "Encrypted Data")
        else:
            if not text.strip() or not key_input.strip():
                st.warning("Enter both encrypted text and key.")
            else:
                decrypted = decrypt_data(text, key_input)
                if decrypted:
                    st.success("✅ Decryption successful!")
                    st.text_area("Decrypted Output", decrypted, height=130)
                    record_action(st.session_state.user, "Decrypted Data")
                else:
                    st.error("❌ Invalid key or text. Decryption failed.")

# ------------------ INPUT VALIDATION ------------------
elif choice == "🧮 Input Validation":
    st.header("🧮 Transaction Validation Example")
    amount = st.text_input("Enter transaction amount:")
    desc = st.text_input("Enter transaction note:")

    if st.button("Submit"):
        if not amount.isdigit():
            st.warning("Amount must be a valid number.")
        elif len(desc.strip()) == 0:
            st.warning("Please add a note for your transaction.")
        else:
            st.success(f"✅ Transaction of Rs.{amount} recorded successfully.")
            record_action(st.session_state.user or 'guest', f"Transaction: {amount}")

# ------------------ ACTIVITY LOG ------------------
elif choice == "📊 Activity Log":
    st.header("📊 User Activity Dashboard")
    if not st.session_state.logged:
        st.warning("Please login to view activity.")
        st.stop()

    log_path = os.path.join(LOG_DIR, f"{st.session_state.user}_activity.log")
    if not os.path.exists(log_path):
        st.info("No recorded activity yet.")
    else:
        with open(log_path, "r") as f:
            logs = [line.strip() for line in f.readlines()]
        st.write("🕓 Recent Activity:")
        for line in logs[-10:]:
            st.write(line)

        # Summary Visualization
        df = pd.DataFrame([l.split("|")[1].strip() for l in logs], columns=["Action"])
        summary = df["Action"].value_counts().reset_index()
        summary.columns = ["Action", "Count"]

        fig = px.bar(summary, x="Action", y="Count", color="Action",
                     color_discrete_sequence=px.colors.sequential.Tealgrn,
                     title=f"{st.session_state.user}'s Activity Summary")
        st.plotly_chart(fig, use_container_width=True)

# ------------------ FOOTER ------------------
st.markdown("""
<footer>
Developed with ❤️ by <b>Norain Gillani</b> | Secure FinTech © 2025
</footer>
""", unsafe_allow_html=True)
