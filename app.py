import streamlit as st
from cryptography.fernet import Fernet
import os
import time
import plotly.express as px
import re

# ---------------- CONFIG ----------------
st.set_page_config(page_title="Noori's 🥷🏻 FinTech", page_icon="💳", layout="wide")

USER_FILE = "users.txt"

# ---------------- UTILITIES ----------------
def encrypt_password(password):
    key = Fernet.generate_key()
    cipher = Fernet(key)
    encrypted = cipher.encrypt(password.encode()).decode()
    return encrypted, key.decode()

def decrypt_password(encrypted_password, key_str):
    try:
        cipher = Fernet(key_str.encode())
        return cipher.decrypt(encrypted_password.encode()).decode()
    except Exception:
        return None

def save_user(username, email, encrypted_pw, key_str):
    with open(USER_FILE, "a") as f:
        f.write(f"{username}|{email}|{encrypted_pw}|{key_str}\n")

def load_users():
    users = {}
    if os.path.exists(USER_FILE):
        with open(USER_FILE, "r") as f:
            for line in f:
                if line.strip():
                    username, email, encrypted_pw, key_str = line.strip().split("|")
                    users[username] = {"email": email, "password": encrypted_pw, "key": key_str}
    return users

def log_activity(action, username=None):
    """Logs actions per user (separate file per user)."""
    if not username:
        username = st.session_state.get("username", "unknown_user")
    log_file = f"activity_{username}.txt"
    with open(log_file, "a") as f:
        f.write(f"{username} | {action} | {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

# ---------------- STYLING ----------------
st.markdown("""
<style>
body {
    background-color: #f9fafb;
    font-family: 'Poppins', sans-serif;
}
h1, h2, h3 {
    color: #004a57;
}
div.stButton > button {
    background-color: #004a57;
    color: white;
    border: none;
    padding: 8px 18px;
    border-radius: 8px;
    font-weight: 500;
}
div.stButton > button:hover {
    background-color: #00797b;
    transform: scale(1.03);
}
footer {
    position: fixed;
    bottom: 0;
    left: 0;
    width: 100%;
    text-align: center;
    background-color: #004a57;
    color: white;
    padding: 8px;
    font-size: 13px;
}
</style>
""", unsafe_allow_html=True)

# ---------------- SESSION SETUP ----------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = ""
if "last_active" not in st.session_state:
    st.session_state.last_active = time.time()

# ---------------- AUTO LOGOUT FEATURE ----------------
SESSION_TIMEOUT = 300  # 5 minutes
if st.session_state.logged_in:
    now = time.time()
    if now - st.session_state.last_active > SESSION_TIMEOUT:
        st.warning("⚠️ Session expired due to inactivity. Please login again.")
        log_activity("Session Expired", st.session_state.username)
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.session_state.last_active = time.time()
        st.stop()

# ---------------- NAVIGATION ----------------
menu = ["🏠 Home", "📝 Register", "🔐 Login", "🔒 Encrypt", "🔓 Decrypt", "📊 Activity", "🔢 Input Validation"]

choice = st.sidebar.radio("Navigate", menu)

# Sidebar user info
if st.session_state.logged_in:
    st.sidebar.markdown(f"👋 Logged in as: **{st.session_state.username}**")
    if st.sidebar.button("🚪 Logout"):
        log_activity("Logged Out", st.session_state.username)
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.success("✅ You have been logged out successfully.")
        st.stop()

# ---------------- HOME ----------------
if choice == "🏠 Home":
    st.title("💳 Welcome to Noori's 🥷🏻 FinTech")
    st.write("""
    A secure and simple FinTech app developed to demonstrate **cybersecurity practices** in modern finance systems.
    
    ✅ Secure Registration & Login  
    ✅ Password Encryption using Fernet  
    ✅ Data Validation & Error Handling  
    ✅ Audit Logging & Activity Dashboard
    """)
    st.success("Your privacy and data security are our top priorities!")

# ---------------- REGISTER ----------------
elif choice == "📝 Register":
    st.title("Create Account 📝")

    username = st.text_input("Username")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")
    confirm = st.text_input("Confirm Password", type="password")

    if st.button("Register"):
        st.session_state.last_active = time.time()
        users = load_users()

        email_pattern = r'^[\\w\\.-]+@[\\w\\.-]+\\.\\w+$'
        if username in users:
            st.warning("⚠️ Username already exists.")
        elif not username or not email or not password or not confirm:
            st.warning("⚠️ Please fill in all fields.")
        elif not re.match(email_pattern, email):
            st.warning("⚠️ Invalid email format.")
        elif password != confirm:
            st.error("❌ Passwords do not match.")
        elif len(password) < 8 or not any(char.isdigit() for char in password) or not any(char.isalpha() for char in password):
            st.warning("⚠️ Password must be at least 8 characters and contain both letters and numbers.")
        else:
            encrypted_pw, key = encrypt_password(password)
            save_user(username, email, encrypted_pw, key)
            st.success(f"✅ Account created successfully for {username}!")
            st.info("💾 Please copy and save your encryption key below:")
            st.code(key)
            log_activity("Registered", username)

# ---------------- LOGIN ----------------
elif choice == "🔐 Login":
    st.title("User Login 🔐")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if "login_attempts" not in st.session_state:
        st.session_state.login_attempts = 0

    if st.button("Login"):
        st.session_state.last_active = time.time()
        users = load_users()

        if st.session_state.login_attempts >= 3:
            st.error("🚫 Account temporarily locked after 3 failed attempts.")
            st.stop()

        if username in users:
            data = users[username]
            decrypted_pw = decrypt_password(data["password"], data["key"])
            if decrypted_pw and password == decrypted_pw:
                st.session_state.logged_in = True
                st.session_state.username = username
                st.session_state.last_active = time.time()
                st.session_state.login_attempts = 0
                st.success(f"✅ Welcome, {username}!")
                log_activity("Logged In", username)
            else:
                st.session_state.login_attempts += 1
                st.warning(f"❌ Invalid password. Attempt {st.session_state.login_attempts}/3")
                if st.session_state.login_attempts >= 3:
                    st.error("🚫 Account locked after 3 failed attempts.")
                    log_activity("Account Locked", username)
        else:
            st.error("❌ Username not found.")

# ---------------- ENCRYPT ----------------
elif choice == "🔒 Encrypt":
    st.title("Encrypt Your Data 🔐")

    if not st.session_state.logged_in:
        st.warning("⚠️ Please login first!")
        st.stop()

    text = st.text_area("Enter text to encrypt:")
    if st.button("Encrypt"):
        st.session_state.last_active = time.time()
        if text.strip() == "":
            st.warning("⚠️ Please enter some text.")
        else:
            key = Fernet.generate_key()
            cipher = Fernet(key)
            encrypted_text = cipher.encrypt(text.encode()).decode()
            st.success("✅ Data Encrypted Successfully!")
            st.text_area("Encrypted Text:", encrypted_text, height=150)
            st.info("💾 Save this encryption key safely:")
            st.code(key.decode())
            log_activity("Encrypted Data", st.session_state.username)

# ---------------- DECRYPT ----------------
elif choice == "🔓 Decrypt":
    st.title("Decrypt Your Data 🔓")

    if not st.session_state.logged_in:
        st.warning("⚠️ Please login first!")
        st.stop()

    encrypted_text = st.text_area("Enter encrypted text:")
    key_input = st.text_input("Enter encryption key:")

    if st.button("Decrypt"):
        st.session_state.last_active = time.time()
        if not encrypted_text or not key_input:
            st.warning("⚠️ Please enter both fields.")
        else:
            try:
                cipher = Fernet(key_input.encode())
                decrypted_text = cipher.decrypt(encrypted_text.encode()).decode()
                st.success("✅ Decryption Successful!")
                st.text_area("Decrypted Text:", decrypted_text, height=150)
                log_activity("Decrypted Data", st.session_state.username)
            except Exception:
                st.error("⚠️ Decryption failed. Invalid key or text.")

# ---------------- ACTIVITY ----------------
elif choice == "📊 Activity":
    st.title("📊 User Activity Dashboard")

    if not st.session_state.get("logged_in"):
        st.warning("⚠️ Please login first!")
        st.stop()

    username = st.session_state.get("username", "")
    user_log = f"activity_{username}.txt"

    if not os.path.exists(user_log):
        st.info("No activity yet.")
    else:
        with open(user_log, "r") as f:
            lines = [line.strip() for line in f.readlines() if line.strip()]

        if not lines:
            st.info("No recorded activity yet.")
        else:
            actions = {"Registered": 0, "Logged In": 0, "Encrypted Data": 0, "Decrypted Data": 0, "Logged Out": 0, "Session Expired": 0}
            for line in lines:
                for key in actions.keys():
                    if key in line:
                        actions[key] += 1

            st.subheader("📘 Recent Activity Log (Last 10 Actions)")
            for line in lines[-10:]:
                st.write("🕓", line)

            fig = px.bar(
                x=list(actions.keys()),
                y=list(actions.values()),
                labels={'x': 'Action Type', 'y': 'Count'},
                text=list(actions.values()),
                title=f"{username}'s Activity Summary",
                color=list(actions.keys()),
                color_discrete_sequence=px.colors.sequential.Tealgrn,
            )
            fig.update_traces(textposition='outside')
            st.plotly_chart(fig, use_container_width=True)

# ---------------- INPUT VALIDATION ----------------
elif choice == "🔢 Input Validation":
    st.title("🔢 Input Validation Test")

    amount = st.text_input("Enter Transaction Amount:")
    if st.button("Submit"):
        if not amount.isdigit():
            st.warning("⚠️ Please enter a valid number!")
        else:
            st.success(f"✅ Transaction amount {amount} accepted!")

# ---------------- FOOTER ----------------
st.markdown("""
<footer>
Developed with ❤️ by <b>Norain Gillani</b> | Noori's 🥷🏻 FinTech ©️ 2025
</footer>
""", unsafe_allow_html=True)
