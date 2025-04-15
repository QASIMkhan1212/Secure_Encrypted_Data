# import streamlit as st
# import hashlib
# from cryptography.fernet import Fernet

# # Generate a key (this should be stored securely in production)
# KEY = Fernet.generate_key()
# cipher = Fernet(KEY)

# # In-memory data storage
# stored_data = {}  # {"user1_data": {"encrypted_text": "xyz", "passkey": "hashed"}}
# failed_attempts = 0

# # Function to hash passkey
# def hash_passkey(passkey):
#     return hashlib.sha256(passkey.encode()).hexdigest()

# # Function to encrypt data
# def encrypt_data(text, passkey):
#     return cipher.encrypt(text.encode()).decode()

# # Function to decrypt data
# def decrypt_data(encrypted_text, passkey):
#     global failed_attempts  # Declare global variable at the top
#     hashed_passkey = hash_passkey(passkey)

#     for key, value in stored_data.items():
#         if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
#             failed_attempts = 0
#             return cipher.decrypt(encrypted_text.encode()).decode()
    
#     failed_attempts += 1
#     return None

# # Streamlit UI
# st.title("🔒 Secure Data Encryption System")

# # Navigation
# menu = ["Home", "Store Data", "Retrieve Data", "Login"]
# choice = st.sidebar.selectbox("Navigation", menu)

# if choice == "Home":
#     st.subheader("🏠 Welcome to the Secure Data System")
#     st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

# elif choice == "Store Data":
#     st.subheader("📂 Store Data Securely")
#     user_data = st.text_area("Enter Data:")
#     passkey = st.text_input("Enter Passkey:", type="password")

#     if st.button("Encrypt & Save"):
#         if user_data and passkey:
#             hashed_passkey = hash_passkey(passkey)
#             encrypted_text = encrypt_data(user_data, passkey)
#             stored_data[encrypted_text] = {"encrypted_text": encrypted_text, "passkey": hashed_passkey}
#             st.success("✅ Data stored securely!")
#         else:
#             st.error("⚠️ Both fields are required!")

# elif choice == "Retrieve Data":
#     st.subheader("🔍 Retrieve Your Data")
#     encrypted_text = st.text_area("Enter Encrypted Data:")
#     passkey = st.text_input("Enter Passkey:", type="password")

#     if st.button("Decrypt"):
#         if encrypted_text and passkey:
#             decrypted_text = decrypt_data(encrypted_text, passkey)

#             if decrypted_text:
#                 st.success(f"✅ Decrypted Data: {decrypted_text}")
#             else:
#                 st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - failed_attempts}")

#                 if failed_attempts >= 3:
#                     st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
#                     st.experimental_rerun()
#         else:
#             st.error("⚠️ Both fields are required!")

# elif choice == "Login":
#     st.subheader("🔑 Reauthorization Required")
#     login_pass = st.text_input("Enter Master Password:", type="password")

#     if st.button("Login"):
#         if login_pass == "admin123":  # Hardcoded for demo, replace with proper auth
        
#             failed_attempts = 0
#             st.success("✅ Reauthorized successfully! Redirecting to Retrieve Data...")
#             st.experimental_rerun()
#         else:
#             st.error("❌ Incorrect password!")

import streamlit as st
import hashlib
import json
from cryptography.fernet import Fernet
from hashlib import pbkdf2_hmac  # Import PBKDF2 for secure password hashing

# Generate a key (this should be stored securely in production)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# File to store encrypted data
DATA_FILE = "stored_data.json"

# Load data from JSON file
def load_data():
    try:
        with open(DATA_FILE, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return {}

# Save data to JSON file
def save_data(data):
    with open(DATA_FILE, "w") as file:
        json.dump(data, file)

# Load data on app startup
stored_data = load_data()

# Function to hash passkey using PBKDF2
def hash_passkey(passkey, salt="default_salt"):
    """
    Hashes the passkey using PBKDF2 with SHA-256, a salt, and 100,000 iterations.
    """
    return pbkdf2_hmac("sha256", passkey.encode(), salt.encode(), 100000).hex()

# Function to encrypt data
def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text, passkey):
    global failed_attempts  # Declare global variable at the top
    hashed_passkey = hash_passkey(passkey)

    for key, value in stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    
    failed_attempts += 1
    return None

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data, passkey)
            stored_data[encrypted_text] = {"encrypted_text": encrypted_text, "passkey": hashed_passkey}
            save_data(stored_data)  # Save updated data to JSON file
            st.success("✅ Data stored securely!")
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    encrypted_text = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            decrypted_text = decrypt_data(encrypted_text, passkey)

            if decrypted_text:
                st.success(f"✅ Decrypted Data: {decrypted_text}")
            else:
                st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - failed_attempts}")

                if failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # Hardcoded for demo, replace with proper auth
            failed_attempts = 0
            st.success("✅ Reauthorized successfully! Redirecting to Retrieve Data...")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password!")