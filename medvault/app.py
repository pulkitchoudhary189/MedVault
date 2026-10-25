import streamlit as st
import uuid
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

# --- 1. CRYPTO ENGINE LAYOUT ---
SALT = b'\x86\x19\xda\xbf\x95\x8b\x90\xdd'

def derive_key(password: str) -> bytes:
    return PBKDF2(password.encode(), SALT, dkLen=32, count=100000, hmac_hash_module=SHA256)

def encrypt_file_data(file_bytes: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(file_bytes)
    return ciphertext, cipher.nonce, tag

def decrypt_file_data(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# --- 2. SIMULATED MOCK DATABASE STATE ---
# Streamlit re-runs the script on input change. We use st.session_state to persist records.
if "db" not in st.session_state:
    st.session_state.db = {}

# --- 3. UI ELEMENT CONFIGURATION ---
st.set_page_config(page_title="MedVault Streamlit Engine", page_icon="🔒")
st.title("🔒 MedVault: Zero-Knowledge Health Locker")

password = st.sidebar.text_input("Enter Vault Master Key", type="password")

if not password:
    st.info("💡 Please provide a Master Key in the left sidebar to access your vault controls.")
else:
    # Key is derived in local transient system RAM memory
    local_key = derive_key(password)
    st.sidebar.success("Vault Encryption Key Active")

    tab1, tab2 = st.tabs(["📤 Secure & Upload Record", "📥 Fetch & Decrypt Record"])

    with tab1:
        st.subheader("Encrypt Document Metadata")
        uploaded_file = st.file_uploader("Select Medical File Payload", type=["pdf", "png", "jpg", "txt"])

        if uploaded_file and st.button("🔒 Encrypt and Save"):
            raw_bytes = uploaded_file.read()
            filename = uploaded_file.name

            # Encrypt locally inside memory allocation
            ciphertext, nonce, tag = encrypt_file_data(raw_bytes, local_key)
            doc_id = str(uuid.uuid4())

            # Commit to our simulated state database directory
            st.session_state.db[doc_id] = {
                "ciphertext": ciphertext,
                "nonce": nonce,
                "tag": tag,
                "filename": filename
            }

            st.success("🎉 File successfully encrypted into raw binary noise!")
            st.write("📋 Copy this unique Secure Document ID:")
            st.code(doc_id)

    with tab2:
        st.subheader("Decrypt Storage Payload")
        search_id = st.text_input("Paste target Secure ID String").strip()

        if search_id and st.button("🔓 Fetch and Decrypt"):
            if search_id not in st.session_state.db:
                st.error("❌ Document ID not found in current database engine registry.")
            else:
                record = st.session_state.db[search_id]

                try:
                    # Attempt local decryption handshake pass
                    decrypted_data = decrypt_file_data(
                        record["ciphertext"], 
                        local_key, 
                        record["nonce"], 
                        record["tag"]
                    )
                    st.success("🎉 Decryption Successful! Raw file extracted securely.")
                    st.download_button(
                        label=f"💾 Download {record['filename']}",
                        data=decrypted_data,
                        file_name=f"recovered_{record['filename']}"
                    )
                except Exception:
                    st.error("❌ Decryption Failed! Invalid master password or corrupted payload file.")
