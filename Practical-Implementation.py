import time
import hmac
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import sys

# Step 1: Alice's side - Generating RSA keys for Digital Signature (DS)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Step 2: Alice's side - Input for message and nonce
message = input("Enter the message: ").encode()  # Taking user input for message
nonce = input("Enter the nonce: ")               # Taking user input for nonce

# Generate timestamp for the message
timestamp = time.time()

# HMAC for MAC solution (MAC binds message + nonce + timestamp)
shared_secret_key = b'secret_shared_key'
mac_data = message + nonce.encode() + str(timestamp).encode()
mac = hmac.new(shared_secret_key, mac_data, hashlib.sha256).hexdigest()

# Digital Signature (DS) binds message + nonce + timestamp
signature = private_key.sign(
    mac_data,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256()
)

# Alice sends the message, nonce, timestamp, and auth(x) (MAC or DS) to Bob
# Transmission: [message, nonce, timestamp, mac, signature]
print("\n--- Sending data from Alice to Bob ---")
print(f"Message: {message.decode()}")
print(f"Nonce: {nonce}")
print(f"Timestamp: {timestamp}")
print(f"MAC: {mac}")
print(f"Signature: {signature.hex()}\n")

# ----------------------------------------------
# Step 3: Bob's side - Verification process
# ----------------------------------------------
def verify_mac(message, nonce, timestamp, received_mac):
    """Verify the HMAC for message authenticity and integrity."""
    mac_data = message + nonce.encode() + str(timestamp).encode()
    mac_check = hmac.new(shared_secret_key, mac_data, hashlib.sha256).hexdigest()
    return received_mac == mac_check

def verify_signature(message, nonce, timestamp, signature):
    """Verify the Digital Signature for authenticity and integrity."""
    try:
        mac_data = message + nonce.encode() + str(timestamp).encode()
        public_key.verify(
            signature,
            mac_data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Signature verification error: {e}")
        return False

# Step 4: Bob receives the data and verifies it
current_time = time.time()
time_window = 10  # Allowable time window for timestamp (in seconds)

print("--- Bob's Verification ---")
if abs(current_time - timestamp) < time_window:  # Timestamp validation
    # Verify MAC
    if verify_mac(message, nonce, timestamp, mac):
        print("\nMAC verified: Message is authentic and within time window.")
    else:
        print("\nMAC verification failed or message is a replay.")

    # Verify Digital Signature
    if verify_signature(message, nonce, timestamp, signature):
        print("DS verified: Message is authentic and within time window.")
        # Print the received message and nonce
        print(f"Verified Message: {message.decode()}")
        print(f"Verified Nonce: {nonce}")
    else:
        print("DS verification failed or message is a replay.")
else:
    print("\nMessage is too old or potentially replayed.")
