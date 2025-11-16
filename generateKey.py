from cryptography.fernet import Fernet

#Generate new key
key = Fernet.generate_key()

#Save key to file
with open("secret.key", "wb") as key_file:
    key_file.write(key)

print("Key generated and saved to secret.key")
print("IMPORTANT: Keep this file safe and do NOT add it to version control (e.g., Git).")