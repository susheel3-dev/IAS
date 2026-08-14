import socket
import os
import time
from ciphers import encrypt_caesar, decrypt_caesar
from ciphers import encrypt_playfair, decrypt_playfair
from ciphers import encrypt_sdes_bytes, decrypt_sdes_bytes

HOST = '127.0.0.1'
PORT = 5000

CAESAR_SHIFT = 3
PLAYFAIR_KEY = "SECRETKEY"
SDES_KEY = [1, 0, 1, 0, 0, 0, 0, 0, 1, 0]

def recv_all(conn, length):
    data = b""
    while len(data) < length:
        packet = conn.recv(length - len(data))
        if not packet:
            break
        data += packet
    return data

def main():
    while True:
        print("\n--- Active Learning Management (ALM) ---")
        print("1. Caesar Cipher")
        print("2. Playfair Cipher")
        print("3. SDES (1MB file transfer)")
        print("4. Exit")
        choice = input("Choose an option: ")
        
        if choice == '4':
            break
            
        if choice not in ['1', '2', '3']:
            print("Invalid option.")
            continue
            
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.connect((HOST, PORT))
            except ConnectionRefusedError:
                print("Server is not running.")
                continue
                
            s.sendall(choice.encode('utf-8'))
            
            if choice == '1':
                msg = input("Enter message to encrypt (Caesar): ")
                ciphertext = encrypt_caesar(msg, CAESAR_SHIFT)
                print(f"Client Ciphertext: {ciphertext}")
                s.sendall(ciphertext.encode('utf-8'))
                
                reply_cipher = s.recv(1024).decode('utf-8')
                print(f"Received Server Reply Ciphertext: {reply_cipher}")
                reply_plain = decrypt_caesar(reply_cipher, CAESAR_SHIFT)
                print(f"Decrypted Server Reply Plaintext: {reply_plain}")
                
            elif choice == '2':
                msg = input("Enter message to encrypt (Playfair): ")
                ciphertext = encrypt_playfair(msg, PLAYFAIR_KEY)
                print(f"Client Ciphertext: {ciphertext}")
                s.sendall(ciphertext.encode('utf-8'))
                
                reply_cipher = s.recv(1024).decode('utf-8')
                print(f"Received Server Reply Ciphertext: {reply_cipher}")
                reply_plain = decrypt_playfair(reply_cipher, PLAYFAIR_KEY)
                print(f"Decrypted Server Reply Plaintext: {reply_plain}")
                
            elif choice == '3':
                file_1mb = "file_1mb.txt"
                if not os.path.exists(file_1mb):
                    print("Generating 1MB file...")
                    with open(file_1mb, "w") as f:
                        f.write("Client data block 1MB. " * (1048576 // 23))
                
                with open(file_1mb, "rb") as f:
                    data_1mb = f.read()
                
                print("Encrypting 1MB file (this might take a few seconds)...")
                start_time = time.time()
                cipher_1mb = encrypt_sdes_bytes(data_1mb, SDES_KEY)
                print(f"Encryption took {time.time() - start_time:.2f} seconds.")
                
                print(f"1MB Plaintext (first 50 chars): {data_1mb[:50].decode('utf-8', errors='ignore')}")
                print(f"1MB Ciphertext (first 50 bytes): {cipher_1mb[:50].hex()}")
                
                s.sendall(str(len(cipher_1mb)).encode('utf-8'))
                s.recv(1024) # wait for OK
                s.sendall(cipher_1mb)
                
                # Receive 10KB file from server
                size_data = s.recv(1024)
                if not size_data: continue
                file_size = int(size_data.decode('utf-8'))
                s.sendall(b"OK")
                
                print(f"\nReceiving {file_size} bytes (10KB file) from server...")
                ciphertext_10kb = recv_all(s, file_size)
                print(f"Received 10KB Ciphertext (first 50 bytes): {ciphertext_10kb[:50].hex()}")
                
                print("Decrypting 10KB file...")
                plaintext_10kb = decrypt_sdes_bytes(ciphertext_10kb, SDES_KEY)
                print(f"Decrypted 10KB Plaintext (first 50 chars): {plaintext_10kb[:50].decode('utf-8', errors='ignore')}")
                
                with open("decrypted_10kb.txt", "wb") as f:
                    f.write(plaintext_10kb)

if __name__ == "__main__":
    main()
