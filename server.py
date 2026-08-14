import socket
import os
from ciphers import decrypt_caesar, encrypt_caesar
from ciphers import decrypt_playfair, encrypt_playfair
from ciphers import decrypt_sdes_bytes, encrypt_sdes_bytes

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
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server listening on {HOST}:{PORT}")
        
        while True:
            conn, addr = s.accept()
            with conn:
                print(f"Connected by {addr}")
                
                # Receive option
                option = conn.recv(1024).decode('utf-8')
                if not option:
                    continue
                
                if option == '1':
                    print("\n--- Caesar Cipher ---")
                    ciphertext = conn.recv(1024).decode('utf-8')
                    print(f"Received Ciphertext: {ciphertext}")
                    plaintext = decrypt_caesar(ciphertext, CAESAR_SHIFT)
                    print(f"Decrypted Plaintext: {plaintext}")
                    
                    reply = "Message received successfully"
                    reply_cipher = encrypt_caesar(reply, CAESAR_SHIFT)
                    print(f"Sending Reply Plaintext: {reply}")
                    print(f"Sending Reply Ciphertext: {reply_cipher}")
                    conn.sendall(reply_cipher.encode('utf-8'))
                    
                elif option == '2':
                    print("\n--- Playfair Cipher ---")
                    ciphertext = conn.recv(1024).decode('utf-8')
                    print(f"Received Ciphertext: {ciphertext}")
                    plaintext = decrypt_playfair(ciphertext, PLAYFAIR_KEY)
                    print(f"Decrypted Plaintext: {plaintext}")
                    
                    reply = "PLAYFAIRACKNOWLEDGE"
                    reply_cipher = encrypt_playfair(reply, PLAYFAIR_KEY)
                    print(f"Sending Reply Plaintext: {reply}")
                    print(f"Sending Reply Ciphertext: {reply_cipher}")
                    conn.sendall(reply_cipher.encode('utf-8'))
                    
                elif option == '3':
                    print("\n--- SDES File Transfer ---")
                    # Receive size of incoming 1MB file
                    size_data = conn.recv(1024)
                    if not size_data: continue
                    file_size = int(size_data.decode('utf-8'))
                    conn.sendall(b"OK")
                    
                    print(f"Receiving {file_size} bytes...")
                    ciphertext = recv_all(conn, file_size)
                    print(f"Received Ciphertext (first 50 bytes): {ciphertext[:50].hex()}")
                    
                    print("Decrypting 1MB file...")
                    plaintext = decrypt_sdes_bytes(ciphertext, SDES_KEY)
                    print(f"Decrypted Plaintext (first 50 chars): {plaintext[:50].decode('utf-8', errors='ignore')}")
                    
                    with open("decrypted_1mb.txt", "wb") as f:
                        f.write(plaintext)
                    
                    # Generate 10KB file to send back
                    file_10kb = "file_10kb.txt"
                    if not os.path.exists(file_10kb):
                        with open(file_10kb, "w") as f:
                            f.write("Server data block 10KB. " * (10240 // 24))
                    
                    with open(file_10kb, "rb") as f:
                        data_10kb = f.read()
                    
                    print("\nEncrypting 10KB file to send to client...")
                    cipher_10kb = encrypt_sdes_bytes(data_10kb, SDES_KEY)
                    print(f"10KB Plaintext (first 50 chars): {data_10kb[:50].decode('utf-8', errors='ignore')}")
                    print(f"10KB Ciphertext (first 50 bytes): {cipher_10kb[:50].hex()}")
                    
                    conn.sendall(str(len(cipher_10kb)).encode('utf-8'))
                    conn.recv(1024) # wait for OK
                    conn.sendall(cipher_10kb)
                    print("10KB file sent.")

if __name__ == "__main__":
    main()
