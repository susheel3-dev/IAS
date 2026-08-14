def encrypt_caesar(text, shift):
    """Encrypts text using Caesar Cipher."""
    result = []
    for char in text:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - start + shift) % 26 + start))
        else:
            result.append(char)
    return "".join(result)

def decrypt_caesar(text, shift):
    """Decrypts text using Caesar Cipher."""
    return encrypt_caesar(text, -shift)
