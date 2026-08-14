def _generate_matrix(key):
    """Generates the 5x5 Playfair cipher matrix based on a key."""
    key = key.upper().replace('J', 'I')
    matrix = []
    used = set()

    for char in key:
        if char.isalpha() and char not in used:
            matrix.append(char)
            used.add(char)

    for i in range(26):
        char = chr(ord('A') + i)
        if char == 'J':
            continue
        if char not in used:
            matrix.append(char)
            used.add(char)

    return [matrix[i:i + 5] for i in range(0, 25, 5)]

def _find_position(matrix, char):
    for i, row in enumerate(matrix):
        if char in row:
            return i, row.index(char)
    return -1, -1

def _prepare_text(text):
    text = "".join(filter(str.isalpha, text.upper())).replace('J', 'I')
    result = []
    i = 0
    while i < len(text):
        a = text[i]
        if i + 1 < len(text):
            b = text[i + 1]
            if a == b:
                result.append(a + 'X')
                i += 1
            else:
                result.append(a + b)
                i += 2
        else:
            result.append(a + 'X')
            i += 1
    return result

def _playfair_process(text, key, encrypt=True):
    matrix = _generate_matrix(key)
    pairs = _prepare_text(text)
    result = []

    shift = 1 if encrypt else -1

    for a, b in pairs:
        r1, c1 = _find_position(matrix, a)
        r2, c2 = _find_position(matrix, b)

        if r1 == r2:
            result.append(matrix[r1][(c1 + shift) % 5] + matrix[r2][(c2 + shift) % 5])
        elif c1 == c2:
            result.append(matrix[(r1 + shift) % 5][c1] + matrix[(r2 + shift) % 5][c2])
        else:
            result.append(matrix[r1][c2] + matrix[r2][c1])

    return "".join(result)

def encrypt_playfair(text, key):
    """Encrypts text using Playfair Cipher."""
    return _playfair_process(text, key, encrypt=True)

def decrypt_playfair(text, key):
    """Decrypts text using Playfair Cipher."""
    # During decryption we pass the ciphertext (already prepared)
    # However we might need to handle 'X' characters manually after decryption if they were padded.
    decrypted = _playfair_process(text, key, encrypt=False)
    # Note: removing 'X' perfectly is ambiguous without knowing the original text length/content, 
    # so we return the raw decrypted pairs.
    return decrypted
