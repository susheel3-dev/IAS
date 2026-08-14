# SDES (Simplified DES) implementation for bytes

# Permutation Tables
P10 = [2, 4, 1, 6, 3, 9, 0, 8, 7, 5]
P8 = [5, 2, 6, 3, 7, 4, 9, 8]
IP = [1, 5, 2, 0, 3, 7, 4, 6]
IP_INV = [3, 0, 2, 4, 6, 1, 7, 5]
EP = [3, 0, 1, 2, 1, 2, 3, 0]
P4 = [1, 3, 2, 0]

S0 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 2]
]

S1 = [
    [0, 1, 2, 3],
    [2, 0, 1, 3],
    [3, 0, 1, 0],
    [2, 1, 0, 3]
]

def permute(bits, mapping):
    return [bits[i] for i in mapping]

def left_shift(bits, shifts):
    return bits[shifts:] + bits[:shifts]

def xor(bits1, bits2):
    return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

def generate_keys(key_10bit):
    # key_10bit is a list of 10 bits (0s and 1s)
    p10_key = permute(key_10bit, P10)
    left_half = p10_key[:5]
    right_half = p10_key[5:]

    # LS-1
    left_half = left_shift(left_half, 1)
    right_half = left_shift(right_half, 1)
    k1 = permute(left_half + right_half, P8)

    # LS-2
    left_half = left_shift(left_half, 2)
    right_half = left_shift(right_half, 2)
    k2 = permute(left_half + right_half, P8)

    return k1, k2

def sbox_lookup(sbox, bits):
    row = (bits[0] << 1) | bits[3]
    col = (bits[1] << 1) | bits[2]
    val = sbox[row][col]
    return [(val >> 1) & 1, val & 1]

def f_k(bits, key):
    left = bits[:4]
    right = bits[4:]

    ep = permute(right, EP)
    xored = xor(ep, key)

    s0_out = sbox_lookup(S0, xored[:4])
    s1_out = sbox_lookup(S1, xored[4:])

    p4_out = permute(s0_out + s1_out, P4)
    return xor(left, p4_out) + right

def encrypt_byte(byte_val, k1, k2):
    bits = [(byte_val >> (7 - i)) & 1 for i in range(8)]
    bits = permute(bits, IP)

    # Round 1
    bits = f_k(bits, k1)

    # Swap
    bits = bits[4:] + bits[:4]

    # Round 2
    bits = f_k(bits, k2)

    bits = permute(bits, IP_INV)

    out_byte = 0
    for b in bits:
        out_byte = (out_byte << 1) | b
    return out_byte

def decrypt_byte(byte_val, k1, k2):
    # Decryption uses K2 then K1
    bits = [(byte_val >> (7 - i)) & 1 for i in range(8)]
    bits = permute(bits, IP)

    bits = f_k(bits, k2)
    bits = bits[4:] + bits[:4]
    bits = f_k(bits, k1)

    bits = permute(bits, IP_INV)

    out_byte = 0
    for b in bits:
        out_byte = (out_byte << 1) | b
    return out_byte

def encrypt_sdes_bytes(data: bytes, key_10bit: list) -> bytes:
    """Encrypts a byte array using SDES."""
    k1, k2 = generate_keys(key_10bit)
    return bytes(encrypt_byte(b, k1, k2) for b in data)

def decrypt_sdes_bytes(data: bytes, key_10bit: list) -> bytes:
    """Decrypts a byte array using SDES."""
    k1, k2 = generate_keys(key_10bit)
    return bytes(decrypt_byte(b, k1, k2) for b in data)
