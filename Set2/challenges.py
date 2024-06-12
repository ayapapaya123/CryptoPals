from collections import Counter
import random
from typing import Tuple
from Crypto.Cipher import AES
from Set1.challenges import fixed_xor, encrypt_aes_in_ecb_mode, decrypt_aes_in_ecb_mode
from secrets import token_bytes

def pkcs7_pad(text: bytes, block_size: int = 16):
    """ Challenge 9
    Pads text out to an even multiple of block_size bytes using PKCS#7
    """
    if type(block_size) != int or block_size <= 0:
        raise ValueError("Block size must be a positive integer")
    if len(text) % block_size == 0:
        pad_length = 0
    else:
        pad_length = block_size - len(text) % block_size
    return text + bytes([pad_length]) * pad_length

def pkcs7_unpad(text: bytes):
    last_byte = text[-1]
    for char in text[-1:-last_byte - 1:-1]:
        if char != last_byte:
            return text
    return text[:-last_byte]

def bytes_to_padded_blocks(bytes_obj, block_size=16):
    padded_bytes = pkcs7_pad(bytes_obj, block_size)
    return [padded_bytes[index:index+block_size] for index in range(0, len(bytes_obj), block_size)]


def encrypt_aes_cbc_mode(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """ encrypt a message using AES in CBC mode

    Args:
        plaintext (bytes): bytes to encrypt
        key (bytes): key we xor with
        iv (bytes): Initialization vector, used as the fake 0th block when treating the actual first block
    
    Returns:
        bytes: The Encrypted bytes
    """
    assert len(key) == len(iv), "Key and initialization vector must be same size"
    plaintext_blocks = bytes_to_padded_blocks(plaintext, len(key))

    ciphertext = b''
    xor_with = iv # Initially we XOR plaintext with IV
    # For each block, xor plaintext with xor_with, then encrypt and append to ciphertext.
    # Each successive plaintext block is XORed with the previous ciphertext block before encryption.
    for plaintext_block in plaintext_blocks:
        ciphertext_block = encrypt_aes_in_ecb_mode(fixed_xor(plaintext_block, xor_with), key)
        ciphertext += ciphertext_block
        xor_with = ciphertext_block
    return ciphertext


def decrypt_aes_cbc_mode(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """ decrypt a message using AES in CBC mode

    Args:
        ciphertext (bytes): bytes to decrypt
        key (bytes): key we xor with
        iv (bytes): Initialization vector, used as the fake 0th block when treating the actual first block
    
    Returns:
        bytes: The decrypted bytes
    """
    assert len(key) == len(iv), "Key and initialization vector must be same size"
    
    ciphertext_blocks = bytes_to_padded_blocks(plaintext, len(key))
    plaintext = b''
    xor_with = iv # Initially we XOR ciphertext with IV
    # For each block, xor ciphertext with xor_with, then encrypt and append to plaintext.
    # Each successive ciphertext block is XORed with the previous ciphertext block before decryption.
    for ciphertext_block in ciphertext_blocks:
        # ciphertext_block = decrypt_aes_cbc_mode(fixed_xor(ciphertext_block, xor_with), key)
        plaintext_block = fixed_xor(decrypt_aes_in_ecb_mode(ciphertext_block, key), xor_with)
        plaintext += plaintext_block
        xor_with = ciphertext_block
    return plaintext


def generate_random_aes_key(key_length:int = 16) -> bytes:
    """Challenge 11
    Generate a random key for AES encryption

    Args:
        key_length (int, optional): Length of the key. Defaults to 16.

    Returns:
        bytes: Generated Key
    """
    return token_bytes(key_length)

def _generate_random_bytes(min_len: int = 5, max_len: int = 10) -> bytes:
    bytes_length = random.randint(min_len, max_len)
    return token_bytes(bytes_length)

def encryption_oracle(plaintext: bytes) -> bytes:
    """Challenge 11
    A function which has a 50% probability of encrypting with ECB and 50% probability of encrypting with CBC

    Args:
        plaintext (bytes): bytes we will encrypt
    
    Returns:
        bytes: Encrypted plaintext
    """
    key = generate_random_aes_key()
    plaintext = _generate_random_bytes() + plaintext + _generate_random_bytes()

    if random.randint(0, 1) % 2 == 0:
        return "CBC", encrypt_aes_cbc_mode(plaintext, key, generate_random_aes_key())
    return "ECB", encrypt_aes_in_ecb_mode(plaintext, key)
    

def detect_ecb_or_cbc(oracle_function) -> tuple[str, str]:
    """Detects if a black box function is encypting with AES in ECB or CDC mode

    Args:
        oracle_function (function): function acting as a black box which might be encrypting with ECB or CDC 

    Returns:
        str: Tuple of our result and the debug cheat from the oracle function,
            Sould look like ("CBC", "CBC") or using ECB
    """
    # We are using repeating plaintext since ECB is stateless and deterministic and will result in a repeating 
    # ciphertext (idea from challenge 8)
    ciphertext, oracle_method = oracle_function(b'a' * 64)
    blocks = [ciphertext[start:start+16] for start in range(0, len(ciphertext), 16)]
    count = Counter(blocks)
    if max(count.values()) > 1:
        return "ECB", oracle_method
    return "CBC", oracle_method