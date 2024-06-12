from base64 import b64encode
from Set1.challenge_consts import letterFrequency
import binascii
import string
import base64
from Crypto.Cipher import AES
from collections import Counter


def hex_to_base64(hex_string: str) -> str:
    return b64encode(bytes.fromhex(hex_string)).decode()

def xor(first_string, second_string):
    res = hex(int (first_string, 16) ^ int(second_string, 16))
    return res[2:]

def fixed_xor(bytes1, bytes2):
    assert len(bytes1) == len(bytes2), "You must pass equal-length objects"
    return bytes().join([bytes([a ^ b]) for a, b in zip(bytes1, bytes2)])


def single_byte_xor_cryptanalysis(ciphertext):
    plaintexts_dict = {}  # Holds each candidate plaintext and its score
    keys_dict = {}  # Holds each candidate key and its score

    len_ciphertext = len(ciphertext)
    for key_byte in range(256):
        key = bytes([key_byte]) * len_ciphertext
        candidate_plaintext = fixed_xor(ciphertext, key)

        score = detect_plaintext(candidate_plaintext)
        plaintexts_dict[candidate_plaintext] = score
        keys_dict[key_byte] = score
    return max(plaintexts_dict, key=plaintexts_dict.get), \
           max(keys_dict, key=keys_dict.get), \
           max(plaintexts_dict.values())


def detect_plaintext(candidate_plaintext):
    score = float(0)
    for pt_byte in candidate_plaintext:
        c = chr(pt_byte)
        if c in string.ascii_lowercase:
            score += letterFrequency[c]
        # Upper-case letters count slightly less than lower-case
        if c in string.ascii_uppercase:
            score += letterFrequency[c.lower()] * 0.75
    score /= len(candidate_plaintext)  # Normalize score over length of plaintext
    # Decrement score by 5% for every character that is not a letter, number, or common punctuation
    for pt_byte in candidate_plaintext:
        if chr(pt_byte) not in (string.ascii_letters + " ,.'?!\"\n"):
            score *= 0.95
    return score


def detect_single_character_xor(file_obj):
    lines = file_obj.readlines()
    lines_plaintext = {}
    for line in lines:
        line = line.strip('\n')
        line_bytes = binascii.unhexlify(line)
        likely_pt, _, score = single_byte_xor_cryptanalysis(line_bytes)
        lines_plaintext[likely_pt] = score
    return max(lines_plaintext, key=lines_plaintext.get)


def repeating_key_xor(plaintext, key):
    buffered_key = key * (len(plaintext) // len(key))
    remainder = len(plaintext) % len(buffered_key)
    if remainder > 0:
        buffered_key += key[:remainder]
    
    return fixed_xor(plaintext, buffered_key).hex()


def hamming_distance(bytes1, bytes2):
    XOR = bytes().join([bytes([a ^ b]) for a, b in zip(bytes1, bytes2)])
    return int.from_bytes(XOR, "big").bit_count()

def get_keysize(bytes):
    possible_key_size = {}
    for key_length in range(2, 40):
        prev = None
        diff = 0
        n = 0
        for i in range(0, len(bytes), key_length):
            chunk = bytes[i:i+key_length]
            if prev:
                diff += hamming_distance(chunk, prev) / key_length
                n += 1
            prev = chunk
        diff /= n
        possible_key_size[key_length] = diff
    
    return sorted(possible_key_size, key=possible_key_size.get)

def transpose_bytes(input_bytes, block_size):
    bytes_transposed = list()
    for i in range(block_size):
        group = bytearray()
        for j in range(len(input_bytes)):
            if j % block_size == i:
                group.append(input_bytes[j])
        bytes_transposed.append(group)
    return bytes_transposed

def break_repeating_key_xor(ciphertext_bytes):
    ciphertext_bytes = base64.b64decode(ciphertext_bytes)
    
    most_possible_keysize = get_keysize(ciphertext_bytes)[:5]

    decrypts = []
    for candidate_length in most_possible_keysize:
        ct_transposed = transpose_bytes(ciphertext_bytes, candidate_length)
        most_likely_key = bytearray()
        for i in range(candidate_length):
            most_likely_key_byte = single_byte_xor_cryptanalysis(ct_transposed[i])[1]
            most_likely_key.append(most_likely_key_byte)
        most_likely_plaintext = binascii.unhexlify(repeating_key_xor(ciphertext_bytes, most_likely_key))
        decrypts.append( (candidate_length, most_likely_key, most_likely_plaintext) )
    
    return decrypts[0]

def decrypt_aes_in_ecb_mode(ciphertext_bytes: bytes, key: bytes) -> bytes:
    """
    Decrypt a message by using AES in ECB mode with the provided key

    Args:
        ciphertext_bytes (bytes): bytes to decrypt
        key (bytes): encryption key

    Returns:
        bytes: decrypted block
    """
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext_bytes)

def encrypt_aes_in_ecb_mode(message_bytes: bytes, key: bytes) -> bytes:
    """
    Encrypt a message by using AES in ECB mode with the provided key

    Args:
        message_bytes (bytes): bytes to encrypt
        key (bytes): encryption key

    Returns:
        bytes: encrypted block
    """
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(message_bytes)

def detect_aes_ecb(file_obj):
    """ Detecting AES in ECB mode. We received a file of randomly generated hex encoded string and one ECB encrypted string.
    ECB mode is stateless and deterministic meaning the same 16 bytes of plaintext will result in the same ciphertext. Therefore
    we will search for repeating blocks in the string and find the encrypted string and that is likely the encrypted line

    Args:
        file_obj (_type_): File containing the lines of text

    Returns:
        str: Line suspected of being encrypted using ECB
    """
    lines = file_obj.readlines()
    candidate_ciphertext = {}
    for line in lines:
        line = line.strip('\n')
        line_bytes = binascii.unhexlify(line)
        blocks = [line_bytes[start:start+16] for start in range(0, len(line_bytes), 16)]
        count = Counter(blocks)
        candidate_ciphertext[line] = max(count.values())
    
    return max(candidate_ciphertext, key=candidate_ciphertext.get)