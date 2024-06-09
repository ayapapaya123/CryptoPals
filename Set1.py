from base64 import b64encode
from string import ascii_lowercase
import binascii
import string
import base64
from Crypto.Cipher import AES


letterFrequency = {
    'E': 12.0, 'T': 9.1, 'A': 8.12, 'O': 7.68, 'I': 7.31, 'N': 6.95, 'S': 6.28, 'R': 6.02, 'H': 5.92, 'D': 4.32, 'L': 3.98, 'U': 2.88, 'C': 2.71, 'M': 2.61, 'F': 2.3, 'Y': 2.11, 'W': 2.09, 'G': 2.03, 'P': 1.82, 'B': 1.49, 'V': 1.11, 'K': 0.69, 'X': 0.17, 'Q': 0.11, 'J': 0.1, 'Z': 0.07, 'e': 12.0, 't': 9.1, 'a': 8.12, 'o': 7.68, 'i': 7.31, 'n': 6.95, 's': 6.28, 'r': 6.02, 'h': 5.92, 'd': 4.32, 'l': 3.98, 'u': 2.88, 'c': 2.71, 'm': 2.61, 'f': 2.3, 'y': 2.11, 'w': 2.09, 'g': 2.03, 'p': 1.82, 'b': 1.49, 'v': 1.11, 'k': 0.69, 'x': 0.17, 'q': 0.11, 'j': 0.1, 'z': 0.07 }


def hex_to_base64(hex_string: str) -> str:
    return b64encode(bytes.fromhex(hex_string)).decode()

def challenge1():
    EXPECTED_RESULT: str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    result = hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
    if result == EXPECTED_RESULT:
        print("Got the expected result")
    else:
        print(f"Result didn't match the solution, try again. Current result is {result}")

def xor(first_string, second_string):
    res = hex(int (first_string, 16) ^ int(second_string, 16))
    return res[2:]

def fixed_xor(bytes1, bytes2):
    assert len(bytes1) == len(bytes2), "You must pass equal-length objects"
    return bytes().join([bytes([a ^ b]) for a, b in zip(bytes1, bytes2)])

def challenge2():
    EXPECTED_RESULT: str = "746865206b696420646f6e277420706c6179"
    result = xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965")
    if result == EXPECTED_RESULT:
        print("Got the expected result")
    else:
        print(f"Result didn't match the solution, try again. Current result is {result}")

def challenge3():
    ciphertext = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    print(single_byte_xor_cryptanalysis(ciphertext))

def single_byte_xor_cryptanalysis(ciphertext):
    plaintexts_dict = {}  # Holds each candidate plaintext and its score
    keys_dict = {}  # Holds each candidate key and its score

    len_ciphertext = len(ciphertext)
    for key_byte in range(256):
        key = bytes([key_byte]) * len_ciphertext
        candidate_plaintext = fixed_xor(ciphertext, key)

        score = float(0)
        for pt_byte in candidate_plaintext:
            c = chr(pt_byte)
            if c in string.ascii_lowercase:
                score += letterFrequency[c]
            # Upper-case letters count slightly less than lower-case
            if c in string.ascii_uppercase:
                score += letterFrequency[c.lower()] * 0.75
        score /= len(ciphertext)  # Normalize score over length of plaintext
        # Decrement score by 5% for every character that is not a letter, number, or common punctuation
        for pt_byte in candidate_plaintext:
            if chr(pt_byte) not in (string.ascii_letters + " ,.'?!\"\n"):
                score *= 0.95
        plaintexts_dict[candidate_plaintext] = score
        keys_dict[key_byte] = score
    return max(plaintexts_dict, key=plaintexts_dict.get), \
           max(keys_dict, key=keys_dict.get), \
           max(plaintexts_dict.values())

def challenge4():
    file_obj = open("files/set1_challenge4.txt", "r")
    print(detect_single_character_xor(file_obj))
    

def detect_single_character_xor(file_obj):
    lines = file_obj.readlines()
    lines_plaintext = {}
    for line in lines:
        line = line.strip('\n')
        line_bytes = binascii.unhexlify(line)
        likely_pt, _, score = single_byte_xor_cryptanalysis(line_bytes)
        lines_plaintext[likely_pt] = score
    return max(lines_plaintext, key=lines_plaintext.get)

def challenge5():
    plaintext = bytes("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "ascii")
    key = bytes("ICE", "ascii")
    result = repeating_key_xor(plaintext, key)
    EXPECTED_RESULT = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

    if result == EXPECTED_RESULT:
        print("Got the expected result")
    else:
        print(f"Result didn't match the solution, try again. Current result is {result}")

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

def challenge6():
    file_obj = open("files/set1_challenge6.txt", "r").read().replace('\n', '')
    ciphertext_bytes = base64.b64decode(file_obj)
    
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
    
    print(decrypts[0])

def challenge7():
    file_obj = open("files/set1_challenge7.txt", "r").read().replace('\n', '')
    ciphertext_bytes = base64.b64decode(file_obj)
    key = "YELLOW SUBMARINE"
    cipher = AES.new(key,AES.MODE_ECB)
    print(cipher.decrypt(ciphertext_bytes))


if __name__ == "__main__":
    print(challenge7())
