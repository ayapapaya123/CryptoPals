import base64
from Set2 import challenges
from consts import test_files_dir

def test_pkcs7_pad():
    assert challenges.pkcs7_pad(b"YELLOW SUBMARINE", 20) == b"YELLOW SUBMARINE\x04\x04\x04\x04", \
        "Should have four bytes of padding"

def test_pkcs7_no_pad():
    assert challenges.pkcs7_pad(b"YELLOW SUBMARINE", 16) == b"YELLOW SUBMARINE", \
        "Should have no padding because input is same length as block"

def test_pkcs7_max_pad():
    assert challenges.pkcs7_pad(b"YELLOW SUBMARINES", 16) == b"YELLOW SUBMARINES\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f", \
        "Should have 15 bytes of padding"

def test_pkcs7_unpadding():
    padded_text = b"YELLOW SUBMARINE\x04\x04\x04\x04"
    assert challenges.pkcs7_unpad(padded_text) == b"YELLOW SUBMARINE"

def test_pkcs7_unpadding_nothing():
    padded_text = b"YELLOW SUBMARINE"
    assert challenges.pkcs7_unpad(padded_text) == b"YELLOW SUBMARINE"

def test_pkcs7_unpadding_invalid():
    padded_text = b"YELLOW SUBMARINES\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f"
    assert challenges.pkcs7_unpad(padded_text) == b"YELLOW SUBMARINES\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f"

def test_encrypt_decrypt_aes_cbc_mode():
    plaintext = b"In CBC mode, each ciphertext block is added to the next plaintext " + \
                b"block before the next call to the cipher core."
    key = b"chickens fingers"
    iv = b"honey mustard ok"
    ciphertext = challenges.encrypt_aes_cbc_mode(plaintext, key, iv)
    assert challenges.decrypt_aes_cbc_mode(ciphertext, key, iv) == plaintext

def test_challenge10():
    with open(test_files_dir / "set2_challenge10.txt", "r") as file_obj:
        ciphertext_b64 = file_obj.read()
    ciphertext_bytes = base64.b64decode(ciphertext_b64)
    key = b"YELLOW SUBMARINE"
    iv = b"\x00" * 16
    plaintext = challenges.decrypt_aes_cbc_mode(ciphertext_bytes, key, iv)
    assert b"I'm back and I'm ringin' the bell" in plaintext, \
        "Beginning of plaintext not decrypted"
    assert b"'Cause why the freaks are jockin' like Crazy Glue" in plaintext, \
        "Middle of plaintext not decrypted"

# def test_challenge11():
#     for i in range(10):
#         candidate_result, actual_result = challenges.detect_ecb_or_cbc(challenges.encryption_oracle)
#         assert candidate_result == actual_result

