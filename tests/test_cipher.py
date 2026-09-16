import os

from aes.cipher import decrypt_block, encrypt_block

PT = bytes.fromhex("00112233445566778899aabbccddeeff")


def test_aes128_fips197_vector():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    ciphertext = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    assert encrypt_block(PT, key) == ciphertext
    assert decrypt_block(ciphertext, key) == PT


def test_aes192_fips197_vector():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617")
    ciphertext = bytes.fromhex("dda97ca4864cdfe06eaf70a0ec0d7191")
    assert encrypt_block(PT, key) == ciphertext
    assert decrypt_block(ciphertext, key) == PT


def test_aes256_fips197_vector():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    ciphertext = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
    assert encrypt_block(PT, key) == ciphertext
    assert decrypt_block(ciphertext, key) == PT


def test_round_trip_with_random_data():
    for key_len in (16, 24, 32):
        key = os.urandom(key_len)
        plaintext = os.urandom(16)
        assert decrypt_block(encrypt_block(plaintext, key), key) == plaintext
