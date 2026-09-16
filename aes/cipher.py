from aes.key_schedule import key_expansion
from aes.transforms import (
    add_round_key,
    bytes_to_state,
    inv_mix_columns,
    inv_shift_rows,
    inv_sub_bytes,
    mix_columns,
    shift_rows,
    state_to_bytes,
    sub_bytes,
)


def encrypt_block_with_keys(plaintext16, round_keys, Nr):
    state = bytes_to_state(plaintext16)

    add_round_key(state, round_keys[0])              # AddRoundKey inicial

    for r in range(1, Nr):                           # rounds completos
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[r])

    sub_bytes(state)                                 # round final (sin MixColumns)
    shift_rows(state)
    add_round_key(state, round_keys[Nr])

    return state_to_bytes(state)


def decrypt_block_with_keys(ciphertext16, round_keys, Nr):
    state = bytes_to_state(ciphertext16)

    add_round_key(state, round_keys[Nr])             # deshacer round final
    inv_shift_rows(state)
    inv_sub_bytes(state)

    for r in range(Nr - 1, 0, -1):                   # rounds completos al reves
        add_round_key(state, round_keys[r])
        inv_mix_columns(state)
        inv_shift_rows(state)
        inv_sub_bytes(state)

    add_round_key(state, round_keys[0])              # deshacer AddRoundKey inicial

    return state_to_bytes(state)


def encrypt_block(plaintext16, key):
    round_keys, Nr = key_expansion(key)
    return encrypt_block_with_keys(plaintext16, round_keys, Nr)


def decrypt_block(ciphertext16, key):
    round_keys, Nr = key_expansion(key)
    return decrypt_block_with_keys(ciphertext16, round_keys, Nr)