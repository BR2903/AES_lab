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
    """Cifra un bloque de 16 bytes usando round keys YA expandidas.

    No re-expande la llave: recibe round_keys y Nr como parametros. Esta es la
    variante que usa el benchmark para no recomputar el key schedule por bloque.
    """
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
    """Descifra un bloque de 16 bytes usando round keys YA expandidas.

    Inversa exacta de encrypt_block_with_keys. No re-expande la llave.
    """
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
    """Cifra un bloque de 16 bytes con la llave dada (16/24/32 bytes).

    Expande la llave una vez y delega en encrypt_block_with_keys. Para cifrar
    muchos bloques con la misma llave, expande con key_expansion una sola vez
    y usa encrypt_block_with_keys directamente (evita re-expandir por bloque).
    """
    round_keys, Nr = key_expansion(key)
    return encrypt_block_with_keys(plaintext16, round_keys, Nr)


def decrypt_block(ciphertext16, key):
    """Descifra un bloque de 16 bytes (inversa exacta de encrypt_block)."""
    round_keys, Nr = key_expansion(key)
    return decrypt_block_with_keys(ciphertext16, round_keys, Nr)