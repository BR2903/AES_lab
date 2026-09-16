from aes.gf import mul
from aes.sbox import SBOX, INV_SBOX


def bytes_to_state(data16):
    assert len(data16) == 16
    return bytearray(data16)


def state_to_bytes(state):
    return bytes(state)


def print_state(state):
    for r in range(4):
        print(" ".join(f"{state[r + 4*c]:02x}" for c in range(4)))


def sub_bytes(state):
    for i in range(16):
        state[i] = SBOX[state[i]]


def inv_sub_bytes(state):
    for i in range(16):
        state[i] = INV_SBOX[state[i]]


def shift_rows(state):
    for r in range(1, 4):                      # fila 0 no se mueve
        row = [state[r + 4*c] for c in range(4)]   # leer la fila
        row = row[r:] + row[:r]                     # rotar r a la izquierda
        for c in range(4):
            state[r + 4*c] = row[c]                 # escribir de vuelta


def inv_shift_rows(state):
    for r in range(1, 4):
        row = [state[r + 4*c] for c in range(4)]
        row = row[-r:] + row[:-r]                   # rotar r a la derecha
        for c in range(4):
            state[r + 4*c] = row[c]


def mix_columns(state):
    for c in range(4):
        i = 4 * c
        s0, s1, s2, s3 = state[i], state[i+1], state[i+2], state[i+3]
        state[i]   = mul(s0, 2) ^ mul(s1, 3) ^ s2 ^ s3          # 02 03 01 01
        state[i+1] = s0 ^ mul(s1, 2) ^ mul(s2, 3) ^ s3          # 01 02 03 01
        state[i+2] = s0 ^ s1 ^ mul(s2, 2) ^ mul(s3, 3)          # 01 01 02 03
        state[i+3] = mul(s0, 3) ^ s1 ^ s2 ^ mul(s3, 2)          # 03 01 01 02


def inv_mix_columns(state):
    for c in range(4):
        i = 4 * c
        s0, s1, s2, s3 = state[i], state[i+1], state[i+2], state[i+3]
        state[i]   = mul(s0, 0x0e) ^ mul(s1, 0x0b) ^ mul(s2, 0x0d) ^ mul(s3, 0x09)
        state[i+1] = mul(s0, 0x09) ^ mul(s1, 0x0e) ^ mul(s2, 0x0b) ^ mul(s3, 0x0d)
        state[i+2] = mul(s0, 0x0d) ^ mul(s1, 0x09) ^ mul(s2, 0x0e) ^ mul(s3, 0x0b)
        state[i+3] = mul(s0, 0x0b) ^ mul(s1, 0x0d) ^ mul(s2, 0x09) ^ mul(s3, 0x0e)


def add_round_key(state, round_key):
    for i in range(16):
        state[i] ^= round_key[i]
