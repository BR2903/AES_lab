from aes.gf import mul
from aes.sbox import SBOX, INV_SBOX


def bytes_to_state(data16):
    """Convierte 16 bytes en un state (bytearray plano por columnas).

    Como los datos ya vienen en el orden r+4*c que AES usa, esto es una
    copia directa a bytearray. Se hace explicito para dejar clara la conancion.
    """
    assert len(data16) == 16
    return bytearray(data16)


def state_to_bytes(state):
    """Convierte el state de vuelta a bytes (mismo orden por columnas)."""
    return bytes(state)


def print_state(state):
    """Imprime el state como matriz 4x4 en hex, para depurar.

    Recorre por filas (r) y dentro de cada fila por columnas (c),
    leyendo el indice r+4*c.
    """
    for r in range(4):
        print(" ".join(f"{state[r + 4*c]:02x}" for c in range(4)))


def sub_bytes(state):
    """Reemplaza cada byte del state por SBOX[byte]."""
    for i in range(16):
        state[i] = SBOX[state[i]]


def inv_sub_bytes(state):
    """Reemplaza cada byte del state por INV_SBOX[byte]."""
    for i in range(16):
        state[i] = INV_SBOX[state[i]]


def shift_rows(state):
    """Rota cada fila r a la izquierda r posiciones."""
    for r in range(1, 4):                      # fila 0 no se mueve
        row = [state[r + 4*c] for c in range(4)]   # leer la fila
        row = row[r:] + row[:r]                     # rotar r a la izquierda
        for c in range(4):
            state[r + 4*c] = row[c]                 # escribir de vuelta


def inv_shift_rows(state):
    """Rota cada fila r a la derecha r posiciones (inversa de shift_rows)."""
    for r in range(1, 4):
        row = [state[r + 4*c] for c in range(4)]
        row = row[-r:] + row[:-r]                   # rotar r a la derecha
        for c in range(4):
            state[r + 4*c] = row[c]


def mix_columns(state):
    """Multiplica cada columna por la matriz fija de MixColumns en GF(2^8)."""
    for c in range(4):
        i = 4 * c
        s0, s1, s2, s3 = state[i], state[i+1], state[i+2], state[i+3]
        state[i]   = mul(s0, 2) ^ mul(s1, 3) ^ s2 ^ s3          # 02 03 01 01
        state[i+1] = s0 ^ mul(s1, 2) ^ mul(s2, 3) ^ s3          # 01 02 03 01
        state[i+2] = s0 ^ s1 ^ mul(s2, 2) ^ mul(s3, 3)          # 01 01 02 03
        state[i+3] = mul(s0, 3) ^ s1 ^ s2 ^ mul(s3, 2)          # 03 01 01 02


def inv_mix_columns(state):
    """Multiplica cada columna por la matriz inversa de MixColumns."""
    for c in range(4):
        i = 4 * c
        s0, s1, s2, s3 = state[i], state[i+1], state[i+2], state[i+3]
        state[i]   = mul(s0, 0x0e) ^ mul(s1, 0x0b) ^ mul(s2, 0x0d) ^ mul(s3, 0x09)
        state[i+1] = mul(s0, 0x09) ^ mul(s1, 0x0e) ^ mul(s2, 0x0b) ^ mul(s3, 0x0d)
        state[i+2] = mul(s0, 0x0d) ^ mul(s1, 0x09) ^ mul(s2, 0x0e) ^ mul(s3, 0x0b)
        state[i+3] = mul(s0, 0x0b) ^ mul(s1, 0x0d) ^ mul(s2, 0x09) ^ mul(s3, 0x0e)


def add_round_key(state, round_key):
    """XOR posicion a posicion del state con la round key (16 bytes)."""
    for i in range(16):
        state[i] ^= round_key[i]
