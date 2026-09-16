from aes.sbox import SBOX

# Constantes de round (Rcon). Cada una es [RC, 0, 0, 0]; aqui guardamos solo RC.
# RC[i] = xtime aplicado sucesivamente: 01,02,04,08,10,20,40,80,1b,36,...
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
        0x6c, 0xd8, 0xab, 0x4d]   # suficientes para las 3 versiones


def _rot_word(w):
    return w[1:] + w[:1]


def _sub_word(w):
    return [SBOX[b] for b in w]


def key_expansion(key):
    Nk = len(key) // 4                 # 4, 6 u 8 palabras
    Nr = {4: 10, 6: 12, 8: 14}[Nk]     # rounds segun el tamano

    # W: lista de palabras (cada una lista de 4 bytes). Las primeras Nk vienen de la llave.
    W = [list(key[4*i:4*i+4]) for i in range(Nk)]

    for i in range(Nk, 4 * (Nr + 1)):
        temp = list(W[i-1])
        if i % Nk == 0:
            temp = _sub_word(_rot_word(temp))
            temp[0] ^= RCON[i // Nk - 1]        # XOR Rcon en el primer byte
        elif Nk == 8 and i % Nk == 4:
            temp = _sub_word(temp)              # caso extra SOLO en AES-256
        W.append([W[i-Nk][j] ^ temp[j] for j in range(4)])

    # Agrupar cada 4 palabras en una round key de 16 bytes
    round_keys = []
    for r in range(Nr + 1):
        rk = bytearray()
        for w in range(4):
            rk.extend(W[4*r + w])
        round_keys.append(rk)
    return round_keys, Nr
