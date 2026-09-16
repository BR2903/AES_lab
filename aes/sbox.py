from aes.gf import mul


def _gf_inverse(a):
    if a == 0:
        return 0
    for b in range(256):
        if mul(a, b) == 1:
            return b
    return 0


def _affine(b):
    def rotl(x, n):
        return ((x << n) | (x >> (8 - n))) & 0xFF
    return b ^ rotl(b, 1) ^ rotl(b, 2) ^ rotl(b, 3) ^ rotl(b, 4) ^ 0x63


def _build_sbox():
    sbox = [0] * 256
    for a in range(256):
        sbox[a] = _affine(_gf_inverse(a))
    inv = [0] * 256
    for a in range(256):
        inv[sbox[a]] = a          # si sbox[a]=b entonces inv[b]=a
    return sbox, inv


SBOX, INV_SBOX = _build_sbox()
