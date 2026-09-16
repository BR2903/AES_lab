from aes.gf import mul


def _gf_inverse(a):
    """Inverso multiplicativo de 'a' en GF(2^8) por busqueda exhaustiva.

    Solo se usa UNA vez para construir la S-box, asi que la fuerza bruta
    (probar los 256 bytes) es perfectamente aceptable. inverso de 0 = 0.
    """
    if a == 0:
        return 0
    for b in range(256):
        if mul(a, b) == 1:
            return b
    return 0


def _affine(b):
    """Transformacion afin de la S-box aplicada a un byte ya invertido.

    Cada bit de salida es un XOR de 5 bits del byte rotado, mas el bit
    correspondiente de la constante 0x63. La forma compacta usa rotaciones:
      s = b ^ rotl(b,1) ^ rotl(b,2) ^ rotl(b,3) ^ rotl(b,4) ^ 0x63
    donde rotl es rotacion circular de 8 bits a la izquierda.
    """
    def rotl(x, n):
        return ((x << n) | (x >> (8 - n))) & 0xFF
    return b ^ rotl(b, 1) ^ rotl(b, 2) ^ rotl(b, 3) ^ rotl(b, 4) ^ 0x63


def _build_sbox():
    """Construye SBOX e INV_SBOX desde la definicion matematica."""
    sbox = [0] * 256
    for a in range(256):
        sbox[a] = _affine(_gf_inverse(a))
    inv = [0] * 256
    for a in range(256):
        inv[sbox[a]] = a          # si sbox[a]=b entonces inv[b]=a
    return sbox, inv


SBOX, INV_SBOX = _build_sbox()
