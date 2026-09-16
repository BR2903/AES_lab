def xtime(b):
    """Multiplica un byte por 0x02 en GF(2^8).

    Paso 1: recuerda si el bit 7 estaba encendido ANTES de mover (b & 0x80).
    Paso 2: corre a la izquierda (multiplicar por x).
    Paso 3: si el bit 7 estaba encendido, el resultado se desbordó a x^8,
            así que se reduce con XOR 0x1B. Se recorta a 8 bits con & 0xFF.
    """
    result = b << 1
    if b & 0x80:
        result ^= 0x1B
    return result & 0xFF


def mul(a, b):
    """Multiplica a * b en GF(2^8).

    Recorre los bits de b (de menor a mayor). En cada vuelta:
      - si el bit bajo de b esta encendido, suma (XOR) la 'a' actual al resultado,
      - duplica 'a' con xtime (para representar la siguiente potencia de 2),
      - corre 'b' a la derecha para leer el siguiente bit.
    """
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1
    return result
