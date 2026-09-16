def xtime(b):
    result = b << 1
    if b & 0x80:
        result ^= 0x1B
    return result & 0xFF


def mul(a, b):
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1
    return result
