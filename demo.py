from aes.cipher import encrypt_block, decrypt_block


def pad(data):
    faltan = 16 - (len(data) % 16)      # entre 1 y 16
    return data + bytes([faltan]) * faltan


def unpad(data):
    faltan = data[-1]
    return data[:-faltan]


def encrypt(texto, key):
    data = pad(texto.encode("utf-8"))            # str -> bytes -> padded
    salida = bytearray()
    for i in range(0, len(data), 16):            # bloques de 16
        salida += encrypt_block(data[i:i+16], key)
    return bytes(salida)


def decrypt(cifrado, key):
    salida = bytearray()
    for i in range(0, len(cifrado), 16):
        salida += decrypt_block(cifrado[i:i+16], key)
    return unpad(salida).decode("utf-8")         # quita padding -> str


if __name__ == "__main__":
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")   # 16 bytes = AES-128
    texto = "Hola, esto es un mensaje secreto"

    cifrado = encrypt(texto, key)
    print("Cifrado (hex):", cifrado.hex())

    recuperado = decrypt(cifrado, key)
    print("Descifrado:   ", recuperado)