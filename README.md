# AES Lab 3

Implementación de **AES-128 / 192 / 256** en Python puro, escrita desde cero para entender
cada transformación del algoritmo antes de optimizarla. Validada contra los test vectors de
**FIPS-197**.

## Estructura

```
aes/
├── gf.py            # aritmética en GF(2^8): xtime, mul
├── sbox.py          # construcción de la S-box y su inversa
├── transforms.py    # SubBytes, ShiftRows, MixColumns, AddRoundKey (y sus inversas)
├── key_schedule.py  # expansión de llave (key_expansion) para 128/192/256
└── cipher.py         # encrypt_block / decrypt_block

tests/                # tests con pytest, uno por módulo
benchmark/            # generación de datos y medición de rendimiento
results/              # salidas del benchmark
```

## Uso

```python
from aes.cipher import encrypt_block, decrypt_block

key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")

ciphertext = encrypt_block(plaintext, key)
assert decrypt_block(ciphertext, key) == plaintext
```

## Tests

```bash
pip install -r requirements.txt
pytest
```

## Notas

- Prioridad: claridad sobre rendimiento. La S-box se construye matemáticamente en vez de
  usar una tabla estática.
- El cifrado opera sobre bloques de 16 bytes; no implementa un modo de operación (ECB/CBC/etc.)
  ni padding.
- El notebook `AES_lab3.ipynb` documenta el desarrollo paso a paso, con explicación y
  verificación de cada sección antes de modularizarla en `aes/`.
