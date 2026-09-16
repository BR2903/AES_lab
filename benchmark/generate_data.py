"""Generacion de datos y llaves de prueba para el benchmark de AES."""

import os

MB = 1024 * 1024


def generate_random_data(n_bytes):
    """Genera n_bytes de datos aleatorios con os.urandom.

    n_bytes debe ser multiplo de 16 para poder partir en bloques AES
    completos sin necesitar padding (el benchmark evalua el core, que
    solo opera sobre bloques de 16 bytes).
    """
    if n_bytes % 16 != 0:
        raise ValueError("n_bytes debe ser multiplo de 16 (sin padding)")
    return os.urandom(n_bytes)


def generate_data_mb(size_mb):
    """Genera datos aleatorios a partir de un tamano en MB.

    Se trunca hacia abajo al multiplo de 16 mas cercano por si se pasa
    un tamano fraccionario (ej. 0.5 MB) que no cayera exacto.
    """
    n_bytes = int(size_mb * MB)
    n_bytes -= n_bytes % 16
    return generate_random_data(n_bytes)


def generate_test_keys():
    """Genera las tres llaves de prueba: AES-128 (16B), AES-192 (24B), AES-256 (32B)."""
    return {
        128: os.urandom(16),
        192: os.urandom(24),
        256: os.urandom(32),
    }
