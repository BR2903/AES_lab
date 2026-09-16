"""Benchmark de rendimiento del core de AES (Exercise 3).

Compara AES-128/192/256 sobre datos de distintos tamanos, procesando los
bloques de 16 bytes de forma independiente (estilo ECB, sin padding ni IV).
Esto NO es un modo de operacion seguro: solo sirve para medir la velocidad
del core (encrypt_block / decrypt_block).

El core en aes/ NO se modifica. Como encrypt_block/decrypt_block re-expanden
la llave en cada llamada (ver aes/cipher.py), aqui definimos variantes
auxiliares que reciben las round_keys ya calculadas, para no pagar el costo
de key_expansion en cada bloque.
"""

import argparse
import csv
import json
import sys
from pathlib import Path
from statistics import mean
from time import perf_counter

# Permite ejecutar tanto "python -m benchmark.benchmark" desde la raiz
# como "python benchmark/benchmark.py" directamente.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aes.key_schedule import key_expansion
from aes.transforms import (
    add_round_key,
    bytes_to_state,
    inv_mix_columns,
    inv_shift_rows,
    inv_sub_bytes,
    mix_columns,
    shift_rows,
    state_to_bytes,
    sub_bytes,
)
from benchmark.generate_data import MB, generate_data_mb, generate_test_keys


# --------------------------------------------------------------------------
# Variantes de encrypt_block/decrypt_block que reciben round_keys precalculadas.
# Son copias de la logica de aes/cipher.py; la unica diferencia es que no
# llaman a key_expansion, sino que reciben (round_keys, Nr) ya listos.
# --------------------------------------------------------------------------

def encrypt_block_with_keys(plaintext16, round_keys, Nr):
    state = bytes_to_state(plaintext16)
    add_round_key(state, round_keys[0])
    for r in range(1, Nr):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[r])
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[Nr])
    return state_to_bytes(state)


def decrypt_block_with_keys(ciphertext16, round_keys, Nr):
    state = bytes_to_state(ciphertext16)
    add_round_key(state, round_keys[Nr])
    inv_shift_rows(state)
    inv_sub_bytes(state)
    for r in range(Nr - 1, 0, -1):
        add_round_key(state, round_keys[r])
        inv_mix_columns(state)
        inv_shift_rows(state)
        inv_sub_bytes(state)
    add_round_key(state, round_keys[0])
    return state_to_bytes(state)


def process_all_blocks(data, round_keys, Nr, block_func, progress_label=None):
    """Aplica block_func a cada bloque de 16 bytes de data y devuelve el resultado.

    Si progress_label se da, imprime el avance en la misma linea (con \\r)
    cada ~5% de los bloques procesados. Esto importa sobre todo para 100 MB
    en Python puro, donde una corrida puede tardar varios minutos y sin
    feedback pareceria que el programa esta colgado.
    """
    n_blocks = len(data) // 16
    out = bytearray(len(data))
    step = max(n_blocks // 20, 1)  # ~20 actualizaciones de progreso (cada 5%)

    for idx in range(n_blocks):
        i = idx * 16
        out[i:i + 16] = block_func(data[i:i + 16], round_keys, Nr)
        if progress_label and (idx % step == 0 or idx == n_blocks - 1):
            pct = (idx + 1) / n_blocks * 100
            print(f"\r    {progress_label}: {pct:5.1f}% "
                  f"({idx + 1}/{n_blocks} bloques)", end="", flush=True)

    if progress_label:
        print()  # salto de linea final para no pisar el siguiente print

    return bytes(out)


def run_benchmark(versions, sizes_mb, repeats, show_progress=True):
    """Corre el benchmark completo y devuelve una lista de dicts con resultados.

    Decisiones de medicion:
    - perf_counter() en vez de time(): usa el reloj monotonico de mayor
      resolucion disponible, no se ve afectado por ajustes del reloj del
      sistema (NTP, cambios de hora) y es el recomendado para medir
      intervalos cortos de CPU en Python.
    - key_expansion se llama UNA sola vez por version (AES-128/192/256),
      fuera de los loops de tamano y de repeticion, porque la llave no
      cambia entre corridas. Asi el tiempo medido corresponde solo al
      procesamiento de bloques (lo que realmente se quiere comparar), y no
      se infla con el costo fijo de expandir la llave una y otra vez.
    - Cada combinacion (version, tamano) se repite `repeats` veces y se
      reporta el promedio, para amortiguar ruido del sistema operativo
      (scheduling, GC, otros procesos) que puede hacer que una sola corrida
      no sea representativa.
    """
    keys = generate_test_keys()
    results = []

    for version in versions:
        key = keys[version]
        # Expansion de llave UNA sola vez por version; se reutiliza para
        # todos los tamanos y todas las repeticiones de esta version.
        round_keys, Nr = key_expansion(key)
        print(f"\n=== AES-{version} ===")

        for size_mb in sizes_mb:
            print(f"\n-- Tamano: {size_mb} MB --")
            data = generate_data_mb(size_mb)
            n_blocks = len(data) // 16
            real_mb = len(data) / MB  # tamano real tras truncar a multiplo de 16

            enc_times = []
            dec_times = []

            for rep in range(1, repeats + 1):
                label_enc = f"AES-{version} {size_mb}MB cifrado" if show_progress else None
                label_dec = f"AES-{version} {size_mb}MB descifrado" if show_progress else None

                print(f"  [Run {rep}/{repeats}] cifrando {n_blocks} bloques...")
                t0 = perf_counter()
                ciphertext = process_all_blocks(
                    data, round_keys, Nr, encrypt_block_with_keys, label_enc
                )
                t1 = perf_counter()
                enc_times.append(t1 - t0)

                print(f"  [Run {rep}/{repeats}] descifrando {n_blocks} bloques...")
                t0 = perf_counter()
                plaintext = process_all_blocks(
                    ciphertext, round_keys, Nr, decrypt_block_with_keys, label_dec
                )
                t1 = perf_counter()
                dec_times.append(t1 - t0)

                if rep == 1 and plaintext != data:
                    raise RuntimeError(
                        f"Descifrado no coincide con el original (AES-{version}, {size_mb} MB)"
                    )

            avg_enc_time = mean(enc_times)
            avg_dec_time = mean(dec_times)
            enc_throughput = real_mb / avg_enc_time
            dec_throughput = real_mb / avg_dec_time

            results.append({
                "version": version,
                "size_mb": round(real_mb, 4),
                "repeats": repeats,
                "avg_encrypt_time_s": avg_enc_time,
                "avg_decrypt_time_s": avg_dec_time,
                "encrypt_throughput_mbps": enc_throughput,
                "decrypt_throughput_mbps": dec_throughput,
            })

    return results


def print_results_table(results):
    header = (
        f"{'Version':<10}{'Tamano(MB)':<12}{'T.cifrado(s)':<14}"
        f"{'T.descifrado(s)':<17}{'Thr.cifrado(MB/s)':<19}{'Thr.descifrado(MB/s)':<20}"
    )
    print("\n" + header)
    print("-" * len(header))
    for r in results:
        print(
            f"AES-{r['version']:<6}{r['size_mb']:<12.2f}"
            f"{r['avg_encrypt_time_s']:<14.4f}{r['avg_decrypt_time_s']:<17.4f}"
            f"{r['encrypt_throughput_mbps']:<19.2f}{r['decrypt_throughput_mbps']:<20.2f}"
        )


def save_results(results, outdir, tag):
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    csv_path = outdir / f"benchmark_results_{tag}.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)

    json_path = outdir / f"benchmark_results_{tag}.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\nResultados guardados en:\n  {csv_path}\n  {json_path}")


def parse_args():
    parser = argparse.ArgumentParser(description="Benchmark del core de AES")
    parser.add_argument(
        "--sizes", type=float, nargs="+", default=[1, 10],
        help="Tamanos a probar en MB (default: 1 10). Ej: --sizes 1 10 100",
    )
    parser.add_argument(
        "--versions", type=int, nargs="+", default=[128, 192, 256], choices=[128, 192, 256],
        help="Versiones de AES a comparar (default: 128 192 256)",
    )
    parser.add_argument(
        "--repeats", type=int, default=3,
        help="Numero de repeticiones por combinacion version/tamano (default: 3)",
    )
    parser.add_argument(
        "--outdir", type=str, default="results",
        help="Carpeta donde guardar CSV/JSON (default: results)",
    )
    parser.add_argument(
        "--no-progress", action="store_true",
        help="Desactiva la barra de progreso por bloque (solo muestra progreso por run)",
    )
    parser.add_argument(
        "--tag", type=str, default=None,
        help="Sufijo para nombrar los archivos de salida (default: timestamp)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    tag = args.tag
    if tag is None:
        from datetime import datetime
        tag = datetime.now().strftime("%Y%m%d_%H%M%S")

    results = run_benchmark(
        versions=args.versions,
        sizes_mb=args.sizes,
        repeats=args.repeats,
        show_progress=not args.no_progress,
    )

    print_results_table(results)
    save_results(results, args.outdir, tag)
