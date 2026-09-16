# Laboratorio 3 — Implementación y evaluación de AES

**Autor:** Bryan Amaya
**Curso:** Cryptography — Yachay Tech University

---

## 1. Implementación

Se implementó AES-128/192/256 desde la especificación (FIPS-197), sin librerías
criptográficas, en Python. El proyecto sigue una estructura modular con separación
entre el core, los tests y los experimentos.

**Organización del código:**

- `aes/gf.py` — aritmética en GF(2⁸): `xtime` y multiplicación general `mul`.
- `aes/sbox.py` — S-box e inversa, generadas desde su definición matemática.
- `aes/transforms.py` — las cuatro transformaciones y sus inversas, más utilidades del state.
- `aes/key_schedule.py` — expansión de llave para los tres tamaños.
- `aes/cipher.py` — cifrado y descifrado de bloque.

**Decisiones de diseño relevantes:**

- **State como `bytearray` plano de 16 bytes, ordenado por columnas** (índice `r + 4*c`),
  en lugar de una matriz 4×4. En Python cada nivel de indirección cuesta tiempo de
  intérprete, por lo que un arreglo plano evita el overhead de una estructura anidada y
  facilita la optimización posterior. Las operaciones acceden directamente por índice.

- **Multiplicación en GF(2⁸) mediante una única función general `mul(a, b)`** en lugar de
  una función por constante. `mul` descompone el segundo operando en potencias de 2
  (leyendo sus bits) y acumula múltiplos de `a` generados con `xtime`. Una sola función
  cubre las siete constantes que usa AES (01, 02, 03 en cifrado; 09, 0B, 0D, 0E en
  descifrado), reduciendo la duplicación de código.

- **S-box generada, no copiada.** En vez de incrustar la tabla de 256 valores, se calcula
  desde su definición: inverso multiplicativo en GF(2⁸) seguido de la transformación afín
  (con constante 0x63). La construcción ocurre una sola vez al importar el módulo y de paso
  verifica la corrección de la aritmética de campo. La tabla inversa se deriva invirtiendo
  la directa.

- **Una sola `key_expansion` para las tres versiones.** El número de palabras de llave (Nk)
  se deriva del largo de la llave, y de Nk se derivan el número de rounds (Nr) y toda la
  lógica del schedule, incluyendo el caso especial de AES-256 (un `SubWord` adicional cada
  8 palabras). No hay código duplicado por versión.

- **Último round sin MixColumns.** Respeta la especificación; es lo que permite que el
  descifrado invierta la estructura de forma simétrica.

---

## 2. Validación

Se construyó una suite de tests automáticos (20 casos) organizada por módulo, usando dos
estrategias complementarias:

- **Valor conocido:** se comparan las salidas contra valores oficiales de FIPS-197
  (apéndices A, B y C), la fuente de verdad del estándar.
- **Ida y vuelta (round-trip):** se verifica que cada operación inversa deshace a la directa,
  y que `D(E(P)) = P` para datos aleatorios en las tres versiones.

**Cobertura:**

- `test_gf` — `xtime` en ambos caminos (con y sin reducción) y `mul` (vector `0x57·0x13 = 0xFE`).
- `test_transforms` — cada transformación contra valores de FIPS-197 y round-trip con su inversa.
- `test_key_schedule` — round keys de AES-128 contra FIPS-197 (apéndice A) y Nr correcto para 128/192/256.
- `test_cipher` — los tres test vectors de FIPS-197 (apéndice C) y round-trip aleatorio.

**Resultado:** las tres versiones (AES-128/192/256) pasan la totalidad de los tests,
incluyendo los test vectors oficiales, antes de la evaluación de rendimiento.

---

## 3. Configuración experimental

- **Hardware:** [COMPLETAR: modelo de CPU, RAM]
- **Sistema operativo:** Windows [versión]
- **Lenguaje:** Python [versión]
- **Procedimiento:** para cada versión y tamaño de datos, se parten los datos en bloques de
  16 bytes (procesados de forma independiente, estilo ECB — el benchmark evalúa el core, no
  un modo seguro), se mide el tiempo de cifrado y de descifrado con `time.perf_counter()`, y
  se calcula el throughput como R = D/T (MB/s). Datos generados con `os.urandom` en tamaños
  múltiplos de 16 (sin padding). La expansión de llave se realiza una sola vez por versión,
  fuera de los loops de medición, para que el tiempo medido corresponda solo al
  procesamiento de bloques.

> 📌 Completar hardware y versiones de Windows/Python antes de entregar.

---

## 4. Resultados y análisis

**Tabla de resultados** (10 MB, 1 repetición):

| Versión | T. cifrado (s) | T. descifrado (s) | Throughput cifrado (MB/s) | Throughput descifrado (MB/s) |
|---------|----------------|-------------------|---------------------------|------------------------------|
| AES-128 | 123.59 | 340.82 | 0.08 | 0.03 |
| AES-192 | 151.56 | 461.93 | 0.07 | 0.02 |
| AES-256 | 188.76 | 487.10 | 0.05 | 0.02 |

> 📌 Por restricción de tiempo se ejecutó 1 repetición en la corrida de 10 MB (el enunciado
> sugiere al menos 3). Los resultados de 1 MB y 10 MB son mutuamente consistentes (mismo
> throughput y misma tendencia entre versiones), lo que respalda la validez de la medición.
> Datos completos en `results/`.

> 📌 Si el tiempo lo permite, insertar un gráfico de barras del throughput por versión.

**Análisis:**

1. **AES-128 vs 192 vs 256.** El tiempo de cifrado crece de forma consistente con el número
   de rounds: 123.59 s (128, 10 rounds) < 151.56 s (192, 12 rounds) < 188.76 s (256, 14
   rounds). AES-256 es el más lento y AES-128 el más rápido, con AES-192 en un punto
   intermedio, siguiendo la proporción de rounds entre versiones.

2. **Efecto del número de rounds.** Como el grueso del trabajo por bloque son las cuatro
   transformaciones repetidas en cada round, el tiempo escala aproximadamente de forma lineal
   con Nr. El incremento de 128 a 256 (~53% más tiempo de cifrado) es coherente con el
   aumento de rounds (de 10 a 14, +40%), con el margen restante atribuible a la mayor
   expansión de llave y al ruido de una sola repetición.

3. **Cifrado vs descifrado.** El descifrado es consistentemente ~2.6–3× más lento que el
   cifrado (p. ej. AES-128: 340.82 s vs 123.59 s). La causa está en `InvMixColumns`: sus
   constantes (0E, 0B, 0D, 09) son "grandes" y requieren más multiplicaciones en GF(2⁸) que
   las del cifrado (02, 03, 01, donde multiplicar por 01 es gratuito). Esta diferencia teórica
   se refleja directamente en los tiempos medidos.

4. **Efecto del tamaño de datos.** El throughput se mantiene estable entre 1 MB y 10 MB
   (~0.08 MB/s en cifrado en ambos casos), ya que el costo por bloque es constante y el
   trabajo escala linealmente con el número de bloques.

5. **Trade-off tamaño de llave vs costo.** Una llave mayor implica más rounds y por tanto
   mayor costo computacional. AES-256 ofrece mayor margen de seguridad a cambio de
   aproximadamente 53% más tiempo de cifrado que AES-128 en esta implementación.

**Hallazgo de rendimiento.** El throughput absoluto es bajo (~0.08 MB/s en cifrado) para
Python puro. La causa no es la expansión de llave —que se realiza una sola vez por versión—
sino la multiplicación en GF(2⁸): se implementó de forma legible (`mul` con un loop sobre los
bits del operando), y `MixColumns` la invoca del orden de 150 veces por bloque, es decir del
orden de 100 millones de veces para 10 MB. Como `mul` recalcula cada producto en cada
invocación, ese recálculo repetido domina el tiempo. La optimización principal pendiente es
precomputar tablas de multiplicación por constante (256 valores calculados una sola vez),
reemplazando cada `mul(x, c)` por un lookup `TABLA_c[x]`. Esto convierte millones de cálculos
repetidos en lookups O(1) sin alterar la corrección del algoritmo (validada en la sección 2).
Se priorizó la claridad del código sobre la velocidad, coherente con el objetivo de
comprensión del laboratorio.

---

## 5. Conclusiones

- Se implementaron y validaron AES-128, AES-192 y AES-256 desde la especificación, pasando la
  totalidad de los test vectors oficiales de FIPS-197.
- El comportamiento de rendimiento observado es coherente con la teoría: el costo crece con el
  número de rounds (128 < 192 < 256), y el descifrado es ~3× más lento que el cifrado por el
  mayor costo de `InvMixColumns`.
- El throughput se mantiene estable al variar el tamaño de los datos, confirmando un costo por
  bloque constante.
- El análisis del core identificó una oportunidad de optimización concreta: precomputar tablas
  de multiplicación en GF(2⁸), que constituye el principal trabajo futuro para acercar el
  rendimiento al esperado en Python sin sacrificar la corrección.