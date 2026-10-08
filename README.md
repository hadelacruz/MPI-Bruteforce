# Proyecto 2 — Bruteforce DES con MPI

Búsqueda por fuerza bruta de la llave privada DES con la que se cifró un
texto, en versión secuencial y paralela (Open MPI). Incluye el enfoque
"naive" y dos acercamientos alternativos.

## Estructura del proyecto

```
.
├── README.md        # este archivo
├── Makefile         # compila src/ -> bin/
├── src/             # codigo fuente (.c y .h)
├── docs/            # informe.tex + enunciado del proyecto
├── pruebas/         # entradas de prueba (texto.txt)
└── bin/             # ejecutables (se crea al compilar; ignorado por git)
```

| Archivo (en `src/`) | Descripción |
|---|---|
| `des.c` / `des.h` | Implementación propia de DES (FIPS 46-3), modo ECB. |
| `keyutil.c` / `keyutil.h` | Lectura de archivos y prueba de una llave. |
| `test_des.c` | Valida el DES propio contra vectores de OpenSSL. |
| `cifrar.c` | Cifra/descifra un `.txt` con una llave arbitraria. |
| `secuencial.c` | Búsqueda **secuencial** (línea base). |
| `bruteforce.c` | Búsqueda paralela **naive** (bloques contiguos), MPI. |
| `cyclic.c` | **Alternativa 1**: reparto cíclico (intercalado), MPI. |
| `master_worker.c` | **Alternativa 2**: maestro-trabajador dinámico, MPI. |

## Requisitos

- `gcc` (para los programas secuenciales).
- **Open MPI** (`mpicc`, `mpirun`) para los programas paralelos.
  En Ubuntu/WSL: `sudo apt install -y openmpi-bin libopenmpi-dev`
- No se necesita ninguna librería de DES externa: se incluye una propia
  (`src/des.c`), que reemplaza a `<rpc/des_crypt.h>`.

> Open MPI no corre nativo en Windows. Use **WSL (Ubuntu)**, Linux o el
> clúster del laboratorio.

## Compilación

```bash
make          # compila todo en bin/
make clean    # borra bin/
```

## Uso

### 1. Validar el DES
```bash
./bin/test_des            # debe imprimir "Resultado global: OK"
```

### 2. Cifrar / descifrar un archivo (Parte B.1)
```bash
./bin/cifrar -e <entrada.txt> <llave> <salida.bin>     # cifrar
./bin/cifrar -d <salida.bin>  <llave> <recuperado.txt> # descifrar
# Ejemplo con llave 42:
printf 'Hola mundo secreto' > pruebas/frase.txt
./bin/cifrar -e pruebas/frase.txt 42 frase.bin
./bin/cifrar -d frase.bin 42 frase_out.txt && cat frase_out.txt
```

### 3. Búsqueda de la llave

Todos los buscadores reciben: `<archivo_cifrado> <palabra_clave> [bits]`.
El parámetro opcional `bits` fija el espacio de búsqueda a `2^bits` llaves
(por defecto 56, el espacio completo de DES). Se usa un espacio reducido
para los experimentos de *speedup* (ver informe).

```bash
# Preparar un caso de prueba:
./bin/cifrar -e pruebas/texto.txt 123456 cifrado.bin

# Secuencial:
./bin/secuencial cifrado.bin "es una prueba de" 56

# Paralelo (4 procesos):
mpirun -np 4 ./bin/bruteforce     cifrado.bin "es una prueba de" 56
mpirun -np 4 ./bin/cyclic         cifrado.bin "es una prueba de" 56
mpirun -np 4 ./bin/master_worker  cifrado.bin "es una prueba de" 56   # requiere -np >= 2
```

Cada programa imprime la llave encontrada, el nombre del archivo cifrado, la
palabra clave, el texto descifrado y el tiempo de ejecución.

### Pruebas oficiales (Parte B.2)

Texto `"Esta es una prueba de proyecto 2"` (en `pruebas/texto.txt`), palabra
clave `"es una prueba de"`, 4 procesos, espacio completo (`bits=56`):

| Caso | Llave | Resultado esperado |
|---|---|---|
| (a) | `123456` | se rompe en segundos |
| (b) | `18014398509481983` (2⁵⁴−1) | **no termina** (la llave queda al final del bloque 0) |
| (c) | `18014398509481984` (2⁵⁴) | se rompe al instante (inicio del bloque 1) |

```bash
./bin/cifrar -e pruebas/texto.txt 123456 ca.bin
mpirun -np 4 ./bin/bruteforce ca.bin "es una prueba de" 56
```

## Notas

- `cifrar` rellena el texto con ceros hasta un múltiplo de 8 bytes (bloque DES).
- El DES propio no está optimizado (~4×10⁴ llaves/s); por eso los
  experimentos de *speedup* usan un espacio reducido (`bits` ≈ 20). El
  fenómeno de *speedup* es invariante de escala.
- El informe está en `docs/informe.tex` (compílelo en Overleaf o con
  `pdflatex`).
