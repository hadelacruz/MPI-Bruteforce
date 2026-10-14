/* hybrid.c - Version HIBRIDA MPI + OpenMP de la busqueda por fuerza bruta de
 * la llave DES. Combina DOS niveles de paralelismo:
 *   - MPI    : N procesos (posiblemente en varias maquinas/nodos).
 *   - OpenMP : T hilos dentro de CADA proceso (varios nucleos de un nodo).
 * El total de "unidades" de busqueda es N * T.
 *
 * El reparto es CICLICO en dos niveles (como cyclic.c pero anidado):
 *   - entre procesos: paso N        (el proceso id cubre k ≡ id mod N);
 *   - entre hilos   : paso N*T       (el hilo t de ese proceso se intercala).
 * Formula del indice que prueba el hilo t del proceso id en su iteracion c:
 *   k = id + t*N + c*(N*T)
 *
 * Patron de hilos: MPI_THREAD_FUNNELED -> solo el hilo maestro hace llamadas
 * MPI. Por eso se calcula en la region paralela de OpenMP y se coordina por
 * MPI (envio/sondeo de la senal de parada) FUERA de ella, en el maestro.
 *
 * Uso:
 *   OMP_NUM_THREADS=<T> mpirun --bind-to none -np <N> \
 *       ./hybrid <archivo_cifrado> <palabra_clave> [bits]
 */

#include "des.h"
#include "keyutil.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mpi.h>
#include <omp.h>

#define TAG_STOP 1
/* Llaves que prueba CADA hilo por lote antes de que el maestro revise MPI.
 * Un lote completo procesa BATCH_POR_HILO * T llaves de este proceso.
 * (1u<<10 = 2^10 = 1024). Mas grande = menos overhead MPI, parada mas lenta. */
#define BATCH_POR_HILO (1u<<10)

int main(int argc, char *argv[]) {
    /* --- Arranque de MPI con soporte de hilos ---
     * MPI_Init_thread (en vez de MPI_Init) pide el nivel MPI_THREAD_FUNNELED:
     * habra varios hilos, pero SOLO el hilo principal llamara a MPI. 'provided'
     * indica el nivel que la implementacion realmente concedio. */
    int provided;
    MPI_Init_thread(&argc, &argv, MPI_THREAD_FUNNELED, &provided);

    int N, id;
    MPI_Comm comm = MPI_COMM_WORLD;
    MPI_Comm_size(comm, &N);   /* N  = numero de procesos MPI      */
    MPI_Comm_rank(comm, &id);  /* id = rango de este proceso       */

    /* Aviso (no fatal) si la implementacion no garantiza el nivel pedido. */
    if (provided < MPI_THREAD_FUNNELED && id == 0)
        fprintf(stderr, "Advertencia: la implementacion MPI no garantiza "
                        "MPI_THREAD_FUNNELED (provided=%d)\n", provided);

    /* --- Validacion de argumentos (solo el proceso 0 reporta) --- */
    if (argc < 3) {
        if (id == 0)
            fprintf(stderr, "Uso: OMP_NUM_THREADS=<T> mpirun --bind-to none -np <N> "
                            "%s <archivo_cifrado> <palabra_clave> [bits]\n", argv[0]);
        MPI_Finalize();
        return 1;
    }
    const char *archivo = argv[1];
    const char *palabra = argv[2];
    int bits = (argc >= 4) ? atoi(argv[3]) : 56;
    if (bits < 1 || bits > 56) {
        if (id == 0) fprintf(stderr, "Error: bits debe estar entre 1 y 56\n");
        MPI_Finalize();
        return 1;
    }

    /* --- Carga del cifrado por el proceso 0 y difusion a todos (igual que
     *     en bruteforce.c): primero el tamano, luego el contenido. --- */
    long len = 0;
    unsigned char *cipher = NULL;
    if (id == 0) {
        cipher = leer_archivo(archivo, &len);
        if (!cipher || len % 8 != 0 || palabra[0] == '\0') {
            fprintf(stderr, "Error: archivo cifrado invalido o palabra clave vacia\n");
            len = -1;   /* senal de error a difundir */
        }
    }
    MPI_Bcast(&len, 1, MPI_LONG, 0, comm);
    if (len < 0) { free(cipher); MPI_Finalize(); return 1; }

    if (id != 0) cipher = malloc((size_t)len + 1);
    if (!cipher) { fprintf(stderr, "Rank %d: memoria insuficiente\n", id); MPI_Abort(comm, 1); }
    MPI_Bcast(cipher, (int)len, MPI_UNSIGNED_CHAR, 0, comm);
    cipher[len] = 0;

    /* --- Un buffer de trabajo POR HILO ---
     * probar_llave ESCRIBE el descifrado en 'work'; si los hilos lo
     * compartieran se pisarian (condicion de carrera). Por eso se reserva uno
     * independiente para cada uno de los T hilos. */
    int T = omp_get_max_threads();
    unsigned char **works = malloc((size_t)T * sizeof(*works));
    if (!works) { fprintf(stderr, "Rank %d: memoria insuficiente\n", id); MPI_Abort(comm, 1); }
    for (int t = 0; t < T; ++t) {
        works[t] = malloc((size_t)len + 1);
        if (!works[t]) { fprintf(stderr, "Rank %d: memoria insuficiente\n", id); MPI_Abort(comm, 1); }
    }

    uint64_t upper = 1ULL << bits;
    long long found = -1;        /* llave hallada (o recibida), o -1 */
    volatile int stop = 0;       /* bandera compartida entre hilos: 1 = parar */

    /* Pasos del reparto ciclico de dos niveles (en indices k):
     *   paso_hilo = N    -> separacion entre hilos consecutivos de un proceso.
     *   paso_lote = N*T  -> separacion entre llaves sucesivas de UN mismo hilo. */
    const uint64_t paso_hilo = (uint64_t)N;
    const uint64_t paso_lote = (uint64_t)N * T;

    MPI_Barrier(comm);           /* todos arrancan el cronometro a la vez */
    double t0 = MPI_Wtime();

    /* --- Bucle de LOTES ---
     * 'base' avanza de lote en lote. Cada vuelta procesa, en paralelo con los
     * T hilos, un lote de (N*T * BATCH_POR_HILO) llaves de ESTE proceso, y al
     * terminar vuelve al hilo maestro para coordinar por MPI. */
    for (uint64_t base = (uint64_t)id; !stop && base < upper;
         base += paso_lote * BATCH_POR_HILO) {

        /* Region paralela OpenMP: reparte los T hilos (uno por iteracion t).
         * schedule(static) porque todos los hilos hacen el mismo trabajo. */
        #pragma omp parallel for schedule(static)
        for (int t = 0; t < T; ++t) {
            unsigned char *work = works[t];               /* buffer propio del hilo */
            uint64_t k0 = base + (uint64_t)t * paso_hilo;  /* 1er indice del hilo t  */
            for (uint64_t c = 0; c < BATCH_POR_HILO; ++c) {
                if (stop) break;                           /* otro hilo ya la hallo  */
                uint64_t k = k0 + c * paso_lote;           /* k = id + t*N + c*(N*T) */
                if (k >= upper) break;                     /* fuera del espacio      */
                if (probar_llave(k, cipher, (int)len, work, palabra)) {
                    /* Seccion critica: un hilo a la vez escribe el resultado,
                     * para que dos hallazgos simultaneos no se pisen. Gana el
                     * primero (el 'if (!stop)'). */
                    #pragma omp critical
                    {
                        if (!stop) { stop = 1; found = (long long)k; }
                    }
                    break;
                }
            }
        }

        /* --- Coordinacion MPI: SOLO el hilo maestro, fuera de OpenMP --- */
        if (stop) {
            /* Este proceso encontro la llave: avisa a los demas. */
            for (int j = 0; j < N; ++j)
                if (j != id)
                    MPI_Send(&found, 1, MPI_LONG_LONG, j, TAG_STOP, comm);
            break;
        } else {
            /* Sondeo no bloqueante: ¿otro proceso ya la encontro? */
            int flag = 0;
            MPI_Status st;
            MPI_Iprobe(MPI_ANY_SOURCE, TAG_STOP, comm, &flag, &st);
            if (flag) {
                MPI_Recv(&found, 1, MPI_LONG_LONG, st.MPI_SOURCE, TAG_STOP, comm, MPI_STATUS_IGNORE);
                stop = 1;
                break;
            }
        }
    }

    double t1 = MPI_Wtime();

    /* Consolidacion: el maximo de todos los 'found' es la llave (o -1). */
    long long global_found;
    MPI_Allreduce(&found, &global_found, 1, MPI_LONG_LONG, MPI_MAX, comm);

    /* Tiempo reportado = el del proceso mas lento. */
    double elapsed = t1 - t0, max_elapsed;
    MPI_Reduce(&elapsed, &max_elapsed, 1, MPI_DOUBLE, MPI_MAX, 0, comm);

    /* --- Reporte (solo el proceso 0) --- */
    if (id == 0) {
        if (global_found >= 0) {
            memcpy(works[0], cipher, (size_t)len);
            des_ecb((uint64_t)global_found, works[0], (int)len, 1);
            works[0][len] = 0;
            printf("Llave encontrada : %lld\n", global_found);
            printf("Archivo cifrado  : %s\n", archivo);
            printf("Palabra clave    : %s\n", palabra);
            printf("Texto descifrado : %s\n", works[0]);
        } else {
            printf("Llave NO encontrada en [0, 2^%d)\n", bits);
            printf("Archivo cifrado  : %s\n", archivo);
            printf("Palabra clave    : %s\n", palabra);
        }
        printf("Enfoque          : hibrido MPI+OpenMP (ciclico, paso N*T)\n");
        printf("Procesos (MPI)   : %d\n", N);
        printf("Hilos por proceso: %d\n", T);
        printf("Unidades totales : %d\n", N * T);
        printf("Tiempo           : %.4f s\n", max_elapsed);
    }

    /* Drenar avisos de parada pendientes antes de finalizar (evita colgados). */
    int flag = 1;
    while (flag) {
        MPI_Status st;
        MPI_Iprobe(MPI_ANY_SOURCE, TAG_STOP, comm, &flag, &st);
        if (flag) {
            long long tmp;
            MPI_Recv(&tmp, 1, MPI_LONG_LONG, st.MPI_SOURCE, TAG_STOP, comm, MPI_STATUS_IGNORE);
        }
    }

    for (int t = 0; t < T; ++t) free(works[t]);
    free(works);
    free(cipher);
    MPI_Finalize();
    return 0;
}
