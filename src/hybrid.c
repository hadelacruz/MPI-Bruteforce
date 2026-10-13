#include "des.h"
#include "keyutil.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mpi.h>
#include <omp.h>

#define TAG_STOP 1
/* Llaves que prueba CADA hilo por lote antes de que el maestro revise MPI.
 * Un lote completo procesa BATCH_POR_HILO * T llaves de este proceso. */
#define BATCH_POR_HILO (1u<<10)

int main(int argc, char *argv[]) {
    int provided;
    MPI_Init_thread(&argc, &argv, MPI_THREAD_FUNNELED, &provided);

    int N, id;
    MPI_Comm comm = MPI_COMM_WORLD;
    MPI_Comm_size(comm, &N);
    MPI_Comm_rank(comm, &id);

    if (provided < MPI_THREAD_FUNNELED && id == 0)
        fprintf(stderr, "Advertencia: la implementacion MPI no garantiza "
                        "MPI_THREAD_FUNNELED (provided=%d)\n", provided);

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

    long len = 0;
    unsigned char *cipher = NULL;
    if (id == 0) {
        cipher = leer_archivo(archivo, &len);
        if (!cipher || len % 8 != 0 || palabra[0] == '\0') {
            fprintf(stderr, "Error: archivo cifrado invalido o palabra clave vacia\n");
            len = -1;
        }
    }
    MPI_Bcast(&len, 1, MPI_LONG, 0, comm);
    if (len < 0) { free(cipher); MPI_Finalize(); return 1; }

    if (id != 0) cipher = malloc((size_t)len + 1);
    if (!cipher) { fprintf(stderr, "Rank %d: memoria insuficiente\n", id); MPI_Abort(comm, 1); }
    MPI_Bcast(cipher, (int)len, MPI_UNSIGNED_CHAR, 0, comm);
    cipher[len] = 0;

    /* Un buffer de trabajo POR HILO: probar_llave escribe en work, asi que
     * no puede compartirse entre hilos. */
    int T = omp_get_max_threads();
    unsigned char **works = malloc((size_t)T * sizeof(*works));
    if (!works) { fprintf(stderr, "Rank %d: memoria insuficiente\n", id); MPI_Abort(comm, 1); }
    for (int t = 0; t < T; ++t) {
        works[t] = malloc((size_t)len + 1);
        if (!works[t]) { fprintf(stderr, "Rank %d: memoria insuficiente\n", id); MPI_Abort(comm, 1); }
    }

    uint64_t upper = 1ULL << bits;
    long long found = -1;        /* llave hallada (o recibida), o -1 */
    volatile int stop = 0;       /* bandera compartida entre hilos */

    /* Paso del lote medido en indices "j" (k = id + j*N). Cada lote cubre
     * T * BATCH_POR_HILO indices, uno por hilo de forma intercalada. */
    const uint64_t paso_hilo = (uint64_t)N;              /* separacion entre hilos */
    const uint64_t paso_lote = (uint64_t)N * T;          /* separacion entre lotes (por hilo) */

    MPI_Barrier(comm);
    double t0 = MPI_Wtime();

    for (uint64_t base = (uint64_t)id; !stop && base < upper;
         base += paso_lote * BATCH_POR_HILO) {

        #pragma omp parallel for schedule(static)
        for (int t = 0; t < T; ++t) {
            unsigned char *work = works[t];
            uint64_t k0 = base + (uint64_t)t * paso_hilo;  /* 1er indice del hilo t */
            for (uint64_t c = 0; c < BATCH_POR_HILO; ++c) {
                if (stop) break;
                uint64_t k = k0 + c * paso_lote;
                if (k >= upper) break;
                if (probar_llave(k, cipher, (int)len, work, palabra)) {
                    #pragma omp critical
                    {
                        if (!stop) { stop = 1; found = (long long)k; }
                    }
                    break;
                }
            }
        }

        /* --- Coordinacion MPI: solo el hilo maestro, fuera de OpenMP --- */
        if (stop) {
            for (int j = 0; j < N; ++j)
                if (j != id)
                    MPI_Send(&found, 1, MPI_LONG_LONG, j, TAG_STOP, comm);
            break;
        } else {
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

    long long global_found;
    MPI_Allreduce(&found, &global_found, 1, MPI_LONG_LONG, MPI_MAX, comm);

    double elapsed = t1 - t0, max_elapsed;
    MPI_Reduce(&elapsed, &max_elapsed, 1, MPI_DOUBLE, MPI_MAX, 0, comm);

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

    /* Drenar avisos de parada pendientes antes de finalizar. */
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
