/* cyclic.c - ALTERNATIVA 1 al enfoque naive: reparto CICLICO (intercalado).
 *
 * En vez de darle a cada proceso un bloque contiguo gigante, el proceso id
 * prueba las llaves id, id+N, id+2N, ... es decir, los N procesos "barren"
 * todo el espacio de forma intercalada, con paso N.
 *
 * Motivacion (ver informe): con el reparto naive, el tiempo depende
 * dramaticamente de DONDE caiga la llave (si cae al inicio de un bloque se
 * encuentra al instante; si cae al final del primer bloque no hay speedup).
 * Con el reparto ciclico, una llave en la posicion p es probada por el
 * proceso (p mod N) tras ~p/N iteraciones, sin importar donde este p: el
 * tiempo esperado y el speedup (~N) son consistentes.
 *
 * Uso:
 *   mpirun -np <N> ./cyclic <archivo_cifrado> <palabra_clave> [bits]
 */

#include "des.h"
#include "keyutil.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mpi.h>

#define TAG_STOP 1              /* etiqueta del mensaje "ya se encontro la llave" */
#define CHECK_INTERVAL (1u<<12) /* cada cuantas iteraciones se sondea el STOP     */

int main(int argc, char *argv[]) {
    MPI_Init(&argc, &argv);

    /* Identidad del proceso: N = total de procesos, id = rango propio. */
    int N, id;
    MPI_Comm comm = MPI_COMM_WORLD;
    MPI_Comm_size(comm, &N);
    MPI_Comm_rank(comm, &id);

    /* --- Validacion de argumentos (solo el proceso 0 reporta) --- */
    if (argc < 3) {
        if (id == 0)
            fprintf(stderr, "Uso: mpirun -np <N> %s <archivo_cifrado> <palabra_clave> [bits]\n", argv[0]);
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

    /* --- Carga del cifrado por el proceso 0 y difusion a todos ---
     * (identico a bruteforce: primero se difunde el tamano, luego el buffer). */
    long len = 0;
    unsigned char *cipher = NULL;
    if (id == 0) {
        cipher = leer_archivo(archivo, &len);
        if (!cipher || len % 8 != 0 || palabra[0] == '\0') {
            fprintf(stderr, "Error: archivo cifrado invalido o palabra clave vacia\n");
            len = -1;   /* senal de error que se difunde a todos */
        }
    }
    MPI_Bcast(&len, 1, MPI_LONG, 0, comm);
    if (len < 0) { free(cipher); MPI_Finalize(); return 1; }

    if (id != 0) cipher = malloc((size_t)len + 1);
    if (!cipher) { fprintf(stderr, "Rank %d: memoria insuficiente\n", id); MPI_Abort(comm, 1); }
    MPI_Bcast(cipher, (int)len, MPI_UNSIGNED_CHAR, 0, comm);
    cipher[len] = 0;

    unsigned char *work = malloc((size_t)len + 1);  /* buffer de descifrado local */
    if (!work) { fprintf(stderr, "Rank %d: memoria insuficiente\n", id); MPI_Abort(comm, 1); }

    uint64_t upper = 1ULL << bits;  /* cota superior (exclusiva) del espacio */
    long long found = -1;

    MPI_Barrier(comm);              /* todos arrancan el cronometro a la vez */
    double t0 = MPI_Wtime();

    /* --- Reparto CICLICO: el proceso id prueba id, id+N, id+2N, ... ---
     * El paso +N garantiza que cada llave del espacio la cubre exactamente un
     * proceso (el id = k mod N) y que todos avanzan "en paralelo" por todo el
     * rango, en lugar de concentrarse en una franja contigua. */
    unsigned long contador = 0;
    for (uint64_t k = (uint64_t)id; k < upper; k += (uint64_t)N) {
        if (probar_llave(k, cipher, (int)len, work, palabra)) {
            found = (long long)k;
            /* Avisa a los demas procesos para que corten su busqueda. */
            for (int j = 0; j < N; ++j)
                if (j != id)
                    MPI_Send(&found, 1, MPI_LONG_LONG, j, TAG_STOP, comm);
            break;
        }
        /* Sondeo periodico no bloqueante: ¿otro proceso ya la encontro? */
        if ((++contador % CHECK_INTERVAL) == 0) {
            int flag = 0;
            MPI_Status st;
            MPI_Iprobe(MPI_ANY_SOURCE, TAG_STOP, comm, &flag, &st);
            if (flag) {
                MPI_Recv(&found, 1, MPI_LONG_LONG, st.MPI_SOURCE, TAG_STOP, comm, MPI_STATUS_IGNORE);
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

    /* --- Reporte (solo proceso 0) --- */
    if (id == 0) {
        if (global_found >= 0) {
            memcpy(work, cipher, (size_t)len);
            des_ecb((uint64_t)global_found, work, (int)len, 1);
            work[len] = 0;
            printf("Llave encontrada : %lld\n", global_found);
            printf("Archivo cifrado  : %s\n", archivo);
            printf("Palabra clave    : %s\n", palabra);
            printf("Texto descifrado : %s\n", work);
        } else {
            printf("Llave NO encontrada en [0, 2^%d)\n", bits);
            printf("Archivo cifrado  : %s\n", archivo);
            printf("Palabra clave    : %s\n", palabra);
        }
        printf("Enfoque          : ciclico (intercalado, paso N)\n");
        printf("Procesos         : %d\n", N);
        printf("Tiempo           : %.4f s\n", max_elapsed);
    }

    /* Drenaje de mensajes STOP pendientes antes de finalizar (evita colgados). */
    int flag = 1;
    while (flag) {
        MPI_Status st;
        MPI_Iprobe(MPI_ANY_SOURCE, TAG_STOP, comm, &flag, &st);
        if (flag) {
            long long tmp;
            MPI_Recv(&tmp, 1, MPI_LONG_LONG, st.MPI_SOURCE, TAG_STOP, comm, MPI_STATUS_IGNORE);
        }
    }

    free(work);
    free(cipher);
    MPI_Finalize();
    return 0;
}
