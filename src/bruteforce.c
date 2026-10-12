/* bruteforce.c - Version PARALELA "NAIVE" (de bloques) de la busqueda por
 * fuerza bruta de la llave DES, con MPI. Es la version base entregada en
 * Canvas, adaptada para:
 *   (1) usar el modulo DES propio des.c/des.h en vez de <rpc/des_crypt.h>;
 *   (2) leer el texto cifrado desde un archivo y la palabra clave como
 *       parametro (programacion defensiva de entradas);
 *   (3) corregir dos fallos del codigo original:
 *       - "off-by-one": el ultimo valor de cada bloque nunca se probaba;
 *       - los procesos no se detenian al encontrar otro la llave (el
 *         MPI_Irecv nunca progresaba). Aqui se sondea con MPI_Iprobe.
 *
 * Reparto NAIVE: el espacio [0, 2^bits) se divide en N bloques CONTIGUOS,
 * uno por proceso. El proceso id busca en [id*base, (id+1)*base). Es simple
 * pero puede quedar desbalanceado (si la llave cae en el primer bloque, los
 * demas procesos trabajan de mas hasta recibir la senal de parada).
 *
 * Uso:
 *   mpirun -np <N> ./bruteforce <archivo_cifrado> <palabra_clave> [bits]
 */

#include "des.h"
#include "keyutil.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mpi.h>

#define TAG_STOP 1              /* etiqueta del mensaje: "ya se encontro la llave K" */
#define CHECK_INTERVAL (1u<<12) /* cada cuantas iteraciones se sondea el STOP        */

int main(int argc, char *argv[]) {
    MPI_Init(&argc, &argv);

    /* --- Identidad de cada proceso dentro del comunicador global --- */
    int N, id;
    MPI_Comm comm = MPI_COMM_WORLD;
    MPI_Comm_size(comm, &N);   /* N  = numero total de procesos  */
    MPI_Comm_rank(comm, &id);  /* id = rango de ESTE proceso (0..N-1) */

    /* --- Validacion de argumentos (solo el proceso 0 imprime el error) --- */
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

    /* --- Carga y difusion del texto cifrado ---
     * Solo el proceso 0 toca el disco; luego reparte el contenido a todos con
     * MPI_Bcast. Asi se evita que N procesos lean el mismo archivo a la vez. */
    long len = 0;
    unsigned char *cipher = NULL;
    if (id == 0) {
        cipher = leer_archivo(archivo, &len);
        /* Si algo esta mal (archivo invalido, tamano no multiplo de 8, o
         * palabra vacia) se marca len = -1 como senal de error a difundir. */
        if (!cipher || len % 8 != 0 || palabra[0] == '\0') {
            fprintf(stderr, "Error: archivo cifrado invalido o palabra clave vacia\n");
            len = -1;
        }
    }
    /* 1er broadcast: el tamano (y/o la senal de error). Todos los procesos
     * necesitan 'len' antes de poder reservar su copia del buffer. */
    MPI_Bcast(&len, 1, MPI_LONG, 0, comm);
    if (len < 0) { free(cipher); MPI_Finalize(); return 1; }  /* abortar limpio */

    /* Los procesos != 0 aun no tienen buffer: lo reservan ahora (len+1 para
     * poder colocar un terminador '\0'). */
    if (id != 0) cipher = malloc((size_t)len + 1);
    if (!cipher) { fprintf(stderr, "Rank %d: memoria insuficiente\n", id); MPI_Abort(comm, 1); }
    /* 2do broadcast: el contenido cifrado en si. */
    MPI_Bcast(cipher, (int)len, MPI_UNSIGNED_CHAR, 0, comm);
    cipher[len] = 0;

    /* Buffer de trabajo local donde cada proceso descifra sus candidatas. */
    unsigned char *work = malloc((size_t)len + 1);
    if (!work) { fprintf(stderr, "Rank %d: memoria insuficiente\n", id); MPI_Abort(comm, 1); }

    /* --- Reparto NAIVE de bloques contiguos ---
     * base    = tamano de cada bloque = 2^bits / N (division entera).
     * mylower = inicio del bloque de este proceso.
     * myupper = fin (exclusivo); el ULTIMO proceso absorbe el resto de la
     *           division para cubrir TODO el espacio (evita el off-by-one). */
    uint64_t upper = 1ULL << bits;
    uint64_t base  = upper / (uint64_t)N;
    uint64_t mylower = base * (uint64_t)id;
    uint64_t myupper = (id == N - 1) ? upper : base * (uint64_t)(id + 1); /* rango [mylower, myupper) */

    long long found = -1;  /* llave hallada por/comunicada a este proceso */

    /* Barrera para que todos arranquen el cronometro a la vez y la medicion
     * del tiempo paralelo sea comparable entre procesos. */
    MPI_Barrier(comm);
    double t0 = MPI_Wtime();

    unsigned long contador = 0;
    for (uint64_t k = mylower; k < myupper; ++k) {
        /* Caso 1: ESTE proceso encuentra la llave. */
        if (probar_llave(k, cipher, (int)len, work, palabra)) {
            found = (long long)k;
            /* Avisa a todos los demas para que detengan su busqueda. */
            for (int j = 0; j < N; ++j)
                if (j != id)
                    MPI_Send(&found, 1, MPI_LONG_LONG, j, TAG_STOP, comm);
            break;
        }
        /* Caso 2: cada CHECK_INTERVAL iteraciones, revisar si OTRO proceso ya
         * encontro la llave. Se usa MPI_Iprobe (sondeo NO bloqueante): si hay
         * un mensaje STOP pendiente, se recibe y se corta. No sondear en cada
         * iteracion evita el coste de comunicacion en el camino rapido. */
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

    /* --- Consolidacion del resultado ---
     * Cada proceso tiene 'found' = llave (si la hallo o la recibio) o -1.
     * MPI_Allreduce con MPI_MAX deja en 'global_found' el maximo de todos:
     * como las llaves validas son >= 0 y el "no encontrado" es -1, el maximo
     * es justamente la llave correcta (o -1 si nadie la hallo). */
    long long global_found;
    MPI_Allreduce(&found, &global_found, 1, MPI_LONG_LONG, MPI_MAX, comm);

    /* El tiempo reportado es el del proceso mas lento (MPI_MAX): refleja el
     * tiempo real de pared hasta que TODO el trabajo util termino. */
    double elapsed = t1 - t0, max_elapsed;
    MPI_Reduce(&elapsed, &max_elapsed, 1, MPI_DOUBLE, MPI_MAX, 0, comm);

    /* --- Reporte (solo el proceso 0) --- */
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
        printf("Enfoque          : naive (bloques contiguos)\n");
        printf("Procesos         : %d\n", N);
        printf("Tiempo           : %.4f s\n", max_elapsed);
    }

    /* --- Drenaje de mensajes STOP pendientes ---
     * El que encontro la llave envio un STOP a cada proceso, pero algunos
     * pudieron terminar su bloque (o recibir otro STOP) antes de consumirlo.
     * Esos mensajes quedarian "colgados" en las colas internas de MPI; se
     * reciben todos aqui para que MPI_Finalize cierre sin fugas. */
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
