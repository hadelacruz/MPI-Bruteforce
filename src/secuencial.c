/* secuencial.c - Version SECUENCIAL (sin MPI) de la busqueda por fuerza
 * bruta de la llave privada DES. Es la linea base contra la cual se miden
 * los speedups de las versiones paralelas (bruteforce, cyclic, master_worker).
 *
 * Idea: se tiene un texto cifrado y se sabe que el texto claro contiene cierta
 * "palabra clave". Se prueban las llaves 0, 1, 2, ... en orden; para cada una
 * se descifra el texto y se comprueba si aparece la palabra. La primera llave
 * cuyo descifrado contenga la palabra se da por correcta.
 *
 * Uso:
 *   ./secuencial <archivo_cifrado> <palabra_clave> [bits]
 *
 * Ejemplo:
 *   ./secuencial mensaje.bin "respuesta" 24
 */

#include "des.h"       /* des_ecb()        */
#include "keyutil.h"   /* leer_archivo(), probar_llave() */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>      /* clock_gettime(): medicion de tiempo monotono */

/* Modo de empleo en stderr. */
static void uso(const char *prog) {
    fprintf(stderr, "Uso: %s <archivo_cifrado> <palabra_clave> [bits]\n", prog);
    fprintf(stderr, "  bits : espacio de busqueda = 2^bits llaves (1..56, por defecto 56)\n");
}

int main(int argc, char *argv[]) {
    /* Se requieren al menos 2 argumentos: archivo y palabra. 'bits' es opcional. */
    if (argc < 3) { uso(argv[0]); return 1; }

    const char *archivo = argv[1];
    const char *palabra = argv[2];
    /* 'bits' acota el espacio de busqueda a 2^bits llaves. Por defecto 56
     * (tamano real de la llave DES). Valores pequenos sirven para pruebas. */
    int bits = (argc >= 4) ? atoi(argv[3]) : 56;

    /* --- Validacion defensiva de entradas --- */
    if (palabra[0] == '\0') {
        fprintf(stderr, "Error: la palabra clave no puede estar vacia\n");
        return 1;
    }
    if (bits < 1 || bits > 56) {
        fprintf(stderr, "Error: bits debe estar entre 1 y 56\n");
        return 1;
    }

    /* --- Lectura del texto cifrado --- */
    long len;
    unsigned char *cipher = leer_archivo(archivo, &len);
    if (!cipher) {
        fprintf(stderr, "Error: no se pudo leer el archivo cifrado '%s'\n", archivo);
        return 1;
    }
    /* El texto cifrado por DES siempre es multiplo de 8 bytes; si no lo es,
     * el archivo no fue generado por nuestra utilidad 'cifrar' y se rechaza. */
    if (len % 8 != 0) {
        fprintf(stderr, "Error: el texto cifrado debe ser multiplo de 8 bytes (es %ld)\n", len);
        free(cipher);
        return 1;
    }

    /* 'work' es un buffer de trabajo donde probar_llave vuelca el descifrado
     * de cada llave candidata (asi NO se modifica 'cipher'). Se reserva len+1
     * para poder colocar un '\0' terminador al imprimir el resultado. */
    unsigned char *work = malloc((size_t)len + 1);
    if (!work) {
        fprintf(stderr, "Error: memoria insuficiente\n");
        free(cipher);
        return 1;
    }

    /* upper = 2^bits = cota superior (exclusiva) del espacio de llaves. */
    uint64_t upper = 1ULL << bits;
    long long encontrada = -1;   /* -1 = aun no encontrada */

    /* --- Bucle de fuerza bruta, cronometrado con reloj monotono --- */
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (uint64_t k = 0; k < upper; ++k) {
        /* probar_llave descifra con 'k' sobre 'work' y devuelve 1 si el
         * resultado contiene 'palabra' como substring. */
        if (probar_llave(k, cipher, (int)len, work, palabra)) {
            encontrada = (long long)k;
            break;  /* primera coincidencia: se detiene la busqueda */
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    /* Tiempo transcurrido en segundos (parte en segundos + parte en nanos). */
    double seg = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;

    /* --- Reporte de resultados --- */
    if (encontrada >= 0) {
        /* Se vuelve a descifrar con la llave hallada para mostrar el texto
         * claro completo (el bucle solo guardaba el hecho de haberla hallado). */
        memcpy(work, cipher, (size_t)len);
        des_ecb((uint64_t)encontrada, work, (int)len, 1);
        work[len] = 0;  /* terminador para imprimir como cadena */
        printf("Llave encontrada : %lld\n", encontrada);
        printf("Archivo cifrado  : %s\n", archivo);
        printf("Palabra clave    : %s\n", palabra);
        printf("Texto descifrado : %s\n", work);
    } else {
        printf("Llave NO encontrada en el espacio [0, 2^%d)\n", bits);
        printf("Archivo cifrado  : %s\n", archivo);
        printf("Palabra clave    : %s\n", palabra);
    }
    printf("Tiempo           : %.4f s\n", seg);

    free(work);
    free(cipher);
    return 0;
}
