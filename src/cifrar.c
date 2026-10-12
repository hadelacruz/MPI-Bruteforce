/* cifrar.c - Utilidad para cifrar o descifrar un archivo de texto con DES
 * usando una llave privada arbitraria pasada como parametro.
 *
 * Cubre el requisito de la Parte B: "cifre un texto cargado desde un archivo
 * (.txt) usando una llave privada arbitraria (como parametro)". Tambien se
 * usa para generar los archivos cifrados que luego rompen los programas de
 * fuerza bruta (secuencial, bruteforce, cyclic, master_worker).
 *
 * Uso:
 *   ./cifrar -e <archivo_entrada> <llave> <archivo_salida>   (cifrar)
 *   ./cifrar -d <archivo_entrada> <llave> <archivo_salida>   (descifrar)
 *
 * Ejemplo:
 *   ./cifrar -e mensaje.txt 42 mensaje.bin   # cifra con la llave 42
 *   ./cifrar -d mensaje.bin 42 recuperado.txt
 */

#include "des.h"       /* des_ecb(): cifra/descifra un buffer en modo ECB   */
#include "keyutil.h"   /* leer_archivo(): carga un archivo completo a RAM   */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Imprime en stderr el modo de empleo. Se llama ante cualquier error de
 * argumentos para que el usuario sepa como invocar el programa. */
static void uso(const char *prog) {
    fprintf(stderr, "Uso: %s <-e|-d> <archivo_entrada> <llave> <archivo_salida>\n", prog);
    fprintf(stderr, "  -e : cifrar    -d : descifrar\n");
    fprintf(stderr, "  <llave> : entero sin signo en base 10 (ej. 42)\n");
}

int main(int argc, char *argv[]) {
    /* Se exigen exactamente 4 argumentos (mas el nombre del programa = 5). */
    if (argc != 5) { uso(argv[0]); return 1; }

    /* --- 1. Modo de operacion: -e (cifrar) o -d (descifrar) --- */
    int cifrar;
    if (strcmp(argv[1], "-e") == 0)      cifrar = 1;
    else if (strcmp(argv[1], "-d") == 0) cifrar = 0;
    else { uso(argv[0]); return 1; }  /* cualquier otro flag es invalido */

    const char *entrada = argv[2];

    /* --- 2. Parseo defensivo de la llave ---
     * strtoull convierte la cadena a entero sin signo. 'fin' queda apuntando
     * al primer caracter no consumido: si no es '\0' (o la cadena esta vacia)
     * significa que el argumento no era un numero valido y se rechaza. */
    char *fin;
    unsigned long long llave = strtoull(argv[3], &fin, 10);
    if (argv[3][0] == '\0' || *fin != '\0') {
        fprintf(stderr, "Llave invalida: '%s'\n", argv[3]);
        return 1;
    }
    const char *salida = argv[4];

    /* --- 3. Lectura del archivo de entrada a un buffer en memoria ---
     * leer_archivo reserva el buffer con malloc y escribe el tamano en 'len'.
     * Devuelve NULL ante cualquier error (archivo inexistente, etc.). */
    long len;
    unsigned char *datos = leer_archivo(entrada, &len);
    if (!datos) {
        fprintf(stderr, "Error: no se pudo leer el archivo de entrada '%s'\n", entrada);
        return 1;
    }

    /* --- 4. Relleno (padding) a multiplo de 8 bytes ---
     * DES cifra en bloques de 8 bytes. Si el texto no es multiplo de 8, se
     * redondea hacia arriba al siguiente multiplo y los bytes sobrantes se
     * rellenan con ceros. calloc deja esos bytes en 0 automaticamente; el
     * relleno nulo es invisible al imprimir el texto como cadena. */
    int padded = (int)(((len + 7) / 8) * 8);
    unsigned char *buf = calloc((size_t)padded, 1);
    if (!buf) {
        fprintf(stderr, "Error: memoria insuficiente\n");
        free(datos);
        return 1;
    }
    memcpy(buf, datos, (size_t)len);  /* copia el contenido real; resto = 0 */
    free(datos);                      /* 'datos' ya no se necesita           */

    /* --- 5. Cifrado/descifrado en sitio ---
     * des_ecb opera sobre 'buf' modificandolo. El ultimo parametro es el
     * modo: 0 = cifrar, 1 = descifrar (por eso se invierte 'cifrar'). */
    des_ecb((uint64_t)llave, buf, padded, cifrar ? 0 : 1);

    /* --- 6. Escritura del resultado en modo binario ---
     * Se abre "wb" porque el texto cifrado NO es texto imprimible: contiene
     * bytes arbitrarios y no debe sufrir conversiones de fin de linea. */
    FILE *f = fopen(salida, "wb");
    if (!f) {
        fprintf(stderr, "Error: no se pudo crear el archivo de salida '%s'\n", salida);
        free(buf);
        return 1;
    }
    fwrite(buf, 1, (size_t)padded, f);
    fclose(f);

    /* --- 7. Mensaje informativo segun la operacion --- */
    if (cifrar)
        printf("Cifrado:  '%s' (%ld bytes -> %d) con llave %llu  =>  '%s'\n",
               entrada, len, padded, llave, salida);
    else
        printf("Descifrado: '%s' con llave %llu  =>  '%s'\n", entrada, llave, salida);

    free(buf);
    return 0;
}
