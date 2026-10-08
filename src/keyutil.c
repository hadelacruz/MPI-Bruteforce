/* keyutil.c - Funciones auxiliares compartidas por las versiones secuencial
 * y paralelas: lectura de archivos y prueba de una llave candidata. */

#include "keyutil.h"
#include "des.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char *leer_archivo(const char *ruta, long *len) {
    FILE *f = fopen(ruta, "rb");
    if (!f) return NULL;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if (n <= 0) { fclose(f); return NULL; }
    rewind(f);

    unsigned char *buf = malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }

    size_t leidos = fread(buf, 1, (size_t)n, f);
    fclose(f);
    if ((long)leidos != n) { free(buf); return NULL; }

    buf[n] = 0;
    *len = n;
    return buf;
}

int probar_llave(uint64_t key, const unsigned char *cipher, int len,
                 unsigned char *work, const char *palabra) {
    memcpy(work, cipher, (size_t)len);
    des_ecb(key, work, len, 1); /* 1 = descifrar */
    work[len] = 0;              /* terminador para tratar el buffer como cadena */
    return strstr((char *)work, palabra) != NULL;
}
