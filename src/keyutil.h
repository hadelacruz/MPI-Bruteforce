#ifndef KEYUTIL_H
#define KEYUTIL_H

#include <stdint.h>

/* Lee un archivo binario completo a un buffer recien asignado con malloc.
 * Devuelve el buffer (el llamador debe liberarlo con free) y escribe el
 * numero de bytes leidos en *len. Devuelve NULL si ocurre cualquier error. */
unsigned char *leer_archivo(const char *ruta, long *len);

/* Prueba una llave candidata: descifra una COPIA del texto cifrado sobre el
 * buffer de trabajo 'work' (de tamano al menos len+1) y verifica si el
 * resultado contiene 'palabra' como substring. No modifica 'cipher'.
 * Devuelve 1 si la palabra aparece (llave candidata correcta), 0 si no. */
int probar_llave(uint64_t key, const unsigned char *cipher, int len,
                 unsigned char *work, const char *palabra);

#endif
