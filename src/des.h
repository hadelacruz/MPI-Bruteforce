#ifndef DES_H
#define DES_H

#include <stdint.h>

/* Genera las 16 subllaves de ronda (48 bits cada una, almacenadas como
 * arreglos de 6 bytes empaquetados) a partir de una llave de 56 bits. */
void des_key_schedule(uint64_t key56, uint8_t subkeys[16][6]);

/* Cifra/descifra un bloque de 8 bytes en modo ECB usando las subllaves
 * ya calculadas. decrypt=0 -> cifra, decrypt=1 -> descifra. */
void des_crypt_block(const uint8_t in[8], uint8_t out[8],
                      const uint8_t subkeys[16][6], int decrypt);

/* Envoltura de conveniencia: cifra/descifra 'len' bytes (multiplo de 8)
 * en modo ECB, calculando internamente el key schedule. */
void des_ecb(uint64_t key56, uint8_t *buf, int len, int decrypt);

#endif
