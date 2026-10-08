#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "des.h"

/* key56 se construye a partir de una llave estandar de 64 bits (con bits
 * de paridad, uno por byte, en el bit menos significativo de cada byte),
 * descartando esos 8 bits de paridad -- exactamente como hace la libreria
 * al armar bits64 internamente. Esto permite comparar contra vectores de
 * prueba expresados como llaves DES "clasicas" de 64 bits. */
static uint64_t key56_from_std64(uint64_t stdkey) {
    uint64_t key56 = 0;
    for (int i = 0; i < 64; ++i) {
        int bit = (stdkey >> (63 - i)) & 1;
        if ((i + 1) % 8 == 0) continue;
        key56 = (key56 << 1) | bit;
    }
    return key56;
}

static int check_vector(const char *name, uint64_t stdkey,
                         const uint8_t plain[8], const uint8_t expected[8]) {
    uint8_t subkeys[16][6], cipher[8], recovered[8];
    des_key_schedule(key56_from_std64(stdkey), subkeys);
    des_crypt_block(plain, cipher, subkeys, 0);
    des_crypt_block(cipher, recovered, subkeys, 1);

    int ok_cipher = memcmp(cipher, expected, 8) == 0;
    int ok_roundtrip = memcmp(plain, recovered, 8) == 0;
    printf("[%s] cifrado=%s esperado=", name, ok_cipher ? "OK" : "FALLO");
    for (int i = 0; i < 8; ++i) printf("%02x", expected[i]);
    printf(" obtenido=");
    for (int i = 0; i < 8; ++i) printf("%02x", cipher[i]);
    printf(" round-trip=%s\n", ok_roundtrip ? "OK" : "FALLO");
    return ok_cipher && ok_roundtrip;
}

int main(void) {
    /* Los 3 vectores fueron generados de forma independiente con
     * `openssl enc -des-ecb` para validar esta implementacion propia. */
    int ok = 1;
    {
        uint8_t p[8] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};
        uint8_t c[8] = {0xfd,0x7a,0xd4,0x40,0xb1,0x22,0x0a,0x67};
        ok &= check_vector("vector1", 0x133457799BBCDCFFULL, p, c);
    }
    {
        uint8_t p[8] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
        uint8_t c[8] = {0x35,0x55,0x50,0xb2,0x15,0x0e,0x24,0x51};
        ok &= check_vector("vector2", 0x0000000000000000ULL, p, c);
    }
    {
        uint8_t p[8] = {'I','\x20','l','i','k','e',' ','t'};
        uint8_t c[8] = {0xd7,0xb3,0x5d,0xd9,0x59,0x4d,0x53,0x35};
        ok &= check_vector("vector3", 0x000000000001E240ULL, p, c);
    }
    printf("Resultado global: %s\n", ok ? "OK" : "FALLO");

    /* Prueba adicional con ECB de 16 bytes y una frase legible */
    char text[17] = "I like the sun!!";
    uint64_t demo_key = 123456;
    des_ecb(demo_key, (uint8_t *)text, 16, 0);
    des_ecb(demo_key, (uint8_t *)text, 16, 1);
    text[16] = 0;
    int ok_ecb = strcmp(text, "I like the sun!!") == 0;
    printf("ECB round-trip texto: '%s' -> %s\n", text, ok_ecb ? "OK" : "FALLO");
    ok &= ok_ecb;

    return !ok;
}
