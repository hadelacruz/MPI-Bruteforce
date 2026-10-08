/* des.c - Implementacion propia y compacta de DES (FIPS 46-3), modo ECB.
 * Escrita para el Proyecto 2 (Computacion Paralela y Distribuida, UVG)
 * como reemplazo portable de <rpc/des_crypt.h>, que no existe fuera de
 * Solaris/glibc antiguo. No depende de ninguna libreria externa. */

#include "des.h"
#include <string.h>

static const int IP[64] = {
    58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6, 64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,  59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7
};

static const int FP[64] = {
    40,8,48,16,56,24,64,32, 39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30, 37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28, 35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26, 33,1,41,9,49,17,57,25
};

static const int E[48] = {
    32,1,2,3,4,5, 4,5,6,7,8,9, 8,9,10,11,12,13, 12,13,14,15,16,17,
    16,17,18,19,20,21, 20,21,22,23,24,25, 24,25,26,27,28,29, 28,29,30,31,32,1
};

static const int P[32] = {
    16,7,20,21,29,12,28,17, 1,15,23,26,5,18,31,10,
    2,8,24,14,32,27,3,9, 19,13,30,6,22,11,4,25
};

static const int PC1[56] = {
    57,49,41,33,25,17,9, 1,58,50,42,34,26,18,
    10,2,59,51,43,35,27, 19,11,3,60,52,44,36,
    63,55,47,39,31,23,15, 7,62,54,46,38,30,22,
    14,6,61,53,45,37,29, 21,13,5,28,20,12,4
};

static const int PC2[48] = {
    14,17,11,24,1,5, 3,28,15,6,21,10, 23,19,12,4,26,8, 16,7,27,20,13,2,
    41,52,31,37,47,55, 30,40,51,45,33,48, 44,49,39,56,34,53, 46,42,50,36,29,32
};

static const int SHIFTS[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};

static const int SBOX[8][4][16] = {
{{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
 {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
 {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
 {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},
{{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
 {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
 {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
 {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},
{{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
 {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
 {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
 {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},
{{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
 {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
 {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
 {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},
{{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
 {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
 {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
 {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},
{{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
 {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
 {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
 {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},
{{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
 {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
 {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
 {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},
{{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
 {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
 {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
 {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}
};

/* --- utilidades de bits: se trabaja con 1 bit por byte (0/1), indices
 * logicos 1..n como en las tablas de la especificacion FIPS. --- */

static void permute(const uint8_t *in, uint8_t *out, const int *table, int n) {
    for (int i = 0; i < n; ++i) out[i] = in[table[i] - 1];
}

static void bytes_to_bits(const uint8_t bytes[8], uint8_t bits[64]) {
    for (int i = 0; i < 64; ++i) bits[i] = (bytes[i / 8] >> (7 - (i % 8))) & 1;
}

static void bits_to_bytes(const uint8_t bits[64], uint8_t bytes[8]) {
    memset(bytes, 0, 8);
    for (int i = 0; i < 64; ++i) bytes[i / 8] |= bits[i] << (7 - (i % 8));
}

static void pack48(const uint8_t bits[48], uint8_t out[6]) {
    memset(out, 0, 6);
    for (int i = 0; i < 48; ++i) out[i / 8] |= bits[i] << (7 - (i % 8));
}

static void unpack48(const uint8_t in[6], uint8_t bits[48]) {
    for (int i = 0; i < 48; ++i) bits[i] = (in[i / 8] >> (7 - (i % 8))) & 1;
}

void des_key_schedule(uint64_t key56, uint8_t subkeys[16][6]) {
    /* Se reconstruye una palabra de 64 bits insertando un bit "de paridad"
     * en 0 cada 8 posiciones. PC1 nunca selecciona esas posiciones, asi
     * que su valor no afecta el resultado del cifrado (ver informe). */
    uint8_t bits64[64];
    int src = 0;
    for (int i = 0; i < 64; ++i) {
        if ((i + 1) % 8 == 0) {
            bits64[i] = 0;
        } else {
            bits64[i] = (key56 >> (55 - src)) & 1ULL;
            src++;
        }
    }

    uint8_t cd[56];
    permute(bits64, cd, PC1, 56);

    uint8_t c[28], d[28];
    memcpy(c, cd, 28);
    memcpy(d, cd + 28, 28);

    for (int round = 0; round < 16; ++round) {
        int s = SHIFTS[round];
        uint8_t ctmp[28], dtmp[28];
        for (int i = 0; i < 28; ++i) ctmp[i] = c[(i + s) % 28];
        for (int i = 0; i < 28; ++i) dtmp[i] = d[(i + s) % 28];
        memcpy(c, ctmp, 28);
        memcpy(d, dtmp, 28);

        uint8_t cdround[56], k48[48];
        memcpy(cdround, c, 28);
        memcpy(cdround + 28, d, 28);
        permute(cdround, k48, PC2, 48);
        pack48(k48, subkeys[round]);
    }
}

static void feistel(const uint8_t r[32], const uint8_t subkey[6], uint8_t out[32]) {
    uint8_t er[48], k48[48], x[48];
    permute(r, er, E, 48);
    unpack48(subkey, k48);
    for (int i = 0; i < 48; ++i) x[i] = er[i] ^ k48[i];

    uint8_t sout[32];
    for (int box = 0; box < 8; ++box) {
        const uint8_t *b = x + box * 6;
        int row = (b[0] << 1) | b[5];
        int col = (b[1] << 3) | (b[2] << 2) | (b[3] << 1) | b[4];
        int val = SBOX[box][row][col];
        for (int bit = 0; bit < 4; ++bit)
            sout[box * 4 + bit] = (val >> (3 - bit)) & 1;
    }
    permute(sout, out, P, 32);
}

void des_crypt_block(const uint8_t in[8], uint8_t out[8],
                      const uint8_t subkeys[16][6], int decrypt) {
    uint8_t bits[64], ip[64];
    bytes_to_bits(in, bits);
    permute(bits, ip, IP, 64);

    uint8_t l[32], r[32];
    memcpy(l, ip, 32);
    memcpy(r, ip + 32, 32);

    for (int round = 0; round < 16; ++round) {
        int idx = decrypt ? (15 - round) : round;
        uint8_t f[32], newr[32];
        feistel(r, subkeys[idx], f);
        for (int i = 0; i < 32; ++i) newr[i] = l[i] ^ f[i];
        memcpy(l, r, 32);
        memcpy(r, newr, 32);
    }

    uint8_t preout[64], fp[64];
    memcpy(preout, r, 32);      /* intercambio final R16L16 */
    memcpy(preout + 32, l, 32);
    permute(preout, fp, FP, 64);
    bits_to_bytes(fp, out);
}

void des_ecb(uint64_t key56, uint8_t *buf, int len, int decrypt) {
    uint8_t subkeys[16][6];
    des_key_schedule(key56, subkeys);
    for (int off = 0; off + 8 <= len; off += 8) {
        uint8_t block[8];
        des_crypt_block(buf + off, block, subkeys, decrypt);
        memcpy(buf + off, block, 8);
    }
}
