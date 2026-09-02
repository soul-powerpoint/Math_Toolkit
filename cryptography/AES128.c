#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef unsigned __int128 uint128_t;

static uint32_t plaintext0 = 0xABCDABCD;
static uint32_t plaintext1 = 0x01234567;
static uint32_t plaintext2 = 0xABCDABCD;
static uint32_t plaintext3 = 0x76543210;
static uint32_t mask = 0x000000FF;

static const uint8_t plaintext[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};

static const uint8_t static_key[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static const uint8_t aes_sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static uint8_t inv_sbox[256];

static void build_inv_sbox(void) {
    for (int i = 0; i < 256; i++)
        inv_sbox[aes_sbox[i]] = (uint8_t) i;
}

static const uint8_t **malloc_block(uint8_t *plaintext) {
    uint8_t **block = malloc(sizeof(uint8_t *) * 4);

    for (int i = 0; i < 4; i++) {
        block[i] = malloc(sizeof(uint8_t) * 4);
        for (int j = 0; j < 4; j++) {
            block[i][j] = plaintext[i + 4 * j];
        }
    }

    return block;
}

static const void print_block(uint8_t **block) {
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            printf("%X", block[r][c]);
            if (c != 3) {
                putchar(32);
            }
        }
        putchar(10);
    }
}

static const void free_block(uint8_t **block) {
    for (int i = 0; i < 4; i++) {
        free(block[i]);
    }

    free(block);
}

static void key_expansion(const uint8_t key[16], uint8_t out[176]) {
    static const uint8_t rcon[10] = {
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
    };

    memcpy(out, key, 16);
 
    for (int i = 4; i < 44; i++) {
        uint8_t t[4];
        memcpy(t, out + 4 * (i - 1), 4);
 
        if (i % 4 == 0) {
            uint8_t tmp = t[0];
            t[0] = t[1];
            t[1] = t[2];
            t[2] = t[3];
            t[3] = tmp;

            for (int k = 0; k < 4; k++)
                t[k] = aes_sbox[t[k]];
            t[0] ^= rcon[i / 4 - 1];
        }

        for (int k = 0; k < 4; k++)
            out[4 * i + k] = out[4 * (i - 4) + k] ^ t[k];
    }
}

static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1B;
        b >>= 1;
    }
    return p;
}

void substitute_byte(uint8_t **block) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            block[i][j] = aes_sbox[block[i][j]];
        }
    }
}

void inv_substitute_byte(uint8_t **block) {
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            block[r][c] = inv_sbox[block[r][c]];
}

void shift_rows(uint8_t **block) {
    uint8_t *r0 = block[0];
    uint8_t *r1 = block[1];
    uint8_t *r2 = block[2];
    uint8_t *r3 = block[3];

    uint8_t temp = r1[0];
    r1[0] = r1[1];
    r1[1] = r1[2];
    r1[2] = r1[3];
    r1[3] = temp;

    uint8_t temp0 = r2[0];
    uint8_t temp1 = r2[1];
    r2[0] = r2[2];
    r2[2] = temp0;
    r2[1] = r2[3];
    r2[3] = temp1;

    temp = r3[3];
    r3[3] = r3[2];
    r3[2] = r3[1];
    r3[1] = r3[0];
    r3[0] = temp;
}

void inv_shift_rows(uint8_t **block) {
    uint8_t *r1 = block[1];
    uint8_t *r2 = block[2];
    uint8_t *r3 = block[3];

    uint8_t temp = r1[3];
    r1[3] = r1[2];
    r1[2] = r1[1];
    r1[1] = r1[0];
    r1[0] = temp;

    uint8_t temp0 = r2[0];
    uint8_t temp1 = r2[1];
    r2[0] = r2[2];
    r2[2] = temp0;
    r2[1] = r2[3];
    r2[3] = temp1;

    temp = r3[0];
    r3[0] = r3[1];
    r3[1] = r3[2];
    r3[2] = r3[3];
    r3[3] = temp;
}

void mix_columns(uint8_t **block) {
    uint8_t *r0 = block[0];
    uint8_t *r1 = block[1];
    uint8_t *r2 = block[2];
    uint8_t *r3 = block[3];

    for (int c = 0; c < 4; c++) {
        uint8_t a0 = r0[c], a1 = r1[c], a2 = r2[c], a3 = r3[c];

        r0[c] = gmul(a0, 2) ^ gmul(a1, 3) ^ gmul(a2, 1) ^ gmul(a3, 1);
        r1[c] = gmul(a0, 1) ^ gmul(a1, 2) ^ gmul(a2, 3) ^ gmul(a3, 1);
        r2[c] = gmul(a0, 1) ^ gmul(a1, 1) ^ gmul(a2, 2) ^ gmul(a3, 3);
        r3[c] = gmul(a0, 3) ^ gmul(a1, 1) ^ gmul(a2, 1) ^ gmul(a3, 2);
    }
}

void inv_mix_columns(uint8_t **block) {
    uint8_t *r0 = block[0];
    uint8_t *r1 = block[1];
    uint8_t *r2 = block[2];
    uint8_t *r3 = block[3];

    for (int c = 0; c < 4; c++) {
        uint8_t a0 = r0[c], a1 = r1[c], a2 = r2[c], a3 = r3[c];

        r0[c] = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9);
        r1[c] = gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13);
        r2[c] = gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11);
        r3[c] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14);
    }
}

void add_round_key(uint8_t **block, uint8_t *round_key) {
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            block[r][c] ^= round_key[r + 4 * c];
        }
    }
}

int main(int argc, char **argv) {
    uint8_t round_keys[176];
    key_expansion(static_key, round_keys);

    uint8_t **block = malloc_block(plaintext);

    printf("Plaintext:\n");
    print_block(block);
    putchar(10);

    add_round_key(block, static_key);

    for (int round = 1; round <= 10; round++) {
        substitute_byte(block);
        shift_rows(block);
        if (round != 10) {
            mix_columns(block);
        }
        add_round_key(block, round_keys + 16 * round);
    }

    printf("Ciphertext:\n");
    print_block(block);
    putchar(10);

    build_inv_sbox();

    for (int round = 10; round >= 1; round--) {
        add_round_key(block, round_keys + 16 * round);
        if (round != 10) {
            inv_mix_columns(block);
        }
        inv_shift_rows(block);
        inv_substitute_byte(block);
    }

    add_round_key(block, round_keys);

    printf("Decrpted text\n");
    print_block(block);
    free_block(block);
    return 0;
}
