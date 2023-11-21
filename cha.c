#include <stdio.h>
#include <getopt.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <sodium.h>
#include <math.h>
#include "cha.h"

const uint32_t CHACONST[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};

/* Left rotation of n by d bits */
#define leftRotate(n, d) \
    (n << d) | (n >> (32 - d));

#define QUARTERROUND(arr, a, b, c, d) \
    arr[a] += arr[b]; arr[d] ^= arr[a]; arr[d] = leftRotate(arr[d], 16); \
    arr[c] += arr[d]; arr[b] ^= arr[c]; arr[b] = leftRotate(arr[b], 12); \
    arr[a] += arr[b]; arr[d] ^= arr[a]; arr[d] = leftRotate(arr[d], 8); \
    arr[c] += arr[d]; arr[b] ^= arr[c]; arr[b] = leftRotate(arr[b], 7);

/**
 * Consumes current state and increment the counter
*/
void chacha20_block(struct chacha_ctx* ctx) {
    uint32_t* keystream = ctx->keystream;
    uint32_t* state = ctx->state;

    memcpy(keystream, state, 16 * sizeof(uint32_t));
    for (int i = 0; i < 10; i++) {
        QUARTERROUND(keystream, 0, 4, 8, 12);
        QUARTERROUND(keystream, 1, 5, 9, 13);
        QUARTERROUND(keystream, 2, 6, 10, 14);
        QUARTERROUND(keystream, 3, 7, 11, 15);
        QUARTERROUND(keystream, 0, 5, 10, 15);
        QUARTERROUND(keystream, 1, 6, 11, 12);
        QUARTERROUND(keystream, 2, 7, 8, 13);
        QUARTERROUND(keystream, 3, 4, 9, 14);
    }

    for (int i = 0; i < 16; i++) keystream[i] += state[i];
    *ctx->counter += 1;
}

void bytes_xor(char* result, int size, char* a, char* b) {
    for (int i = 0; i < size; i++) {
        result[i] = a[i] ^ b[i];
    }
}

/**
 * Takes in a chacha_ctx and a byte array and xors it
*/
void chacha20_xor(struct chacha_ctx* ctx, char* buf, int len) {
    for (int j = 0; j < (int)floor((double)len/64.0); j++) {
        chacha20_block(ctx);
        bytes_xor((&buf[j*64]), 64, (char*)ctx->keystream, &buf[j*64]);
    }
    if (len % 64 != 0) {
        int j = (int)floor((double)len/64.0);
        chacha20_block(ctx);
        bytes_xor(&buf[j*64], len%64, (char*)ctx->keystream, &buf[j*64]);
    }
}

void file_xor(struct chacha_ctx* ctx, char* i, char* o) {
    int CHUNKSIZE = 65536;
    char buf[CHUNKSIZE];
    int len = 0;

    FILE* input = fopen(i, "r");
    if (!input) {
        printf("Input file does not exist\n");
        exit(EXIT_FAILURE);
    }
    FILE* output = fopen(o, "w");
    do {
        len = fread((void*)buf, sizeof(char), CHUNKSIZE, input);
        chacha20_xor(ctx, buf, len);
        fwrite(buf, sizeof(char), len, output);
    } while (len == CHUNKSIZE);
    fclose(input);
    fclose(output);
}

void init_chacha_ctx(struct chacha_ctx* ctx, uint32_t* key, uint32_t counter, uint32_t* nonce) {
    memset(ctx, 0, sizeof(struct chacha_ctx));
    memcpy(ctx->state, CHACONST, 4 * sizeof(uint32_t));
    memcpy(ctx->state+4, key, 8 * sizeof(uint32_t));
    ctx->state[12] = counter;
    memcpy(ctx->state+13, nonce, 3 * sizeof(uint32_t));
    ctx->counter = &ctx->state[12];
}

void set_counter(struct chacha_ctx* ctx, uint32_t counter) {
    *ctx->counter = counter;
}

int main(int argc, char* argv[]) {
    int c;
    char *ip = NULL;
    char *op = NULL;
    while ((c = getopt(argc, argv, "i:o:")) != -1) {
        switch (c) {
            case 'i':
                ip = optarg;
                break;
            case 'o':
                op = optarg;
                break;
            case '?':
                exit(EXIT_FAILURE);
        }
    }
    if (!ip || !op) {
        printf("Need -i and -o for input and output respectively\n");
        exit(EXIT_FAILURE);
    }

    uint32_t key[8] = {0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
                    0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c};
    uint32_t counter = 1;
    uint32_t nonce[3] = {0x00000000, 0x4a000000, 0x00000000};
    struct chacha_ctx ctx;
    init_chacha_ctx(&ctx, key, counter, nonce);
    clock_t t;
    t = clock();
    file_xor(&ctx, ip, op);
    t = clock() - t;
    double time_taken = ((double)t)/CLOCKS_PER_SEC; // calculate the elapsed time
    printf("The program took %f seconds to execute\n", time_taken);
}