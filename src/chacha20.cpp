#include <stdint.h>
#include <math.h>
#include <string.h>

#include "utils.h"
#include "chacha20.h"

const uint32_t CHACONST[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};

/**
 * Consumes current state and increment the counter
*/
static inline void chacha20_block(struct chacha_ctx* ctx) {
    uint32_t* keystream = ctx->keystream;
    uint32_t* state = ctx->state;

    for (int i = 0; i < 16; i++) keystream[i] = state[i];
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

/**
 * Takes in a chacha_ctx and a byte array and xors it.
 * The result is also in the byte array.
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

void set_counter(struct chacha_ctx* ctx, uint32_t counter) {
    *ctx->counter = counter;
}

void init_chacha_ctx(struct chacha_ctx* ctx, uint32_t* key, uint32_t counter, uint32_t* nonce) {
    memcpy(ctx->state, CHACONST, 4 * sizeof(uint32_t));
    memcpy(ctx->state+4, key, 8 * sizeof(uint32_t));
    ctx->state[12] = counter;
    memcpy(ctx->state+13, nonce, 3 * sizeof(uint32_t));
    ctx->counter = &ctx->state[12];
}