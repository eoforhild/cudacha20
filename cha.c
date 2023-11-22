#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <getopt.h>
#include <time.h>
#include <string.h>
#include <math.h>
#include <pthread.h>

#include "cha.h"

;enum Threading {
    SINGLE_THREAD,
    MULTI_THREAD,
    GPU_THREAD
};

const uint32_t CHUNKSIZE = 65536;
const uint32_t CHACONST[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
pthread_mutex_t r_lock;
pthread_mutex_t w_lock;

/* Left rotation of n by d bits */
#define ROTL32(n, d) (n << d) | (n >> (32 - d))

#define QUARTERROUND(arr, a, b, c, d) \
    arr[a] += arr[b]; arr[d] ^= arr[a]; arr[d] = ROTL32(arr[d], 16); \
    arr[c] += arr[d]; arr[b] ^= arr[c]; arr[b] = ROTL32(arr[b], 12); \
    arr[a] += arr[b]; arr[d] ^= arr[a]; arr[d] = ROTL32(arr[d], 8); \
    arr[c] += arr[d]; arr[b] ^= arr[c]; arr[b] = ROTL32(arr[b], 7);

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

static inline void bytes_xor(char* result, int size, char* a, char* b) {
    for (int i = 0; i < size; i++) {
        result[i] = a[i] ^ b[i];
    }
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

void file_xor_single(struct chacha_ctx* ctx, char* ip, char* op) {
    char* buf = (char*)malloc(CHUNKSIZE);
    int len = 0;

    FILE* input = fopen(ip, "r");
    if (!input) {
        printf("Input file does not exist\n");
        exit(EXIT_FAILURE);
    }
    FILE* output;
    if (op) output = fopen(op, "w");
    do {
        len = fread((void*)buf, sizeof(char), CHUNKSIZE, input);
        chacha20_xor(ctx, buf, len);
        if (op) fwrite(buf, sizeof(char), len, output);
    } while (len == CHUNKSIZE);
    fclose(input);
    if (op) fclose(output);
    free(buf);
}

void file_xor_multi(struct args* a) {
    struct chacha_ctx* ctx = &a->ctx;
    uint32_t tid = a->tid;
    FILE* input = a->input;
    FILE* output = a->output;

    char* buf = (char*)malloc(CHUNKSIZE);
    int len = 0;
    int skip = CHUNKSIZE / 64;

    do {
        pthread_mutex_lock(&r_lock);
        int init_pos = ftell(input);
        len = fread((void*)buf, sizeof(char), CHUNKSIZE, input);
        pthread_mutex_unlock(&r_lock);

        // Determines where to point the counter
        int temp = init_pos / CHUNKSIZE;
        set_counter(ctx, (skip * temp)+1);
        chacha20_xor(ctx, buf, len);

        if (output) {
            pthread_mutex_lock(&w_lock);
            fseek(output, init_pos, SEEK_SET);
            fwrite(buf, sizeof(char), len, output);
            pthread_mutex_unlock(&w_lock);
        }
    } while (len == CHUNKSIZE);
    free(buf);
}

void single(uint32_t* key, uint32_t counter, uint32_t* nonce, char* ip, char* op) {
    struct chacha_ctx ctx;
    init_chacha_ctx(&ctx, key, counter, nonce);
    file_xor_single(&ctx, ip, op);
}

void multi(uint32_t* key, uint32_t counter, uint32_t* nonce, char* ip, char* op, int num_workers) {
    FILE* input = fopen(ip, "r");
    if (!input) {
        printf("Input file does not exist\n");
        exit(EXIT_FAILURE);
    }
    FILE* output = NULL;
    // Basically write zeroes to the file beforehand
    if (op) {
        output = fopen(op, "w");
        fseek(input, 0, SEEK_END);
        long end = ftell(input);
        fseek(input, 0, SEEK_SET);

        fseek(output, end-1, SEEK_SET);
        fwrite("0", 1, 1, output);
        fseek(output, 0, SEEK_SET);
    }
    pthread_mutex_init(&r_lock, NULL);
    pthread_mutex_init(&w_lock, NULL);
    pthread_t* threads = (pthread_t*)malloc(num_workers * sizeof(pthread_t));
    struct args* a = (struct args*)malloc(num_workers * sizeof(struct args));
    for (int i = 0; i < num_workers; i++) {
        init_chacha_ctx(&a[i].ctx, key, counter, nonce);
        a[i].tid = i;
        a[i].input = input;
        a[i].output = output; 
    }

    for (int i = 0; i < num_workers; i++) {
        pthread_create(&threads[i], NULL, (void*)file_xor_multi, &a[i]);
    }
    for (int i = 0; i < num_workers; i++) {
        pthread_join(threads[i], NULL);
    }
    pthread_mutex_destroy(&r_lock);
    pthread_mutex_destroy(&w_lock);
    free(threads);
    free(a);
    fclose(input);
    if (op) fclose(output);
}

int main(int argc, char* argv[]) {
    int c;
    char *ip = NULL;
    char *op = NULL;
    bool thread = false;
    int num_workers = 0;
    bool gpu = false;
    enum Threading prog_t = SINGLE_THREAD;
    while ((c = getopt(argc, argv, "i:o:t:g")) != -1) {
        switch (c) {
            case 'i':
                ip = optarg;
                break;
            case 'o':
                op = optarg;
                break;
            case 't':
                thread = true;
                num_workers = atoi(optarg);
                prog_t = MULTI_THREAD;
                break;
            case 'g':
                gpu = true;
                prog_t = GPU_THREAD;
                break;
            case '?':
                exit(EXIT_FAILURE);
        }
    }
    if (!ip) {
        printf("Need -i for input, -o is optional for output\n");
        exit(EXIT_FAILURE);
    }
    if (!(thread ^ gpu) && thread) {
        printf("Only one flag for threading allowed\n");
        printf("Either -t for pthreads or -g for GPU\n");
        exit(EXIT_FAILURE);
    }
    if (thread && num_workers == 0) {
        printf("-t needs an integer argument greater than 0\n");
        exit(EXIT_FAILURE);
    }

    uint32_t key[8] = {0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
                    0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c};
    uint32_t counter = 1;
    uint32_t nonce[3] = {0x00000000, 0x4a000000, 0x00000000};
    struct timespec start, end;
    double elapsed;
    clock_gettime(CLOCK_MONOTONIC, &start);
    switch (prog_t) {
        case SINGLE_THREAD:
            single(key, counter, nonce, ip, op);
            break;
        case MULTI_THREAD:
            multi(key, counter, nonce, ip, op, num_workers);
            break;
        case GPU_THREAD:
            break;
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = end.tv_sec - start.tv_sec;
    elapsed += (end.tv_nsec - start.tv_nsec) / 1000000000.0;
    printf("The program took %f seconds to execute\n", elapsed);
}