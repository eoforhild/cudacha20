#include <math.h>
#include <pthread.h>

#include "chacha20.h"
#include "impl_multi.h"
#include "utils.h"

#include <iostream>
using namespace std;

pthread_mutex_t r_lock;
pthread_mutex_t w_lock;

struct args {
    struct chacha_ctx ctx;
    FILE* input;
    FILE* output;
};

void file_xor_multi(struct args* a) {
    struct chacha_ctx* ctx = &a->ctx;
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
        set_counter(ctx, (skip*temp)+1);
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

void multi(uint32_t* key, uint32_t counter, uint32_t* nonce, char* ip, char* op, int num_workers) {
    FILE* input = fopen(ip, "rb");
    if (!input) {
        printf("Input file does not exist\n");
        exit(EXIT_FAILURE);
    }
    FILE* output = NULL;
    // Basically write zeroes to the file beforehand
    if (op) {
        remove(op);
        output = fopen(op, "wb");
        fseek(input, 0, SEEK_END);
        long end = ftell(input);
        fseek(input, 0, SEEK_SET);

        fseek(output, end-1, SEEK_SET);
        fwrite("\0", 1, 1, output);
        fseek(output, 0, SEEK_SET);
    }

    // Setup the arguments to pass to the threads
    pthread_mutex_init(&r_lock, NULL);
    pthread_mutex_init(&w_lock, NULL);
    pthread_t* threads = (pthread_t*)malloc(num_workers * sizeof(pthread_t));
    struct args* a = (struct args*)malloc(num_workers * sizeof(struct args));
    for (int i = 0; i < num_workers; i++) {
        init_chacha_ctx(&a[i].ctx, key, counter, nonce);
        a[i].input = input;
        a[i].output = output; 
    }

    // Run threads to completion
    for (int i = 0; i < num_workers; i++) {
        pthread_create(&threads[i], NULL, (void*(*)(void*))file_xor_multi, &a[i]);
    }
    for (int i = 0; i < num_workers; i++) {
        pthread_join(threads[i], NULL);
    }

    // Cleanup
    pthread_mutex_destroy(&r_lock);
    pthread_mutex_destroy(&w_lock);
    free(threads);
    free(a);
    fclose(input);
    if (op) fclose(output);
}