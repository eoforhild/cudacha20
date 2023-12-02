#include <math.h>
#include <pthread.h>
#include <semaphore.h>

#include "chacha20.h"
#include "utils.h"

#include <iostream>
using namespace std;

/**
 * 
 * 
 * GPU THREADING IMPLEMENTATION
 * 
 * 
*/

struct read_args {
    char* buf;
    FILE* input;
    int* readLen;
    sem_t* r_wait; // Reader waits until buffer has been consumed
    sem_t* buf_ready; // Data has been read into the buffer
};

struct write_args {
    char* res;
    FILE* output;
    int* writeLen;
    sem_t* w_wait; // Main thread waits for past writes to complete
    sem_t* res_ready; // Waiting for res to be filled
};

/**
 * Basically the same as the chacha20_block function but also incorporates the xor
*/
__global__ void d_chacha20_xor(
    uint32_t* d_ciphertext, 
    uint32_t* d_state,
    char* d_buf
) {
    extern __shared__ uint32_t total[16+(THREADS_PER_BLOCK*16)];
    uint32_t* state = &total[0];
    // copy the default state to shared mem
    if (threadIdx.x < 16) {
        state[threadIdx.x] = d_state[threadIdx.x];
    }
    __syncthreads();

    uint32_t* block_ct = &total[16];
    int global_id = blockIdx.x*blockDim.x + threadIdx.x;
    // Localized for each thread
    uint32_t* local_ct = &block_ct[threadIdx.x*16];
    for (int i = 0; i < 16; i++) local_ct[i] = state[i];
    // Adjust counter relative to thread id
    local_ct[12] = state[12] + global_id;
    for (int i = 0; i < 10; i++) {
        QUARTERROUND(local_ct, 0, 4, 8, 12);
        QUARTERROUND(local_ct, 1, 5, 9, 13);
        QUARTERROUND(local_ct, 2, 6, 10, 14);
        QUARTERROUND(local_ct, 3, 7, 11, 15);
        QUARTERROUND(local_ct, 0, 5, 10, 15);
        QUARTERROUND(local_ct, 1, 6, 11, 12);
        QUARTERROUND(local_ct, 2, 7, 8, 13);
        QUARTERROUND(local_ct, 3, 4, 9, 14);
    }

    local_ct[0] += state[0];
    local_ct[1] += state[1];
    local_ct[2] += state[2];
    local_ct[3] += state[3];
    local_ct[4] += state[4];
    local_ct[5] += state[5];
    local_ct[6] += state[6];
    local_ct[7] += state[7];
    local_ct[8] += state[8];
    local_ct[9] += state[9];
    local_ct[10] += state[10];
    local_ct[11] += state[11];
    local_ct[12] += state[12] + global_id;
    local_ct[13] += state[13];
    local_ct[14] += state[14];
    local_ct[15] += state[15];
    
    // XOR the keystream with the buffer
    char* local_buf = &d_buf[global_id*64];
    for (int i = 0; i < 16; i++) {
        local_ct[i] ^= ((uint32_t*)local_buf)[i];
    }

    // Copy back into global memory
    uint32_t* stream_ptr = &d_ciphertext[global_id*16];
    for (int i = 0; i < 16; i++) {
        stream_ptr[i] = local_ct[i];
    }
}

void reader(struct read_args* a) {
    char* buf = a->buf;
    FILE* input = a->input;
    int* readLen = a->readLen;
    sem_t* buf_ready = a->buf_ready;
    sem_t* r_wait = a->r_wait;

    do {
        // Wait for buffer to be consumed by main thread
        sem_wait(r_wait);
        *readLen = fread((void*)buf, sizeof(char), KS_SIZE, input);
        sem_post(buf_ready);
    } while (*readLen);
}

void writer(struct write_args* a) {
    char* res = a->res;
    FILE* output = a->output;
    int* writeLen = a->writeLen;
    sem_t* res_ready = a->res_ready;
    sem_t* w_wait = a->w_wait;

    do {
        // Wait for res to be filled
        sem_wait(res_ready);
        if (*writeLen == 0) {
            // This is signal to quit
            sem_post(w_wait);
            return;
        }
        fwrite(res, sizeof(char), *writeLen, output);
        sem_post(w_wait);
    } while (true);
}

void init_read_args(struct read_args* r_args, char* buf, FILE* input, 
        int* readLen, sem_t* r_wait, sem_t* buf_ready) {
    r_args->buf = buf;
    r_args->input = input;
    r_args->readLen = readLen;
    r_args->r_wait = r_wait;
    r_args->buf_ready = buf_ready;
}

void init_write_args(struct write_args* r_args, char* res, FILE* output, 
        int* writeLen, sem_t* w_wait, sem_t* res_ready) {
    r_args->res = res;
    r_args->output = output;
    r_args->writeLen = writeLen;
    r_args->w_wait = w_wait;
    r_args->res_ready = res_ready;
}

void file_xor_gpu(struct chacha_ctx* ctx, FILE* input, FILE* output) {
    uint32_t ctr_skip = KS_SIZE/64;

    // Set up a reader thread
    pthread_t read_thread;
    sem_t r_wait, buf_ready;
    sem_init(&r_wait, 0, 1);
    sem_init(&buf_ready, 0, 0);

    char* buf = (char*)malloc(KS_SIZE);
    int readlen_cur = 0;
    int readlen_next = 0;
    struct read_args r_args;
    init_read_args(&r_args, buf, input, &readlen_next, &r_wait, &buf_ready);
    pthread_create(&read_thread, NULL, (void*(*)(void*))reader, (void*)&r_args);

    // Set up a writer thread
    pthread_t write_thread;
    sem_t w_wait, res_ready;
    sem_init(&w_wait, 0, 1);
    sem_init(&res_ready, 0, 0);

    char* res = (char*)malloc(KS_SIZE);
    int writeLen = 0;
    struct write_args w_args;
    init_write_args(&w_args, res, output, &writeLen, &w_wait, &res_ready);
    if (output) {
        pthread_create(&write_thread, NULL, (void*(*)(void*))writer, (void*)&w_args);
    }

    // Keystream is either 8, 16, 32, 64, 128, 256 MB
    uint32_t *d_ciphertext, *d_state;
    char* d_buf;
    cudaMalloc((void**)&d_ciphertext, KS_SIZE);
    cudaMalloc((void**)&d_state, 16*sizeof(uint32_t));
    cudaMalloc((void**)&d_buf, KS_SIZE);
    int times = 0;
    do {
        // Read in the file
        sem_wait(&buf_ready);
        readlen_cur = readlen_next;
        cudaMemcpy(d_buf, buf, readlen_cur, cudaMemcpyHostToDevice);
        sem_post(&r_wait);

        // Set counter per n MB ciphertext encrypted
        set_counter(ctx, (ctr_skip*times) + 1);
        cudaMemcpy(d_state, ctx->state, 16*sizeof(uint32_t), cudaMemcpyHostToDevice);
        d_chacha20_xor<<<(KS_SIZE/64)/THREADS_PER_BLOCK, THREADS_PER_BLOCK>>>(d_ciphertext, d_state, d_buf);
        cudaDeviceSynchronize();

        // Write to output
        if (output) {
            sem_wait(&w_wait);
            cudaMemcpy(res, d_ciphertext, readlen_cur, cudaMemcpyDeviceToHost);
            writeLen = readlen_cur;
            sem_post(&res_ready);
        }

        times += 1;
    } while (readlen_cur == KS_SIZE);
    if (output) {
        sem_wait(&w_wait); // Wait for last write op to complete
        writeLen = 0;
        sem_post(&res_ready);
        pthread_join(write_thread, NULL);
    }
    free(buf);
    free(res);
    cudaFree(d_ciphertext);
    cudaFree(d_state);
    cudaFree(d_buf);
    pthread_join(read_thread, NULL);
}

void gpu(uint32_t* key, uint32_t counter, uint32_t* nonce, char* ip, char* op) {
    FILE* input = fopen(ip, "rb");
    if (!input) {
        printf("Input file does not exist\n");
        exit(EXIT_FAILURE);
    }
    FILE* output;
    if (op){
        remove(op);
        output = fopen(op, "wb");
    }

    struct chacha_ctx ctx;
    init_chacha_ctx(&ctx, key, counter, nonce);
    file_xor_gpu(&ctx, input, output);
    fclose(input);
    if (op) fclose(output);
}

/**
 * 
 * 
 * MULTI THREADED IMPLEMENTATION
 * 
 * 
*/

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

/**
 * 
 * 
 * SINGLE THREADED IMPLEMENTATION
 * 
 * 
*/

void file_xor_single(struct chacha_ctx* ctx, FILE* input, FILE* output) {
    char* buf = (char*)malloc(CHUNKSIZE);
    int len = 0;
    do {
        len = fread((void*)buf, sizeof(char), CHUNKSIZE, input);
        chacha20_xor(ctx, buf, len);
        if (output) fwrite(buf, sizeof(char), len, output);
    } while (len == CHUNKSIZE);
    free(buf);
}

void single(uint32_t* key, uint32_t counter, uint32_t* nonce, char* ip, char* op) {
    FILE* input = fopen(ip, "rb");
    if (!input) {
        printf("Input file does not exist\n");
        exit(EXIT_FAILURE);
    }
    FILE* output = NULL;
    if (op) {
        remove(op);
        output = fopen(op, "wb");
    }

    struct chacha_ctx ctx;
    init_chacha_ctx(&ctx, key, counter, nonce);
    file_xor_single(&ctx, input, output);
    fclose(input);
    if (op) fclose(output);
}