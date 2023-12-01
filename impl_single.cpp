#include <math.h>

#include "chacha20.h"
#include "utils.h"

#include <iostream>
using namespace std;

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