#include <stdio.h>
#include <stdint.h>

struct chacha_ctx {
    uint32_t keystream[16];
    uint32_t state[16];
    uint32_t* counter;
};

struct args {
    struct chacha_ctx ctx;
    uint32_t tid;
    FILE* input;
    FILE* output;
}