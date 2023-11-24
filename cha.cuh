#include <stdio.h>
#include <stdint.h>

struct chacha_ctx {
    uint32_t keystream[16];
    uint32_t state[16];
    uint32_t* counter;
};

struct args {
    struct chacha_ctx ctx;
    FILE* input;
    FILE* output;
}

;enum Threading {
    SINGLE_THREAD,
    MULTI_THREAD,
    GPU_THREAD
};