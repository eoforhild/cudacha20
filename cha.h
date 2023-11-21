#include <stdint.h>

struct chacha_ctx {
    uint32_t keystream[16];
    uint32_t state[16];
    uint32_t* counter;
};