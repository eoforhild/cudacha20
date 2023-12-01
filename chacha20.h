#include <stdint.h>

struct chacha_ctx {
    uint32_t keystream[16];
    uint32_t state[16];
    uint32_t* counter;
};

static inline void chacha20_block(struct chacha_ctx* ctx);

void chacha20_xor(struct chacha_ctx* ctx, char* buf, int len);

void set_counter(struct chacha_ctx* ctx, uint32_t counter);

void init_chacha_ctx(struct chacha_ctx* ctx, uint32_t* key, uint32_t counter, uint32_t* nonce);