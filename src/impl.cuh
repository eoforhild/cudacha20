#include <stdint.h>

// Constant for CPU threading version, read and write in this chunksize
const uint32_t CHUNKSIZE = 65536;

// GPU constants
extern uint32_t ks;
#define KS_SIZE ((uint32_t)1<<ks)
#define THREADS_PER_BLOCK 128 // Probably the best

void single(uint32_t* key, uint32_t counter, uint32_t* nonce, char* ip, char* op);
void multi(uint32_t* key, uint32_t counter, uint32_t* nonce, char* ip, char* op, int num_workers);
void gpu(uint32_t* key, uint32_t counter, uint32_t* nonce, char* ip, char* op);