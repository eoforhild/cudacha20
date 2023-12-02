#include <stdint.h>

/* Left rotation of n by d bits */
#define ROTL32(n, d) (n << d) | (n >> (32 - d))

#define QUARTERROUND(arr, a, b, c, d) \
    arr[a] += arr[b]; arr[d] ^= arr[a]; arr[d] = ROTL32(arr[d], 16); \
    arr[c] += arr[d]; arr[b] ^= arr[c]; arr[b] = ROTL32(arr[b], 12); \
    arr[a] += arr[b]; arr[d] ^= arr[a]; arr[d] = ROTL32(arr[d], 8); \
    arr[c] += arr[d]; arr[b] ^= arr[c]; arr[b] = ROTL32(arr[b], 7);

static inline void bytes_xor(char* result, int size, char* a, char* b) {
    for (int i = 0; i < size; i++) {
        result[i] = a[i] ^ b[i];
    }
}