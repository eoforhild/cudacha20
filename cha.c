#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sodium.h>
#include <math.h>

const uint32_t CHACONST[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};

/* Left rotation of n by d bits */
#define INT_BITS 32
uint32_t leftRotate(uint32_t n, unsigned int d) {
    return (n << d) | (n >> (INT_BITS - d));
}

void quarterRound(uint32_t* arr, int a, int b, int c, int d) {
    arr[a] += arr[b]; arr[d] ^= arr[a]; arr[d] = leftRotate(arr[d], 16);
    arr[c] += arr[d]; arr[b] ^= arr[c]; arr[b] = leftRotate(arr[b], 12);
    arr[a] += arr[b]; arr[d] ^= arr[a]; arr[d] = leftRotate(arr[d], 8);
    arr[c] += arr[d]; arr[b] ^= arr[c]; arr[b] = leftRotate(arr[b], 7);
}

void chacha(uint32_t* state) {
    quarterRound(state, 0, 4, 8, 12);
    quarterRound(state, 1, 5, 9, 13);
    quarterRound(state, 2, 6, 10, 14);
    quarterRound(state, 3, 7, 11, 15);

    quarterRound(state, 0, 5, 10, 15);
    quarterRound(state, 1, 6, 11, 12);
    quarterRound(state, 2, 7, 8, 13);
    quarterRound(state, 3, 4, 9, 14);
}

void vec_addassign(uint32_t* dst, uint32_t* src, int size) {
    for (int i = 0; i < size; i++) {
        dst[i] += src[i];
    }
}

/**
 * Generates a keystream
 * 
 * Args:
 *  stream - Where the result will be stored
*/
void chacha20_block(
    uint32_t* stream, 
    uint32_t* key, 
    uint32_t counter, 
    uint32_t* nonce
) {
    uint32_t state[16];
    uint32_t initial_state[16];
    // Set up the state block
    memcpy(state, CHACONST, 4 * sizeof(uint32_t));
    memcpy(state+4, key, 8 * sizeof(uint32_t));
    state[12] = counter;
    memcpy(state+13, nonce, 3 * sizeof(uint32_t));

    memcpy(initial_state, state, 16 * sizeof(uint32_t));
    for (int i = 0; i < 10; i++) {
        chacha(state);
    }
    vec_addassign(state, initial_state, 16);
    memcpy(stream, state, 16 * sizeof(uint32_t));
}

void block_xor(uint32_t* result, uint32_t* stream, uint32_t* block) {
    for (int i = 0; i < 16; i++) {
        result[i] = stream[i] ^ block[i];
    }
}

void bytes_xor(char* result, int size, char* stream, char* block) {
    printf("\n");
    for (int i = 0; i < size; i++) {
        result[i] = stream[i] ^ block[i];
    }
}

void chacha20_encrypt(
    uint32_t* key, 
    uint32_t counter, 
    uint32_t* nonce, 
    char* plaintext,
    char* result
) {
    int len = strlen(plaintext);
    for (int j = 0; j < (int)floor((double)len/64.0); j++) {
        uint32_t stream[16];
        chacha20_block(stream, key, counter+j, nonce);
        block_xor((uint32_t*)(&result[j*64]), stream, (uint32_t*)(&plaintext[j*64]));
    }
    if (len % 64 != 0) {
        int j = (int)floor((double)len/64.0);
        uint32_t stream[16];
        chacha20_block(stream, key, counter+j, nonce);
        bytes_xor(&result[j*64], len%64, (char*)stream, &plaintext[j*64]);
    }
}



int main(int argc, char* argv[]) {
    uint32_t key[8] = {0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
                    0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c};
    uint32_t counter = 1;
    uint32_t nonce[3] = {0x00000000, 0x4a000000, 0x00000000};
    char* plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    char* result = (char*)malloc(strlen(plaintext)*sizeof(char));
    chacha20_encrypt(key, counter, nonce, plaintext, result);
    for (int i = 0; i < strlen(plaintext); i++) {
        if (i != 0 && i%16 == 0) {
            printf("\n");
        }
        printf("%02x ", (unsigned char)result[i]);
    }
    // printf("%x\n", *(uint32_t*)&result[0]);
}