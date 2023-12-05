#include <stdint.h>
#include <stdbool.h>
#include <getopt.h>
#include <time.h>
#include <string.h>

#include "impl.cuh"

#include <iostream>
using namespace std;

/**
 * ALL CONSTANTS IN THE PROGRAM ARE IN impl.cuh
*/

uint32_t ks = 28; // Just for changing GPU keysize, default at 2^28
uint32_t CHUNKSIZE = 65536;

enum Threading {
    SINGLE_THREAD,
    MULTI_THREAD,
    GPU_THREAD
};

bool is_power_two(uint32_t n) {
    return (n & (n - 1)) == 0;
}

int main(int argc, char* argv[]) {
    int c;
    char *ip = NULL;
    char *op = NULL;
    bool t = false;
    int num_workers = 0;
    bool g = false;
    bool data = false;
    enum Threading prog_t = SINGLE_THREAD;
    while ((c = getopt(argc, argv, "i:o:t:g:c:d")) != -1) {
        switch (c) {
            case 'i':
                ip = optarg;
                break;
            case 'o':
                op = optarg;
                break;
            case 't':
                t = true;
                num_workers = atoi(optarg);
                prog_t = MULTI_THREAD;
                break;
            case 'g':
                g = true;
                prog_t = GPU_THREAD;
                switch (atoi(optarg)) {
                    case 1:
                        ks = 20;
                        break;
                    case 2:
                        ks = 21;
                        break;
                    case 4:
                        ks = 22;
                        break;
                    case 8:
                        ks = 23;
                        break;
                    case 16:
                        ks = 24;
                        break;
                    case 32:
                        ks = 25;
                        break;
                    case 64:
                        ks = 26;
                        break;
                    case 128:
                        ks = 27;
                        break;
                    case 256:
                        ks = 28;
                        break;
                    default:
                        printf("The only supported keystream sizes are 1, 2, 4, 8, 16, 32, 64, 128, 256 MBs.\n");
                        exit(EXIT_FAILURE);
                }
                break;
            case 'c':
                CHUNKSIZE = (uint32_t)atoi(optarg);
                if (!is_power_two(CHUNKSIZE) || !(CHUNKSIZE >= 1024 && CHUNKSIZE <= 131072)) {
                    printf("The only supported chunksizes are 1, 2, 4, 8, 16, 32, 64, 128 KBs.\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'd':
                data = true;
                break;
            case '?':
                exit(EXIT_FAILURE);
        }
    }
    if (!ip) {
        printf("Need -i for input, -o is optional for output\n");
        exit(EXIT_FAILURE);
    }
    if (!(t ^ g) && t) {
        printf("Only one flag for threading allowed\n");
        printf("Either -t for pthreads or -g for GPU\n");
        exit(EXIT_FAILURE);
    }
    if (t && num_workers <= 0) {
        printf("-t needs an integer argument greater than 0\n");
        exit(EXIT_FAILURE);
    }

    // Realistically, you need to be able to randomly generate the key
    // and the nonce, and for every 256 GB encrypted, the nonce will
    // need to be regenerated and the counter resetted.
    //
    // For simplicity sake, I'm keeping the key and nonce the same as
    // what was specified in the document.
    uint32_t key[8] = {0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
                    0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c};
    uint32_t counter = 1;
    uint32_t nonce[3] = {0x00000000, 0x4a000000, 0x00000000};
    struct timespec start, end;
    double elapsed;
    clock_gettime(CLOCK_MONOTONIC, &start);
    switch (prog_t) {
        case SINGLE_THREAD:
            single(key, counter, nonce, ip, op);
            break;
        case MULTI_THREAD:
            multi(key, counter, nonce, ip, op, num_workers);
            break;
        case GPU_THREAD:
            gpu(key, counter, nonce, ip, op);
            break;
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = end.tv_sec - start.tv_sec;
    elapsed += (end.tv_nsec - start.tv_nsec) / 1000000000.0;
    printf("%f", elapsed);
    if (!data) {
        printf(" seconds elapsed\n");
    }
}