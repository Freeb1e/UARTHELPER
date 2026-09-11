#include <stdio.h>
#include <stdlib.h>
#include "drng.h"

int main(int argc, char **argv)
{
    unsigned char seed[64], discard[128], message[64];
    size_t count;
    unsigned bytes;
    unsigned keygen_bytes;
    if (argc != 2) return 1;
    bytes = (unsigned)strtoul(argv[1], NULL, 10);
    if (bytes != 16 && bytes != 24 && bytes != 32 && bytes != 64) return 1;
    keygen_bytes = bytes == 64u ? 128u : 64u;
    while ((count = fread(seed, 1, sizeof(seed), stdin)) != 0) {
        DRNG_ctx drng;
        /* The official KAT shares DRNG state across KeyGen and Encaps. */
        if (count != sizeof(seed) ||
            init_random_number(&drng, seed, sizeof(seed)) != 0 ||
            get_random_number(&drng, discard, keygen_bytes * 8u) != 0 ||
            get_random_number(&drng, discard, keygen_bytes * 8u) != 0 ||
            get_random_number(&drng, message, bytes * 8u) != 0 ||
            fwrite(message, 1, bytes, stdout) != bytes)
            return 1;
    }
    return ferror(stdin) || fflush(stdout) != 0;
}
