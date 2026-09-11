#include <stdio.h>
#include <stdlib.h>
#include "drng.h"

int main(int argc, char **argv)
{
    unsigned char seed[64];
    unsigned char inputs[256];
    size_t count;
    unsigned bytes;

    if (argc != 2)
        return 1;
    bytes = (unsigned)strtoul(argv[1], NULL, 10);
    if (bytes != 64u && bytes != 128u)
        return 1;

    while ((count = fread(seed, 1, sizeof(seed), stdin)) != 0) {
        DRNG_ctx drng;

        /* KEM draws z first; PKE then makes a separate draw for alpha. */
        if (count != sizeof(seed) ||
            init_random_number(&drng, seed, sizeof(seed)) != 0 ||
            get_random_number(&drng, inputs, bytes * 8u) != 0 ||
            get_random_number(&drng, inputs + bytes, bytes * 8u) != 0 ||
            fwrite(inputs, 1, 2u * bytes, stdout) != 2u * bytes)
            return 1;
    }
    return ferror(stdin) || fflush(stdout) != 0;
}
