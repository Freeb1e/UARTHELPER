#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "params.h"
#include "sign.h"

#define SEED_BYTES 32u

static uint8_t input_seed[SEED_BYTES];
static int seed_used;

static int hex_nibble(char value)
{
    if (value >= '0' && value <= '9')
        return value - '0';
    if (value >= 'a' && value <= 'f')
        return value - 'a' + 10;
    if (value >= 'A' && value <= 'F')
        return value - 'A' + 10;
    return -1;
}

static int decode_seed(const char *hex)
{
    size_t offset;

    if (strlen(hex) != 2u * sizeof(input_seed))
        return -1;
    for (offset = 0u; offset < sizeof(input_seed); ++offset) {
        int high = hex_nibble(hex[2u * offset]);
        int low = hex_nibble(hex[2u * offset + 1u]);

        if (high < 0 || low < 0)
            return -1;
        input_seed[offset] = (uint8_t)((high << 4) | low);
    }
    return 0;
}

void randombytes(uint8_t *output, size_t length)
{
    if (seed_used || length != sizeof(input_seed)) {
        memset(output, 0, length);
        seed_used = -1;
        return;
    }
    memcpy(output, input_seed, sizeof(input_seed));
    seed_used = 1;
}

int main(int argc, char **argv)
{
    uint8_t public_key[CRYPTO_PUBLICKEYBYTES];
    uint8_t secret_key[CRYPTO_SECRETKEYBYTES];

    if (argc != 2 || decode_seed(argv[1]) != 0)
        return 2;
    if (crypto_sign_keypair(public_key, secret_key) != 0 || seed_used != 1)
        return 3;
    if (fwrite(public_key, 1u, sizeof(public_key), stdout) !=
            sizeof(public_key) ||
        fwrite(secret_key, 1u, sizeof(secret_key), stdout) !=
            sizeof(secret_key))
        return 4;
    return 0;
}
