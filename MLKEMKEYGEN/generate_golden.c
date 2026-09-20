#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kem.h"

#define COINS_BYTES 64u

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

static int decode_coins(uint8_t coins[COINS_BYTES], const char *hex)
{
    size_t offset;

    if (strlen(hex) != 2u * COINS_BYTES)
        return -1;
    for (offset = 0u; offset < COINS_BYTES; ++offset) {
        int high = hex_nibble(hex[2u * offset]);
        int low = hex_nibble(hex[2u * offset + 1u]);

        if (high < 0 || low < 0)
            return -1;
        coins[offset] = (uint8_t)((high << 4) | low);
    }
    return 0;
}

void randombytes(uint8_t *output, size_t length)
{
    memset(output, 0, length);
}

int main(int argc, char **argv)
{
    uint8_t coins[COINS_BYTES];
    uint8_t public_key[CRYPTO_PUBLICKEYBYTES];
    uint8_t secret_key[CRYPTO_SECRETKEYBYTES];

    if (argc != 2 || decode_coins(coins, argv[1]) != 0)
        return 2;
    if (crypto_kem_keypair_derand(public_key, secret_key, coins) != 0)
        return 3;
    if (fwrite(public_key, 1u, sizeof(public_key), stdout) !=
            sizeof(public_key) ||
        fwrite(secret_key, 1u, sizeof(secret_key), stdout) !=
            sizeof(secret_key))
        return 4;
    return 0;
}

