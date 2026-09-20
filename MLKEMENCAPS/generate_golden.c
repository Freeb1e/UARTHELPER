#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kem.h"

#define KEYGEN_COINS_BYTES 64u
#define ENCAPS_COINS_BYTES 32u

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

static int decode_hex(uint8_t *output, size_t bytes, const char *hex)
{
    size_t offset;

    if (strlen(hex) != 2u * bytes)
        return -1;
    for (offset = 0u; offset < bytes; ++offset) {
        int high = hex_nibble(hex[2u * offset]);
        int low = hex_nibble(hex[2u * offset + 1u]);

        if (high < 0 || low < 0)
            return -1;
        output[offset] = (uint8_t)((high << 4) | low);
    }
    return 0;
}

void randombytes(uint8_t *output, size_t length)
{
    memset(output, 0, length);
}

int main(int argc, char **argv)
{
    uint8_t keygen_coins[KEYGEN_COINS_BYTES];
    uint8_t encaps_coins[ENCAPS_COINS_BYTES];
    uint8_t public_key[CRYPTO_PUBLICKEYBYTES];
    uint8_t secret_key[CRYPTO_SECRETKEYBYTES];
    uint8_t ciphertext[CRYPTO_CIPHERTEXTBYTES];
    uint8_t shared_secret[CRYPTO_BYTES];

    if (argc != 3 ||
        decode_hex(keygen_coins, sizeof(keygen_coins), argv[1]) != 0 ||
        decode_hex(encaps_coins, sizeof(encaps_coins), argv[2]) != 0)
        return 2;
    if (crypto_kem_keypair_derand(public_key, secret_key, keygen_coins) != 0)
        return 3;
    if (crypto_kem_enc_derand(ciphertext, shared_secret, public_key,
                              encaps_coins) != 0)
        return 4;
    if (fwrite(public_key, 1u, sizeof(public_key), stdout) !=
            sizeof(public_key) ||
        fwrite(ciphertext, 1u, sizeof(ciphertext), stdout) !=
            sizeof(ciphertext) ||
        fwrite(shared_secret, 1u, sizeof(shared_secret), stdout) !=
            sizeof(shared_secret))
        return 5;
    return 0;
}
