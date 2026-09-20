#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "params.h"
#include "sign.h"

#define INPUT_BYTES 32u

static uint8_t random_inputs[2][INPUT_BYTES];
static unsigned int random_index;
static int random_failed;

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

static int decode_input(uint8_t output[INPUT_BYTES], const char *hex)
{
    size_t offset;

    if (strlen(hex) != 2u * INPUT_BYTES)
        return -1;
    for (offset = 0u; offset < INPUT_BYTES; ++offset) {
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
    if (random_index >= 2u || length != INPUT_BYTES) {
        memset(output, 0, length);
        random_failed = 1;
        return;
    }
    memcpy(output, random_inputs[random_index], INPUT_BYTES);
    ++random_index;
}

int main(int argc, char **argv)
{
    uint8_t public_key[CRYPTO_PUBLICKEYBYTES];
    uint8_t secret_key[CRYPTO_SECRETKEYBYTES];
    uint8_t message[INPUT_BYTES];
    uint8_t signature[CRYPTO_BYTES];
    size_t signature_length = 0u;

    if (argc != 4 ||
        decode_input(random_inputs[0], argv[1]) != 0 ||
        decode_input(message, argv[2]) != 0 ||
        decode_input(random_inputs[1], argv[3]) != 0)
        return 2;
    if (crypto_sign_keypair(public_key, secret_key) != 0 ||
        crypto_sign_signature(signature, &signature_length,
                              message, sizeof(message), NULL, 0u,
                              secret_key) != 0 ||
        signature_length != sizeof(signature) || random_index != 2u ||
        random_failed != 0 ||
        crypto_sign_verify(signature, signature_length,
                           message, sizeof(message), NULL, 0u,
                           public_key) != 0)
        return 3;
    signature[0] ^= 1u;
    if (crypto_sign_verify(signature, signature_length,
                           message, sizeof(message), NULL, 0u,
                           public_key) == 0)
        return 4;
    signature[0] ^= 1u;
    if (fwrite(public_key, 1u, sizeof(public_key), stdout) !=
            sizeof(public_key) ||
        fwrite(signature, 1u, sizeof(signature), stdout) !=
            sizeof(signature))
        return 5;
    return 0;
}
