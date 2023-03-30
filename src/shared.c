#include "shared.h"

unsigned short hash(uint8_t **digest, const void *data, size_t len, hash_type_t hash_type)
{
    switch (hash_type)
    {
    case sha_1:
        *digest = malloc(SHA1_DIGEST_SIZE);
        struct sha1_ctx h;
        sha1_init(&h);
        sha1_update(&h, len, data);
        sha1_digest(&h, SHA1_DIGEST_SIZE, *digest);
        return SHA1_DIGEST_SIZE;
    case sha_256:
        *digest = malloc(SHA256_DIGEST_SIZE);
        struct sha256_ctx h256;
        sha256_init(&h256);
        sha256_update(&h256, len, data);
        sha256_digest(&h256, SHA256_DIGEST_SIZE, *digest);
        return SHA256_DIGEST_SIZE;
    case sha_512:
        *digest = malloc(SHA512_DIGEST_SIZE);
        struct sha512_ctx h512;
        sha512_init(&h512);
        sha512_update(&h512, len, data);
        sha512_digest(&h512, SHA512_DIGEST_SIZE, *digest);
        return SHA512_DIGEST_SIZE;
    default:
        return -1;
    }
}