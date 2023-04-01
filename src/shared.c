#include "shared.h"

unsigned short hash(uint8_t digest[MAX_DIGEST_SIZE], const void *data, size_t len, hash_type_t hash_type)
{
    switch (hash_type)
    {
    case sha_1:
        struct sha1_ctx h;
        sha1_init(&h);
        sha1_update(&h, len, data);
        sha1_digest(&h, SHA1_DIGEST_SIZE, digest);
        return SHA1_DIGEST_SIZE;
    case sha_256:
        struct sha256_ctx h256;
        sha256_init(&h256);
        sha256_update(&h256, len, data);
        sha256_digest(&h256, SHA256_DIGEST_SIZE, digest);
        return SHA256_DIGEST_SIZE;
    case sha_512:
        struct sha512_ctx h512;
        sha512_init(&h512);
        sha512_update(&h512, len, data);
        sha512_digest(&h512, SHA512_DIGEST_SIZE, digest);
        return SHA512_DIGEST_SIZE;
    default:
        return -1;
    }
}

unsigned short hash_element(uint8_t digest[MAX_DIGEST_SIZE], element_t e, hash_type_t hash_type)
{
    int len = element_length_in_bytes(e);
    uint8_t element_buffer[len];
    element_to_bytes(element_buffer, e);
    return hash(digest, element_buffer, len, hash_type);
}