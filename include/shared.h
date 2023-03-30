#ifndef UTIL_H
#define UTIL_H

#include <assert.h>
#include <pbc/pbc.h>
#include <nettle/sha1.h>
#include <nettle/sha2.h>

typedef enum
{
    sha_1,
    sha_256,
    sha_512
} hash_type_t;

/**
 * @brief Generate the digest of the data using the hash_type algorithm
 *
 * @param digest ouput digest obtained by applying the hash_type algorithm to data
 * @param data data to be hashed
 * @param len length of ht data buffer in bytes
 * @param hash_type hash algorithm to be used
 * @return unsigned short length of the digest in bytes
 */
unsigned short hash(uint8_t **digest, const void *data, size_t len, hash_type_t hash_type);

#endif // UTIL_H
