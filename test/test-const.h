/**
 * @file test-const.h
 * @author TendTo (https://github.com/TendTo)
 *
 * @brief Constants used in the tests
 * Those are constants used in the various tests, usually some form of expected result
 */

#ifndef TEST_CONST_H
#define TEST_CONST_H

#include <nettle/sha1.h>
#include <nettle/sha2.h>
#include "shared.h"
#include "sv-scheme.h"

#define N_SEC_LEVELS 2
#define N_HASH_TYPES 3
#define TEST_MESSAGE "Sign this message!"

// Security levels
const int sec_levels[N_SEC_LEVELS] = {80, 128};
const size_t sec_levels_order[N_SEC_LEVELS] = {80, 128};

// Hash
typedef struct
{
    hash_type_t hash_type;
    unsigned short digest_size;
    const uint8_t *identity_digest;
    const uint8_t *element_digest;
} hash_test_t;

const hash_type_t hash_types[N_HASH_TYPES] = {sha_1, sha_256, sha_512};
sv_identity_t TEST_IDENTITY = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
sv_identity_t TEST_IDENTITY_2 = {31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
const uint8_t TEST_IDENTITY_DIGEST_SHA1[SHA1_DIGEST_SIZE] = {174, 91, 216, 239, 234, 83, 34, 196, 217, 152, 109, 6, 104, 10, 120, 19, 146, 249, 166, 66};
const uint8_t TEST_IDENTITY_DIGEST_SHA256[SHA256_DIGEST_SIZE] = {99, 13, 205, 41, 102, 196, 51, 102, 145, 18, 84, 72, 187, 178, 91, 79, 244, 18, 164, 156, 115, 45, 178, 200, 171, 193, 184, 88, 27, 215, 16, 221};
const uint8_t TEST_IDENTITY_DIGEST_SHA512[SHA512_DIGEST_SIZE] = {61, 148, 238, 164, 156, 88, 10, 239, 129, 105, 53, 118, 43, 224, 73, 85, 157, 109, 20, 64, 222, 222, 18, 230, 161, 37, 241, 132, 31, 255, 142, 111, 169, 215, 24, 98, 163, 229, 116, 107, 87, 27, 227, 209, 135, 176, 4, 16, 70, 245, 46, 189, 133, 12, 124, 189, 95, 222, 142, 227, 132, 115, 182, 73};
const uint8_t TEST_ELEMENT_DIGEST_SHA1[SHA1_DIGEST_SIZE] = {154, 143, 18, 130, 101, 228, 140, 242, 203, 105, 27, 76, 239, 204, 192, 85, 109, 156, 189, 58};
const uint8_t TEST_ELEMENT_DIGEST_SHA256[SHA256_DIGEST_SIZE] = {233, 255, 14, 110, 109, 233, 93, 165, 111, 240, 159, 78, 62, 15, 72, 29, 103, 88, 95, 10, 104, 170, 253, 238, 240, 248, 111, 123, 133, 51, 206, 23};
const uint8_t TEST_ELEMENT_DIGEST_SHA512[SHA512_DIGEST_SIZE] = {160, 237, 224, 79, 173, 198, 48, 115, 203, 162, 233, 108, 204, 185, 88, 209, 57, 95, 235, 213, 162, 198, 108, 159, 223, 183, 240, 216, 57, 95, 143, 187, 22, 21, 174, 86, 181, 4, 43, 79, 244, 15, 33, 96, 113, 81, 197, 46, 83, 22, 27, 74, 124, 163, 63, 79, 150, 219, 153, 44, 86, 155, 29, 182};
const hash_test_t hash_tests[N_HASH_TYPES] = {
    {sha_1, SHA1_DIGEST_SIZE, TEST_IDENTITY_DIGEST_SHA1, TEST_ELEMENT_DIGEST_SHA1},
    {sha_256, SHA256_DIGEST_SIZE, TEST_IDENTITY_DIGEST_SHA256, TEST_ELEMENT_DIGEST_SHA256},
    {sha_512, SHA512_DIGEST_SIZE, TEST_IDENTITY_DIGEST_SHA512, TEST_ELEMENT_DIGEST_SHA512}};

#endif