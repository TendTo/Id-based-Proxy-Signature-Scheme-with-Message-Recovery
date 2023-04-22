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
#define TEST_HASH_TYPE sha_1
#define TEST_P "[3080255922072514454854761261637048229063060712234861160626067660516742899193538385939683974943106560975709068251613933839665767313796146065120889043558807, 7280559322651464525813104666108639481832422519363853361129767202449750369614988801604331314447051464218615115625151819688340160207751872108837244060305934]"
#define TEST_PK "[1964065410410776451955588067209269048732978832987707301424669611382452469191330437646754675243233364986804570675322345071777791408921248525095238838354814, 3325695201202249912364364549331129480823406275444460731639151878105768305387402212383803570917220444339994034466993708073963493680228233434715710318719389]"
#define TEST_MSK "117843337233255684997953208940058293206574021446"
#define TEST_Q 20
#define TEST_L1 10
#define TEST_L2 10

// Security levels
extern const int sec_levels[N_SEC_LEVELS];
extern const size_t sec_levels_order[N_SEC_LEVELS];

// Hash
typedef struct
{
    hash_type_t hash_type;
    uint16_t digest_size;
    const uint8_t *identity_digest;
    const uint8_t *element_digest;
} hash_test_t;

extern char TEST_PAIRING_P[];
extern const hash_type_t hash_types[N_HASH_TYPES];
extern sv_identity_t TEST_IDENTITY;
extern sv_identity_t TEST_IDENTITY_2;
extern const uint8_t TEST_IDENTITY_DIGEST_SHA1[SHA1_DIGEST_SIZE];
extern const uint8_t TEST_IDENTITY_DIGEST_SHA256[SHA256_DIGEST_SIZE];
extern const uint8_t TEST_IDENTITY_DIGEST_SHA512[SHA512_DIGEST_SIZE];
extern const uint8_t TEST_ELEMENT_DIGEST_SHA1[SHA1_DIGEST_SIZE];
extern const uint8_t TEST_ELEMENT_DIGEST_SHA256[SHA256_DIGEST_SIZE];
extern const uint8_t TEST_ELEMENT_DIGEST_SHA512[SHA512_DIGEST_SIZE];
extern const uint8_t TEST_MESSAGE_DIGEST_SHA1[SHA1_DIGEST_SIZE];
extern const uint8_t TEST_MESSAGE_DIGEST_SHA256[];
extern const hash_test_t hash_tests[N_HASH_TYPES];

#endif // TEST_CONST_H
