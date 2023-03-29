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

#define N_SEC_LEVELS 2
#define IDENTITY "The identity of the user is in safe hands"
#define IDENTITY_LEN 41

const int sec_levels[N_SEC_LEVELS] = {80, 128};
const int sec_levels_order[N_SEC_LEVELS] = {512, 1536};
const uint8_t IDENTITY_DIGEST[SHA1_DIGEST_SIZE] = {166, 118, 61, 34, 51, 251, 189, 73, 157, 250, 15, 224, 219, 203, 197, 48, 96, 130, 199, 157};

#endif