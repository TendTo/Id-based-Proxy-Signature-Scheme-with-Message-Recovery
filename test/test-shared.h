#include <check.h>
#include "shared.h"
#include "test-const.h"

#pragma region hash

START_TEST(test_hash_sha1)
{
    uint8_t *digest;
    int digest_len = hash(&digest, TEST_IDENTITY, IDENTITY_SIZE, sha_1);

    ck_assert_int_eq(digest_len, SHA1_DIGEST_SIZE);
    for (int i = 0; i < digest_len; i++)
    {
        ck_assert_int_eq(digest[i], TEST_IDENTITY_DIGEST_SHA1[i]);
    }
    free(digest);
}
END_TEST

START_TEST(test_hash_sha256)
{
    uint8_t *digest;
    int digest_len = hash(&digest, TEST_IDENTITY, IDENTITY_SIZE, sha_256);

    ck_assert_int_eq(digest_len, SHA256_DIGEST_SIZE);
    for (int i = 0; i < digest_len; i++)
    {
        ck_assert_int_eq(digest[i], TEST_IDENTITY_DIGEST_SHA256[i]);
    }
    free(digest);
}
END_TEST

START_TEST(test_hash_sha512)
{
    uint8_t *digest;
    int digest_len = hash(&digest, TEST_IDENTITY, IDENTITY_SIZE, sha_512);

    ck_assert_int_eq(digest_len, SHA512_DIGEST_SIZE);
    for (int i = 0; i < digest_len; i++)
    {
        ck_assert_int_eq(digest[i], TEST_IDENTITY_DIGEST_SHA512[i]);
    }
    free(digest);
}
END_TEST

#pragma endregion

Suite *utility_suite()
{
    Suite *s = suite_create("utility");
    TCase *tc_hash = tcase_create("hash");

    tcase_add_test(tc_hash, test_hash_sha1);
    tcase_add_test(tc_hash, test_hash_sha256);
    tcase_add_test(tc_hash, test_hash_sha512);

    suite_add_tcase(s, tc_hash);

    return s;
}