#include <check.h>
#include "shared.h"
#include "test-const.h"

#pragma region hash

START_TEST(test_hash)
{
    hash_test_t hash_test = hash_tests[_i];
    uint8_t digest[MAX_DIGEST_SIZE];
    int digest_len = hash(digest, TEST_IDENTITY, IDENTITY_SIZE, hash_test.hash_type);

    ck_assert_int_eq(digest_len, hash_test.digest_size);
    for (int i = 0; i < digest_len; i++)
    {
        ck_assert_int_eq(digest[i], hash_test.identity_digest[i]);
    }
}
END_TEST

#pragma endregion

#pragma region hash_element

START_TEST(test_hash_element)
{
    hash_test_t hash_test = hash_tests[_i];
    pbc_param_t param;
    pairing_t pairing;
    element_t e;
    pbc_param_init_a_gen(param, 160, 512);
    pairing_init_pbc_param(pairing, param);

    element_init_Zr(e, pairing);
    element_set1(e);

    uint8_t digest[MAX_DIGEST_SIZE];
    int digest_len = hash_element(digest, e, hash_test.hash_type);

    ck_assert_int_eq(digest_len, hash_test.digest_size);
    for (int i = 0; i < digest_len; i++)
    {
        ck_assert_int_eq(digest[i], hash_test.element_digest[i]);
    }
}
END_TEST

#pragma endregion

Suite *utility_suite()
{
    Suite *s = suite_create("utility");

    TCase *tc_hash = tcase_create("hash");
    tcase_add_loop_test(tc_hash, test_hash, 0, N_HASH_TYPES);

    TCase *tc_hash_element = tcase_create("hash_element");
    tcase_add_loop_test(tc_hash_element, test_hash_element, 0, N_HASH_TYPES);

    suite_add_tcase(s, tc_hash);
    suite_add_tcase(s, tc_hash_element);

    return s;
}