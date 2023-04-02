#include <signal.h>
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

#pragma region calculate_beta

START_TEST(test_calculate_beta)
{
    uint8_t beta[MAX_DIGEST_SIZE];
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;

    setup(public_p, secret_p, 80, sha_256);
    calculate_beta(beta, (uint8_t *)TEST_MESSAGE, strlen(TEST_MESSAGE), public_p);

    for (int i = 0; i < public_p->q; i++)
    {
        ck_assert_int_eq(beta[i], TEST_MESSAGE_DIGEST_SHA256[i]);
    }
}
END_TEST

#pragma endregion

#pragma region serialization

START_TEST(test_serialization)
{
    serialized_warrant_t warrant_buffer;
    warrant_t m;

    for (size_t i = 0; i < IDENTITY_SIZE; i++)
    {
        m->from[i] = i;
        m->to[i] = i + IDENTITY_SIZE;
    }

    unsigned short size = serialize_warrant(warrant_buffer, m);

    ck_assert_int_eq(size, WARRANT_SIZE);
    for (size_t i = 0; i < WARRANT_SIZE; i++)
    {
        ck_assert_int_eq(warrant_buffer[i], i);
    }
}
END_TEST

START_TEST(test_deserialization)
{
    serialized_warrant_t warrant_buffer;
    warrant_t m;

    for (size_t i = 0; i < WARRANT_SIZE; i++)
    {
        warrant_buffer[i] = i;
    }

    unsigned short size = deserialize_warrant(m, warrant_buffer);

    ck_assert_int_eq(size, WARRANT_SIZE);
    for (size_t i = 0; i < IDENTITY_SIZE; i++)
    {
        ck_assert_int_eq(m->from[i], i);
        ck_assert_int_eq(m->to[i], i + IDENTITY_SIZE);
    }
}
END_TEST

#pragma endregion

#pragma region setup

START_TEST(test_setup)
{
    const int sec_lvl = sec_levels[_i];
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    setup(public_p, secret_p, sec_lvl, sha_1);

    ck_assert(pairing_is_symmetric(public_p->pairing));
    ck_assert_int_eq(pairing_length_in_bytes_Zr(public_p->pairing) * 8, sec_lvl * 2);
}
END_TEST

START_TEST(test_setup_hash)
{
    const hash_type_t hash_type = hash_types[_i];
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    setup(public_p, secret_p, 80, hash_type);

    ck_assert_int_eq(public_p->hash_type, hash_type);
}
END_TEST

START_TEST(test_setup_pk)
{
    const int sec_lvl = sec_levels[_i];
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    setup(public_p, secret_p, sec_lvl, sha_1);

    element_t new_pk;
    element_init_G1(new_pk, public_p->pairing);
    element_mul_zn(new_pk, public_p->P, secret_p->msk);
    ck_assert(element_cmp(new_pk, public_p->pk) == 0);
}
END_TEST

START_TEST(test_setup_order)
{
    const int sec_lvl = sec_levels[_i];
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    setup(public_p, secret_p, sec_lvl, sha_1);

    ck_assert(public_p->q >= sec_levels_order[_i] / 8);
    ck_assert(public_p->l1 + public_p->l2 == public_p->q);
}
END_TEST

#pragma endregion

#pragma region extract

START_TEST(test_extract_p)
{
    const int sec_lvl = sec_levels[_i];
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    element_t pk_id;
    setup(public_p, secret_p, sec_lvl, sha_1);
    extract_p(pk_id, TEST_IDENTITY, public_p);

    element_t test_pk_id;
    element_init_G1(test_pk_id, public_p->pairing);
    element_from_hash(test_pk_id, (void *)TEST_IDENTITY_DIGEST_SHA1, SHA1_DIGEST_SIZE);
    ck_assert(element_cmp(pk_id, test_pk_id) == 0);
}
END_TEST

START_TEST(test_extract_s)
{
    const int sec_lvl = sec_levels[_i];
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    element_t sk_id;
    setup(public_p, secret_p, sec_lvl, sha_1);
    extract_s(sk_id, TEST_IDENTITY, secret_p);

    element_t test_sk_id;
    element_init_G1(test_sk_id, public_p->pairing);
    element_from_hash(test_sk_id, (void *)TEST_IDENTITY_DIGEST_SHA1, SHA1_DIGEST_SIZE);
    element_mul_zn(test_sk_id, test_sk_id, secret_p->msk);
    ck_assert(element_cmp(sk_id, test_sk_id) == 0);
}
END_TEST

START_TEST(test_extract_relationship)
{
    const int sec_lvl = sec_levels[_i];
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    element_t pk_id, sk_id, temp;

    setup(public_p, secret_p, sec_lvl, sha_1);
    extract_p(pk_id, TEST_IDENTITY, public_p);
    extract_s(sk_id, TEST_IDENTITY, secret_p);

    element_init_G1(temp, public_p->pairing);
    element_mul_zn(temp, pk_id, secret_p->msk);
    ck_assert(element_cmp(sk_id, temp) == 0);
}
END_TEST

#pragma endregion

#pragma region delegate

START_TEST(test_delegate)
{
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    delegation_t w;
    warrant_t m;
    element_t sk;

    memcpy(m->from, TEST_IDENTITY, IDENTITY_SIZE);
    memcpy(m->to, TEST_IDENTITY_2, IDENTITY_SIZE);

    setup(public_p, secret_p, 80, sha_1);
    element_init_G1(sk, public_p->pairing);
    extract_s(sk, TEST_IDENTITY, secret_p);
    delegate(w, sk, m, public_p);

    ck_assert_ptr_eq(w->m, m);
    ck_assert(!element_is0(w->r));
    ck_assert(!element_is0(w->S));
}
END_TEST

#pragma endregion

#pragma region del_verify

START_TEST(test_del_verify)
{
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    delegation_t w;
    warrant_t m;
    element_t sk;

    memcpy(m->from, TEST_IDENTITY, IDENTITY_SIZE);
    memcpy(m->to, TEST_IDENTITY_2, IDENTITY_SIZE);

    setup(public_p, secret_p, 80, sha_1);
    element_init_G1(sk, public_p->pairing);
    extract_s(sk, TEST_IDENTITY, secret_p);
    delegate(w, sk, m, public_p);

    ck_assert(del_verify(w, TEST_IDENTITY, public_p));
}
END_TEST

START_TEST(test_del_verify_fail)
{
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    delegation_t w;
    warrant_t m;
    element_t sk;

    memcpy(m->from, TEST_IDENTITY, IDENTITY_SIZE);
    memcpy(m->to, TEST_IDENTITY_2, IDENTITY_SIZE);

    setup(public_p, secret_p, 80, sha_1);
    element_init_G1(sk, public_p->pairing);
    extract_s(sk, TEST_IDENTITY, secret_p);
    delegate(w, sk, m, public_p);

    // Wrong identity as the one that delegated
    ck_assert(!del_verify(w, TEST_IDENTITY_2, public_p));
}
END_TEST

#pragma endregion

#pragma region clear

START_TEST(test_public_params_clear)
{
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    setup(public_p, secret_p, 80, sha_1);
    public_param_clear(public_p);
    ck_assert(1);
}
END_TEST

START_TEST(test_public_params_already_cleared)
{
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    setup(public_p, secret_p, 80, sha_1);
    public_param_clear(public_p);
    public_param_clear(public_p);
}
END_TEST

START_TEST(test_public_params_not_init)
{
    sv_public_params_t public_p;
    public_param_clear(public_p);
}
END_TEST

START_TEST(test_secret_params_clear)
{
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    setup(public_p, secret_p, 80, sha_1);
    secret_param_clear(secret_p);
    ck_assert(1);
}
END_TEST

START_TEST(test_secret_params_already_cleared)
{
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    setup(public_p, secret_p, 80, sha_1);
    secret_param_clear(secret_p);
    secret_param_clear(secret_p);
}
END_TEST

START_TEST(test_secret_params_not_init)
{
    sv_secret_params_t secret_p;
    secret_param_clear(secret_p);
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

    TCase *tc_calculate_beta = tcase_create("calculate_beta");
    tcase_add_test(tc_calculate_beta, test_calculate_beta);

    TCase *tc_serialize = tcase_create("serialize");
    tcase_add_test(tc_serialize, test_serialization);
    tcase_add_test(tc_serialize, test_deserialization);

    TCase *tc_setup = tcase_create("setup");
    tcase_add_loop_test(tc_setup, test_setup, 0, N_SEC_LEVELS);
    tcase_add_loop_test(tc_setup, test_setup_hash, 0, N_HASH_TYPES);
    tcase_add_loop_test(tc_setup, test_setup_pk, 0, N_SEC_LEVELS);
    tcase_add_loop_test(tc_setup, test_setup_order, 0, N_SEC_LEVELS);

    TCase *tc_extract = tcase_create("extract");
    tcase_add_loop_test(tc_extract, test_extract_p, 0, N_SEC_LEVELS);
    tcase_add_loop_test(tc_extract, test_extract_s, 0, N_SEC_LEVELS);
    tcase_add_loop_test(tc_extract, test_extract_relationship, 0, N_SEC_LEVELS);

    TCase *tc_delegate = tcase_create("delegate");
    tcase_add_test(tc_delegate, test_delegate);

    TCase *tc_del_verify = tcase_create("del_verify");
    tcase_add_test(tc_del_verify, test_del_verify);
    tcase_add_test(tc_del_verify, test_del_verify_fail);

    TCase *tc_clear = tcase_create("clear");
    tcase_add_test(tc_clear, test_public_params_clear);
    tcase_add_test_raise_signal(tc_clear, test_public_params_already_cleared, SIGSEGV);
    tcase_add_test_raise_signal(tc_clear, test_public_params_not_init, SIGSEGV);
    tcase_add_test(tc_clear, test_secret_params_clear);
    tcase_add_test(tc_clear, test_secret_params_already_cleared); // Elements can be cleared more than once
    tcase_add_test_raise_signal(tc_clear, test_secret_params_not_init, SIGSEGV);

    suite_add_tcase(s, tc_hash);
    suite_add_tcase(s, tc_hash_element);
    suite_add_tcase(s, tc_calculate_beta);
    suite_add_tcase(s, tc_serialize);
    suite_add_tcase(s, tc_setup);
    suite_add_tcase(s, tc_extract);
    suite_add_tcase(s, tc_delegate);
    suite_add_tcase(s, tc_del_verify);
    suite_add_tcase(s, tc_clear);

    return s;
}