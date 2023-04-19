#include <check.h>
#include <signal.h>
#include "sv-scheme.h"
#include "test-const.h"

#pragma region fixture

sv_public_params_t public_p;
sv_secret_params_t secret_p;
delegation_t w;
warrant_t m;
element_t sk_a, sk_b, k_sign;
proxy_signature_t p_sig;

void parametrized_setup_fixture(int _i)
{
    memcpy(m->from, TEST_IDENTITY, IDENTITY_SIZE);
    memcpy(m->to, TEST_IDENTITY_2, IDENTITY_SIZE);

    // Use all combinations of security levels and hash type
    int sec_lvl = sec_levels[_i % N_SEC_LEVELS];
    hash_type_t hash_type = hash_types[_i / N_SEC_LEVELS];

    setup(public_p, secret_p, sec_lvl, hash_type);
    element_init_G1(sk_a, public_p->pairing);
    element_init_G1(sk_b, public_p->pairing);
    extract_s(sk_a, TEST_IDENTITY, secret_p);
    extract_s(sk_b, TEST_IDENTITY_2, secret_p);
    delegate(w, sk_a, m, public_p);

    element_init_G1(k_sign, public_p->pairing);
    pk_gen(k_sign, sk_b, w, public_p);
}

void teardown_fixture()
{
    element_clear(sk_a);
    element_clear(sk_b);
    element_clear(k_sign);
    delegation_clear(w);
    proxy_signature_clear(p_sig);
    secret_param_clear(secret_p);
    public_param_clear(public_p);
}

#pragma endregion

#pragma region p_sign

START_TEST(test_p_sign)
{
    parametrized_setup_fixture(_i);
    p_sign(p_sig, k_sign, w, (u_int8_t *)TEST_MESSAGE, strlen(TEST_MESSAGE), public_p);

    ck_assert(p_sig->m == m);
    ck_assert(!element_is0(p_sig->r));
    ck_assert(!element_is0(p_sig->V));
    ck_assert(!element_is0(p_sig->U));
}
END_TEST

#pragma endregion

#pragma region sign_verify

START_TEST(test_sign_verify_one_msg)
{
    parametrized_setup_fixture(_i);
    ck_assert(del_verify(w, TEST_IDENTITY, public_p));

    uint8_t one_msg[public_p->l2];
    memset(one_msg, 1, public_p->l2);

    p_sign(p_sig, k_sign, w, one_msg, public_p->l2, public_p);

    ck_assert(!sign_verify(p_sig, public_p));

    int sec_lvl = sec_levels[_i % N_SEC_LEVELS];
    hash_type_t hash_type = hash_types[_i / N_SEC_LEVELS];
    printf("ONE_MSG: Testing with security level %d and hash function %d\n", sec_lvl, hash_type);
    printf("L1: %d, L2: %d\n", public_p->l1, public_p->l2);
}
END_TEST

START_TEST(test_sign_verify)
{
    parametrized_setup_fixture(_i);
    ck_assert(del_verify(w, TEST_IDENTITY, public_p));

    p_sign(p_sig, k_sign, w, (uint8_t *)TEST_MESSAGE, strlen(TEST_MESSAGE), public_p);

    ck_assert(!sign_verify(p_sig, public_p));

    int sec_lvl = sec_levels[_i % N_SEC_LEVELS];
    hash_type_t hash_type = hash_types[_i / N_SEC_LEVELS];
    printf("VERIFY: Testing with security level %d and hash function %d\n", sec_lvl, hash_type);
    printf("L1: %d, L2: %d\n", public_p->l1, public_p->l2);
}
END_TEST

START_TEST(test_sign_verify_fail)
{
    parametrized_setup_fixture(_i);
    ck_assert(del_verify(w, TEST_IDENTITY, public_p));

    // The signature will be created with a different key from the one of the delegated user
    pk_gen(k_sign, sk_a, w, public_p);
    p_sign(p_sig, k_sign, w, (uint8_t *)TEST_MESSAGE, strlen(TEST_MESSAGE), public_p);

    ck_assert(!sign_verify(p_sig, public_p));
}
END_TEST

#pragma endregion

Suite *sv_scheme_suite()
{
    Suite *s = suite_create("sv-scheme");

    TCase *tc_p_sign = tcase_create("p_sign");
    tcase_add_checked_fixture(tc_p_sign, NULL, teardown_fixture);
    tcase_add_loop_test(tc_p_sign, test_p_sign, 0, N_SEC_LEVELS * N_HASH_TYPES);

    TCase *tc_sign_verify = tcase_create("sign_verify");
    tcase_add_checked_fixture(tc_sign_verify, NULL, teardown_fixture);
    tcase_add_loop_test(tc_sign_verify, test_sign_verify_one_msg, 0, N_SEC_LEVELS * N_HASH_TYPES);
    tcase_add_loop_test(tc_sign_verify, test_sign_verify, 0, N_SEC_LEVELS * N_HASH_TYPES);
    tcase_add_loop_test(tc_sign_verify, test_sign_verify_fail, 0, N_SEC_LEVELS * N_HASH_TYPES);

    suite_add_tcase(s, tc_p_sign);
    suite_add_tcase(s, tc_sign_verify);

    return s;
}