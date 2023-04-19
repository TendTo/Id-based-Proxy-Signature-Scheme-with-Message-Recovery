#include <check.h>
#include <signal.h>
#include "imp-sv-scheme.h"
#include "test-const.h"

#pragma region fixture

sv_public_params_t public_p;
sv_secret_params_t secret_p;
delegation_t w;
warrant_t m;
element_t sk_a, sk_b, k_sign;
proxy_signature_t p_sig;

static void imp_sv_scheme_parametrized_setup_fixture(int _i)
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
    pk_gen(k_sign, sk_b, w, public_p);
}

static void imp_sv_scheme_teardown_fixture()
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

START_TEST(test_imp_p_sign)
{
    imp_sv_scheme_parametrized_setup_fixture(_i);
    imp_p_sign(p_sig, k_sign, w, (u_int8_t *)TEST_MESSAGE, strlen(TEST_MESSAGE), public_p);

    ck_assert(p_sig->m == m);
    ck_assert(!element_is0(p_sig->r));
    ck_assert(!element_is0(p_sig->V));
    ck_assert(!element_is0(p_sig->U));
}
END_TEST

#pragma endregion

#pragma region sign_verify

START_TEST(test_imp_sign_verify_one_msg)
{
    imp_sv_scheme_parametrized_setup_fixture(_i);
    ck_assert(del_verify(w, TEST_IDENTITY, public_p));

    uint8_t one_msg[public_p->l2], msg[public_p->l2];
    memset(one_msg, 1, public_p->l2);

    imp_p_sign(p_sig, k_sign, w, one_msg, public_p->l2, public_p);
    ck_assert(imp_sign_verify(msg, p_sig, public_p));
    for (int i = 0; i < public_p->l2; i++)
        ck_assert_int_eq(msg[i], one_msg[i]);
}
END_TEST

START_TEST(test_imp_sign_verify)
{
    imp_sv_scheme_parametrized_setup_fixture(_i);
    ck_assert(del_verify(w, TEST_IDENTITY, public_p));

    uint8_t msg[public_p->l2];
    imp_p_sign(p_sig, k_sign, w, (uint8_t *)TEST_MESSAGE, strlen(TEST_MESSAGE), public_p);

    ck_assert(imp_sign_verify(msg, p_sig, public_p));
    for (size_t i = 0; i < strlen(TEST_MESSAGE) && i < (size_t)public_p->l2; i++)
        ck_assert_int_eq(msg[i], TEST_MESSAGE[i]);
}
END_TEST

START_TEST(test_imp_sign_verify_fail)
{
    imp_sv_scheme_parametrized_setup_fixture(_i);
    ck_assert(del_verify(w, TEST_IDENTITY, public_p));

    uint8_t msg[public_p->l2];
    // The signature will be created with a different key from the one of the delegated user
    pk_gen(k_sign, sk_a, w, public_p);
    imp_p_sign(p_sig, k_sign, w, (uint8_t *)TEST_MESSAGE, strlen(TEST_MESSAGE), public_p);

    ck_assert(!imp_sign_verify(msg, p_sig, public_p));
}
END_TEST

#pragma endregion

Suite *imp_sv_scheme_suite()
{
    Suite *s = suite_create("imp-sv-scheme");

    TCase *tc_imp_p_sign = tcase_create("imp_p_sign");
    tcase_add_checked_fixture(tc_imp_p_sign, NULL, imp_sv_scheme_teardown_fixture);
    tcase_add_loop_test(tc_imp_p_sign, test_imp_p_sign, 0, N_SEC_LEVELS * N_HASH_TYPES);

    TCase *tc_imp_sign_verify = tcase_create("imp_sign_verify");
    tcase_add_checked_fixture(tc_imp_sign_verify, NULL, imp_sv_scheme_teardown_fixture);
    tcase_add_loop_test(tc_imp_sign_verify, test_imp_sign_verify_one_msg, 0, N_SEC_LEVELS * N_HASH_TYPES);
    tcase_add_loop_test(tc_imp_sign_verify, test_imp_sign_verify, 0, N_SEC_LEVELS * N_HASH_TYPES);
    tcase_add_loop_test(tc_imp_sign_verify, test_imp_sign_verify_fail, 0, N_SEC_LEVELS * N_HASH_TYPES);

    suite_add_tcase(s, tc_imp_p_sign);
    suite_add_tcase(s, tc_imp_sign_verify);

    return s;
}