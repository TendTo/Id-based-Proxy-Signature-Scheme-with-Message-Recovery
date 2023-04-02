#include <check.h>
#include <signal.h>
#include "sv-scheme.h"
#include "test-const.h"

#pragma region p_sign

START_TEST(test_p_sign)
{
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    delegation_t w;
    warrant_t m;
    element_t sk, k_sign;
    proxy_signature_t p_sig;

    memcpy(m->from, TEST_IDENTITY, IDENTITY_SIZE);
    memcpy(m->to, TEST_IDENTITY_2, IDENTITY_SIZE);

    setup(public_p, secret_p, 80, sha_1);
    element_init_G1(sk, public_p->pairing);
    extract_s(sk, TEST_IDENTITY, secret_p);
    delegate(w, sk, m, public_p);

    element_init_G1(k_sign, public_p->pairing);
    element_set0(k_sign);
    pk_gen(k_sign, sk, w, public_p);
    p_sign(p_sig, k_sign, w, (u_int8_t *)TEST_MESSAGE, strlen(TEST_MESSAGE), public_p);

    ck_assert(p_sig->m == m);
    ck_assert(!element_is0(p_sig->r));
    ck_assert(!element_is0(p_sig->V));
    ck_assert(!element_is0(p_sig->U));
}
END_TEST

#pragma endregion

#pragma region sign_verify

START_TEST(test_sign_verify)
{
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    delegation_t w;
    warrant_t m;
    element_t sk_a, sk_b, k_sign;
    proxy_signature_t p_sig;

    memcpy(m->from, TEST_IDENTITY, IDENTITY_SIZE);
    memcpy(m->to, TEST_IDENTITY_2, IDENTITY_SIZE);

    setup(public_p, secret_p, 80, sha_1);
    extract_s(sk_a, TEST_IDENTITY, secret_p);
    extract_s(sk_b, TEST_IDENTITY_2, secret_p);
    delegate(w, sk_a, m, public_p);

    ck_assert(del_verify(w, TEST_IDENTITY, public_p));

    pk_gen(k_sign, sk_b, w, public_p);
    p_sign(p_sig, k_sign, w, (uint8_t *)TEST_MESSAGE, strlen(TEST_MESSAGE), public_p);

    ck_assert(sign_verify(p_sig, public_p));
}
END_TEST

#pragma endregion

#pragma region clean

START_TEST(test_delegation_clear)
{
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    delegation_t w;
    warrant_t m;
    element_t sk;

    memcpy(m->from, TEST_IDENTITY, IDENTITY_SIZE);
    memcpy(m->to, TEST_IDENTITY_2, IDENTITY_SIZE);

    setup(public_p, secret_p, 80, sha_1);
    extract_s(sk, TEST_IDENTITY, secret_p);
    delegate(w, sk, m, public_p);

    delegation_clear(w);
    ck_assert(1);
}
END_TEST

START_TEST(test_delegation_already_cleared)
{
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    delegation_t w;
    warrant_t m;
    element_t sk;

    memcpy(m->from, TEST_IDENTITY, IDENTITY_SIZE);
    memcpy(m->to, TEST_IDENTITY_2, IDENTITY_SIZE);

    setup(public_p, secret_p, 80, sha_1);
    extract_s(sk, TEST_IDENTITY, secret_p);
    delegate(w, sk, m, public_p);

    delegation_clear(w);
    delegation_clear(w);
    ck_assert(1);
}
END_TEST

#pragma endregion

Suite *sv_scheme_suite()
{
    Suite *s = suite_create("sv-scheme");

    TCase *tc_p_sign = tcase_create("p_sign");
    tcase_add_test(tc_p_sign, test_p_sign);

    TCase *tc_sign_verify = tcase_create("sign_verify");
    tcase_add_test(tc_sign_verify, test_sign_verify);
    // tcase_add_test(tc_verify, test_verify_fail);

    TCase *tc_clear = tcase_create("clear");
    tcase_add_test(tc_clear, test_delegation_clear);
    tcase_add_test_raise_signal(tc_clear, test_delegation_already_cleared, SIGSEGV);

    suite_add_tcase(s, tc_p_sign);
    suite_add_tcase(s, tc_sign_verify);
    suite_add_tcase(s, tc_clear);

    return s;
}