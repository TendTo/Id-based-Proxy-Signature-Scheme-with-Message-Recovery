#include <check.h>
#include <signal.h>
#include "imp-sv-scheme.h"
#include "test-const.h"

#pragma region p_sign

START_TEST(test_imp_p_sign)
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
    imp_p_sign(p_sig, k_sign, w, (u_int8_t *)TEST_MESSAGE, strlen(TEST_MESSAGE), public_p);

    ck_assert(p_sig->m == m);
    ck_assert(!element_is0(p_sig->r));
    ck_assert(!element_is0(p_sig->V));
    ck_assert(!element_is0(p_sig->U));
}
END_TEST

#pragma endregion

#pragma region sign_verify

START_TEST(test_imp_sign_verify)
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
    imp_p_sign(p_sig, k_sign, w, (uint8_t *)TEST_MESSAGE, strlen(TEST_MESSAGE), public_p);

    ck_assert(imp_sign_verify(p_sig, public_p));
}
END_TEST

#pragma endregion

#pragma region clean

#pragma endregion

Suite *imp_sv_scheme_suite()
{
    Suite *s = suite_create("imp-sv-scheme");

    TCase *tc_imp_p_sign = tcase_create("imp_p_sign");
    tcase_add_test(tc_imp_p_sign, test_imp_p_sign);

    TCase *tc_imp_sign_verify = tcase_create("imp_sign_verify");
    tcase_add_test(tc_imp_sign_verify, test_imp_sign_verify);
    // tcase_add_test(tc_verify, test_verify_fail);

    suite_add_tcase(s, tc_imp_p_sign);
    suite_add_tcase(s, tc_imp_sign_verify);

    return s;
}