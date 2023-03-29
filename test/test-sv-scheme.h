#include <check.h>
#include <signal.h>
#include "sv-scheme.h"
#include "test-const.h"

#pragma region setup

START_TEST(test_setup)
{
    const int sec_lvl = sec_levels[_i];
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    setup(public_p, secret_p, sec_lvl);

    ck_assert(pairing_is_symmetric(public_p->pairing));
    ck_assert(pairing_length_in_bytes_Zr(public_p->pairing) * 8 == sec_lvl * 2);
}
END_TEST

START_TEST(test_setup_pk)
{
    const int sec_lvl = sec_levels[_i];
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    setup(public_p, secret_p, sec_lvl);

    element_t new_pk;
    element_init_G1(new_pk, public_p->pairing);
    element_mul_zn(new_pk, public_p->P, secret_p->sk);
    ck_assert(element_cmp(new_pk, public_p->pk) == 0);
}
END_TEST

START_TEST(test_setup_order)
{
    const int sec_lvl = sec_levels[_i];
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    setup(public_p, secret_p, sec_lvl);

    ck_assert_msg(public_p->q == sec_levels_order[_i], "Expected: %d, Actual: %d", sec_levels_order[_i], public_p->q);
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
    setup(public_p, secret_p, sec_lvl);
    extract_p(pk_id, public_p, (void *)IDENTITY, IDENTITY_LEN);

    element_t test_pk_id;
    element_init_G1(test_pk_id, public_p->pairing);
    element_from_hash(test_pk_id, (void *)IDENTITY_DIGEST, SHA1_DIGEST_SIZE);
    ck_assert(element_cmp(pk_id, test_pk_id) == 0);
}
END_TEST

#pragma endregion

#pragma region clear

START_TEST(test_public_params_clear)
{
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    setup(public_p, secret_p, 80);
    public_param_clear(public_p);
    ck_assert(1);
}
END_TEST

START_TEST(test_public_params_already_cleared)
{
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    setup(public_p, secret_p, 80);
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
    setup(public_p, secret_p, 80);
    secret_param_clear(secret_p);
    ck_assert(1);
}
END_TEST

START_TEST(test_secret_params_already_cleared)
{
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    setup(public_p, secret_p, 80);
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

Suite *sv_scheme_suite()
{
    Suite *s = suite_create("sv-scheme");

    TCase *tc_setup = tcase_create("setup");
    tcase_add_loop_test(tc_setup, test_setup, 0, N_SEC_LEVELS);
    tcase_add_loop_test(tc_setup, test_setup_pk, 0, N_SEC_LEVELS);
    tcase_add_loop_test(tc_setup, test_setup_order, 0, N_SEC_LEVELS);

    TCase *tc_extract = tcase_create("extract");
    tcase_add_loop_test(tc_extract, test_extract_p, 0, N_SEC_LEVELS);

    TCase *tc_clear = tcase_create("clear");
    tcase_add_test(tc_clear, test_public_params_clear);
    tcase_add_test_raise_signal(tc_clear, test_public_params_already_cleared, SIGSEGV);
    tcase_add_test_raise_signal(tc_clear, test_public_params_not_init, SIGSEGV);
    tcase_add_test(tc_clear, test_secret_params_clear);
    tcase_add_test(tc_clear, test_secret_params_already_cleared); // Elements can be cleared more than once
    tcase_add_test_raise_signal(tc_clear, test_secret_params_not_init, SIGSEGV);

    suite_add_tcase(s, tc_setup);
    suite_add_tcase(s, tc_extract);
    suite_add_tcase(s, tc_clear);

    return s;
}