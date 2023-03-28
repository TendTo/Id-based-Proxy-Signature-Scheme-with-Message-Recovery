#include <check.h>
#include <signal.h>
#include "sv-scheme.h"
#include "test-const.h"

#pragma region setup

START_TEST(test_setup)
{
    const int sec_lvl = sec_levels[_i];
    sv_shared_params_t shared_p;
    sv_private_params_t private_p;
    setup(shared_p, private_p, sec_lvl);

    ck_assert(pairing_is_symmetric(shared_p->pairing));
    ck_assert(pairing_length_in_bytes_Zr(shared_p->pairing) * 8 == sec_lvl * 2);
}
END_TEST

START_TEST(test_setup_pk)
{
    const int sec_lvl = sec_levels[_i];
    sv_shared_params_t shared_p;
    sv_private_params_t private_p;
    setup(shared_p, private_p, sec_lvl);

    element_t new_pk;
    element_init_G1(new_pk, shared_p->pairing);
    element_mul_zn(new_pk, shared_p->P, private_p->sk);
    ck_assert(element_cmp(new_pk, shared_p->pk) == 0);
}
END_TEST

#pragma endregion

#pragma region clear

START_TEST(test_shared_params_clear)
{
    sv_shared_params_t shared_p;
    sv_private_params_t private_p;
    setup(shared_p, private_p, 80);
    shared_param_clear(shared_p);
    ck_assert(1);
}
END_TEST

START_TEST(test_shared_params_already_cleared)
{
    sv_shared_params_t shared_p;
    sv_private_params_t private_p;
    setup(shared_p, private_p, 80);
    shared_param_clear(shared_p);
    shared_param_clear(shared_p);
}
END_TEST

START_TEST(test_shared_params_not_init)
{
    sv_shared_params_t shared_p;
    shared_param_clear(shared_p);
}
END_TEST

START_TEST(test_private_params_clear)
{
    sv_shared_params_t shared_p;
    sv_private_params_t private_p;
    setup(shared_p, private_p, 80);
    private_param_clear(private_p);
    ck_assert(1);
}
END_TEST

START_TEST(test_private_params_already_cleared)
{
    sv_shared_params_t shared_p;
    sv_private_params_t private_p;
    setup(shared_p, private_p, 80);
    private_param_clear(private_p);
    private_param_clear(private_p);
}
END_TEST

START_TEST(test_private_params_not_init)
{
    sv_private_params_t private_p;
    private_param_clear(private_p);
}
END_TEST

#pragma endregion

Suite *sv_scheme_suite()
{
    Suite *s = suite_create("sv-scheme");

    TCase *tc_setup = tcase_create("setup");
    tcase_add_loop_test(tc_setup, test_setup, 0, N_SEC_LEVELS);
    tcase_add_loop_test(tc_setup, test_setup_pk, 0, N_SEC_LEVELS);

    TCase *tc_clear = tcase_create("clear");
    tcase_add_test(tc_clear, test_shared_params_clear);
    tcase_add_test_raise_signal(tc_clear, test_shared_params_already_cleared, SIGSEGV);
    tcase_add_test_raise_signal(tc_clear, test_shared_params_not_init, SIGSEGV);
    tcase_add_test(tc_clear, test_private_params_clear);
    tcase_add_test(tc_clear, test_private_params_already_cleared); // Elements can be cleared more than once
    tcase_add_test_raise_signal(tc_clear, test_private_params_not_init, SIGSEGV);

    suite_add_tcase(s, tc_setup);
    suite_add_tcase(s, tc_clear);

    return s;
}