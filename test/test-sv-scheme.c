#include "test-sv-scheme.h"

#pragma region fixture

static sv_public_params_t public_p;
static sv_secret_params_t secret_p;
static sv_user_t from, to;
static delegation_t w;
static element_t k_sign;
static proxy_signature_t p_sig;

static void sv_scheme_parametrized_setup_fixture(int _i, short precompute)
{
    // Use all combinations of security levels and hash type
    int sec_lvl = sec_levels[_i % N_SEC_LEVELS];
    hash_type_t hash_type = hash_types[_i / N_SEC_LEVELS];

    setup(public_p, secret_p, sec_lvl, hash_type);
    if (precompute)
        public_params_pp(public_p);
    user_init(from, TEST_IDENTITY, public_p);
    user_init(to, TEST_IDENTITY_2, public_p);
    extract_s(from, secret_p);
    extract_s(to, secret_p);
    delegation_init(w, public_p);
    delegate(w, from, to, public_p);
    pk_gen(k_sign, to, w, public_p);
    proxy_signature_init(p_sig, public_p);
}

static void sv_scheme_teardown_fixture()
{
    user_clear(from);
    user_clear(to);
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
    sv_scheme_parametrized_setup_fixture(_i, 0);
    p_sign(p_sig, k_sign, w, (u_int8_t *)TEST_MESSAGE, strlen(TEST_MESSAGE), public_p);

    ck_assert_mem_eq(p_sig->m->from, from->id, IDENTITY_SIZE);
    ck_assert_mem_eq(p_sig->m->to, to->id, IDENTITY_SIZE);
    ck_assert(!element_is0(p_sig->r));
    ck_assert(!element_is0(p_sig->V));
    ck_assert(!element_is0(p_sig->U));
}
END_TEST

START_TEST(test_p_sign_pp)
{
    sv_scheme_parametrized_setup_fixture(_i, 1);
    p_sign(p_sig, k_sign, w, (u_int8_t *)TEST_MESSAGE, strlen(TEST_MESSAGE), public_p);

    ck_assert_mem_eq(p_sig->m->from, from->id, IDENTITY_SIZE);
    ck_assert_mem_eq(p_sig->m->to, to->id, IDENTITY_SIZE);
    ck_assert(!element_is0(p_sig->r));
    ck_assert(!element_is0(p_sig->V));
    ck_assert(!element_is0(p_sig->U));
}
END_TEST

#pragma endregion

#pragma region sign_verify

START_TEST(test_sign_verify_one_msg)
{
    sv_scheme_parametrized_setup_fixture(_i, 0);
    ck_assert(del_verify(w, public_p));

    uint8_t one_msg[public_p->l2], msg[public_p->l2];
    memset(one_msg, 1, public_p->l2);

    p_sign(p_sig, k_sign, w, one_msg, public_p->l2, public_p);
    ck_assert(sign_verify(msg, p_sig, public_p));
    ck_assert_mem_eq(msg, one_msg, public_p->l2);
}
END_TEST

START_TEST(test_sign_verify_one_msg_pp)
{
    sv_scheme_parametrized_setup_fixture(_i, 1);
    ck_assert(del_verify(w, public_p));

    uint8_t one_msg[public_p->l2], msg[public_p->l2];
    memset(one_msg, 1, public_p->l2);

    p_sign(p_sig, k_sign, w, one_msg, public_p->l2, public_p);
    ck_assert(sign_verify(msg, p_sig, public_p));
    ck_assert_mem_eq(msg, one_msg, public_p->l2);
}
END_TEST

START_TEST(test_sign_verify)
{
    sv_scheme_parametrized_setup_fixture(_i, 0);
    ck_assert(del_verify(w, public_p));

    uint8_t msg[public_p->l2];
    p_sign(p_sig, k_sign, w, (uint8_t *)TEST_MESSAGE, strlen(TEST_MESSAGE), public_p);

    ck_assert(sign_verify(msg, p_sig, public_p));
    size_t min_len = strlen(TEST_MESSAGE) < (size_t)public_p->l2 ? strlen(TEST_MESSAGE) : (size_t)public_p->l2;
    ck_assert_mem_eq(msg, TEST_MESSAGE, min_len);
}
END_TEST

START_TEST(test_sign_verify_pp)
{
    sv_scheme_parametrized_setup_fixture(_i, 1);
    ck_assert(del_verify(w, public_p));

    uint8_t msg[public_p->l2];
    p_sign(p_sig, k_sign, w, (uint8_t *)TEST_MESSAGE, strlen(TEST_MESSAGE), public_p);

    ck_assert(sign_verify(msg, p_sig, public_p));
    size_t min_len = strlen(TEST_MESSAGE) < (size_t)public_p->l2 ? strlen(TEST_MESSAGE) : (size_t)public_p->l2;
    ck_assert_mem_eq(msg, TEST_MESSAGE, min_len);
}
END_TEST

START_TEST(test_sign_verify_fail)
{
    sv_scheme_parametrized_setup_fixture(_i, 0);
    ck_assert(del_verify(w, public_p));

    uint8_t msg[public_p->l2];
    // The signature will be created with a different key from the one of the delegated user
    pk_gen(k_sign, from, w, public_p);
    p_sign(p_sig, k_sign, w, (uint8_t *)TEST_MESSAGE, strlen(TEST_MESSAGE), public_p);

    ck_assert(!sign_verify(msg, p_sig, public_p));
}
END_TEST

START_TEST(test_sign_verify_fail_pp)
{
    sv_scheme_parametrized_setup_fixture(_i, 1);
    ck_assert(del_verify(w, public_p));

    uint8_t msg[public_p->l2];
    // The signature will be created with a different key from the one of the delegated user
    pk_gen(k_sign, from, w, public_p);
    p_sign(p_sig, k_sign, w, (uint8_t *)TEST_MESSAGE, strlen(TEST_MESSAGE), public_p);

    ck_assert(!sign_verify(msg, p_sig, public_p));
}
END_TEST

#pragma endregion

Suite *sv_scheme_suite()
{
    Suite *s = suite_create("sv-scheme");

    TCase *tc_p_sign = tcase_create("p_sign");
    tcase_add_checked_fixture(tc_p_sign, NULL, sv_scheme_teardown_fixture);
    tcase_add_loop_test(tc_p_sign, test_p_sign, 0, N_SEC_LEVELS * N_HASH_TYPES);
    tcase_add_loop_test(tc_p_sign, test_p_sign_pp, 0, N_SEC_LEVELS * N_HASH_TYPES);

    TCase *tc_sign_verify = tcase_create("sign_verify");
    tcase_add_checked_fixture(tc_sign_verify, NULL, sv_scheme_teardown_fixture);
    tcase_add_loop_test(tc_sign_verify, test_sign_verify_one_msg, 0, N_SEC_LEVELS * N_HASH_TYPES);
    tcase_add_loop_test(tc_sign_verify, test_sign_verify_one_msg_pp, 0, N_SEC_LEVELS * N_HASH_TYPES);
    tcase_add_loop_test(tc_sign_verify, test_sign_verify, 0, N_SEC_LEVELS * N_HASH_TYPES);
    tcase_add_loop_test(tc_sign_verify, test_sign_verify_pp, 0, N_SEC_LEVELS * N_HASH_TYPES);
    tcase_add_loop_test(tc_sign_verify, test_sign_verify_fail, 0, N_SEC_LEVELS * N_HASH_TYPES);
    tcase_add_loop_test(tc_sign_verify, test_sign_verify_fail_pp, 0, N_SEC_LEVELS * N_HASH_TYPES);

    suite_add_tcase(s, tc_p_sign);
    suite_add_tcase(s, tc_sign_verify);

    return s;
}