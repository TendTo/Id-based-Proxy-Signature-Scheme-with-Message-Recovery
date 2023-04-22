#include "test-shared.h"

#pragma region hash

START_TEST(test_hash)
{
    hash_test_t hash_test = hash_tests[_i];
    uint8_t digest[MAX_DIGEST_SIZE];
    int digest_len = hash(digest, TEST_IDENTITY, IDENTITY_SIZE, hash_test.hash_type);

    ck_assert_int_eq(digest_len, hash_test.digest_size);
    ck_assert_mem_eq(digest, hash_test.identity_digest, digest_len);
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

    ck_assert_mem_eq(beta, TEST_MESSAGE_DIGEST_SHA256, public_p->q);
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

    ck_assert_int_eq(public_p->precompute, 0);
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

    ck_assert((size_t)public_p->q >= sec_levels_order[_i] / 8);
    ck_assert(public_p->l1 + public_p->l2 == public_p->q);
}
END_TEST

START_TEST(test_setup_str)
{
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    setup_from_str(public_p, secret_p, TEST_PAIRING_P);

    char buffer[MAX_PARAM_LINE_SIZE];

    element_snprintf(buffer, MAX_PARAM_LINE_SIZE, "%B", public_p->P);
    ck_assert_int_eq(strcmp(buffer, TEST_P), 0);
    element_snprintf(buffer, MAX_PARAM_LINE_SIZE, "%B", public_p->pk);
    ck_assert_int_eq(strcmp(buffer, TEST_PK), 0);
    element_snprintf(buffer, MAX_PARAM_LINE_SIZE, "%B", secret_p->msk);
    ck_assert_int_eq(strcmp(buffer, TEST_MSK), 0);
    ck_assert_int_eq(public_p->q, TEST_Q);
    ck_assert_int_eq(public_p->l1, TEST_L1);
    ck_assert_int_eq(public_p->l2, TEST_L2);
    ck_assert_int_eq(public_p->hash_type, TEST_HASH_TYPE);
}
END_TEST

START_TEST(test_setup_pp)
{
    const int sec_lvl = sec_levels[_i];
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    setup(public_p, secret_p, sec_lvl, sha_1);
    public_params_pp(public_p);

    ck_assert_int_eq(public_p->precompute, 1);
    ck_assert(public_p->eP_pp != NULL);
    ck_assert(public_p->epk_pp != NULL);
    ck_assert(public_p->PP_pp != NULL);
}
END_TEST

#pragma endregion

#pragma region extract

START_TEST(test_extract_p)
{
    const int sec_lvl = sec_levels[_i];
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    sv_user_t user;

    setup(public_p, secret_p, sec_lvl, sha_1);
    user_init(user, TEST_IDENTITY, public_p);
    extract_p(user, public_p);

    element_t test_pk_id;
    element_init_G1(test_pk_id, public_p->pairing);
    element_from_hash(test_pk_id, (void *)TEST_IDENTITY_DIGEST_SHA1, SHA1_DIGEST_SIZE);
    ck_assert(element_cmp(user->pk, test_pk_id) == 0);
}
END_TEST

START_TEST(test_extract_s)
{
    const int sec_lvl = sec_levels[_i];
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    sv_user_t user;

    setup(public_p, secret_p, sec_lvl, sha_1);
    user_init(user, TEST_IDENTITY, public_p);
    extract_s(user, secret_p);

    element_t test_sk_id;
    element_init_G1(test_sk_id, public_p->pairing);
    element_from_hash(test_sk_id, (void *)TEST_IDENTITY_DIGEST_SHA1, SHA1_DIGEST_SIZE);
    element_mul_zn(test_sk_id, test_sk_id, secret_p->msk);
    ck_assert(element_cmp(user->sk, test_sk_id) == 0);
}
END_TEST

START_TEST(test_extract_relationship)
{
    const int sec_lvl = sec_levels[_i];
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    sv_user_t user;
    element_t temp;

    setup(public_p, secret_p, sec_lvl, sha_1);
    user_init(user, TEST_IDENTITY, public_p);
    extract_p(user, public_p);
    extract_s(user, secret_p);

    element_init_G1(temp, public_p->pairing);
    element_mul_zn(temp, user->pk, secret_p->msk);
    ck_assert(element_cmp(user->sk, temp) == 0);
}
END_TEST

#pragma endregion

#pragma region delegate

START_TEST(test_delegate)
{
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    sv_user_t from, to;
    delegation_t w;

    setup(public_p, secret_p, 80, sha_1);
    user_init(from, TEST_IDENTITY, public_p);
    user_init(to, TEST_IDENTITY_2, public_p);
    extract_s(from, secret_p);
    delegation_init(w, public_p);
    delegate(w, from, to, public_p);

    ck_assert_mem_eq(w->m->from, from->id, IDENTITY_SIZE);
    ck_assert_mem_eq(w->m->to, to->id, IDENTITY_SIZE);
    ck_assert(!element_is0(w->r));
    ck_assert(!element_is0(w->S));
}
END_TEST

START_TEST(test_delegate_pp)
{
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    sv_user_t from, to;
    delegation_t w;

    setup(public_p, secret_p, 80, sha_1);
    public_params_pp(public_p);
    user_init(from, TEST_IDENTITY, public_p);
    user_init(to, TEST_IDENTITY_2, public_p);
    extract_s(from, secret_p);
    delegation_init(w, public_p);
    delegate(w, from, to, public_p);

    ck_assert_mem_eq(w->m->from, from->id, IDENTITY_SIZE);
    ck_assert_mem_eq(w->m->to, to->id, IDENTITY_SIZE);
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
    sv_user_t from, to;
    delegation_t w;

    setup(public_p, secret_p, 80, sha_1);
    user_init(from, TEST_IDENTITY, public_p);
    user_init(to, TEST_IDENTITY_2, public_p);
    extract_s(from, secret_p);
    delegation_init(w, public_p);
    delegate(w, from, to, public_p);

    ck_assert(del_verify(w, public_p));
}
END_TEST

START_TEST(test_del_verify_pp)
{
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    sv_user_t from, to;
    delegation_t w;

    setup(public_p, secret_p, 80, sha_1);
    public_params_pp(public_p);
    user_init(from, TEST_IDENTITY, public_p);
    user_init(to, TEST_IDENTITY_2, public_p);
    extract_s(from, secret_p);
    delegation_init(w, public_p);
    delegate(w, from, to, public_p);

    ck_assert(del_verify(w, public_p));
}
END_TEST

START_TEST(test_del_verify_str)
{
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    sv_user_t from, to;
    delegation_t w;

    setup(public_p, secret_p, 80, sha_1);
    user_init_str(from, "TEST_IDENTITY", public_p);
    user_init_str(to, "TEST_IDENTITY", public_p);
    extract_s(from, secret_p);
    delegation_init(w, public_p);
    delegate(w, from, to, public_p);

    ck_assert(del_verify(w, public_p));
}
END_TEST

START_TEST(test_del_verify_fail_from)
{
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    sv_user_t from, to;
    delegation_t w;

    setup(public_p, secret_p, 80, sha_1);
    user_init(from, TEST_IDENTITY, public_p);
    user_init(to, TEST_IDENTITY_2, public_p);
    extract_s(from, secret_p);
    delegation_init(w, public_p);
    delegate(w, from, to, public_p);

    // Wrong identity as the one that delegated
    memcpy(w->m->from, TEST_IDENTITY_2, IDENTITY_SIZE);
    ck_assert(!del_verify(w, public_p));
}
END_TEST

START_TEST(test_del_verify_fail_to)
{
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    sv_user_t from, to;
    delegation_t w;

    setup(public_p, secret_p, 80, sha_1);
    user_init(from, TEST_IDENTITY, public_p);
    user_init(to, TEST_IDENTITY_2, public_p);
    extract_s(from, secret_p);
    delegation_init(w, public_p);
    delegate(w, from, to, public_p);

    // Wrong identity as the one delegated
    memcpy(w->m->to, TEST_IDENTITY, IDENTITY_SIZE);
    ck_assert(!del_verify(w, public_p));
}
END_TEST

#pragma endregion

#pragma region pk_sign

START_TEST(test_pk_sign)
{
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    sv_user_t from, to;
    delegation_t w;
    element_t k_sign;

    setup(public_p, secret_p, 80, sha_1);
    user_init(from, TEST_IDENTITY, public_p);
    user_init(to, TEST_IDENTITY_2, public_p);
    extract_s(from, secret_p);
    extract_s(to, secret_p);
    delegation_init(w, public_p);
    delegate(w, from, to, public_p);

    element_init_G1(k_sign, public_p->pairing);
    element_set0(k_sign);
    pk_gen(k_sign, to, w, public_p);

    ck_assert(!element_is0(k_sign));
}
END_TEST

START_TEST(test_pk_sign_pp)
{
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    sv_user_t from, to;
    delegation_t w;
    element_t k_sign;

    setup(public_p, secret_p, 80, sha_1);
    public_params_pp(public_p);
    user_init(from, TEST_IDENTITY, public_p);
    user_init(to, TEST_IDENTITY_2, public_p);
    extract_s(from, secret_p);
    extract_s(to, secret_p);
    delegation_init(w, public_p);
    delegate(w, from, to, public_p);

    element_init_G1(k_sign, public_p->pairing);
    element_set0(k_sign);
    pk_gen(k_sign, to, w, public_p);

    ck_assert(!element_is0(k_sign));
}
END_TEST

#pragma endregion

Suite *utility_suite()
{
    Suite *s = suite_create("shared");

    TCase *tc_hash = tcase_create("hash");
    tcase_add_loop_test(tc_hash, test_hash, 0, N_HASH_TYPES);

    TCase *tc_hash_element = tcase_create("hash_element");
    tcase_add_loop_test(tc_hash_element, test_hash_element, 0, N_HASH_TYPES);

    TCase *tc_calculate_beta = tcase_create("calculate_beta");
    tcase_add_test(tc_calculate_beta, test_calculate_beta);

    TCase *tc_setup = tcase_create("setup");
    tcase_add_loop_test(tc_setup, test_setup, 0, N_SEC_LEVELS);
    tcase_add_loop_test(tc_setup, test_setup_hash, 0, N_HASH_TYPES);
    tcase_add_loop_test(tc_setup, test_setup_pk, 0, N_SEC_LEVELS);
    tcase_add_loop_test(tc_setup, test_setup_order, 0, N_SEC_LEVELS);
    tcase_add_loop_test(tc_setup, test_setup_pp, 0, N_SEC_LEVELS);
    tcase_add_test(tc_setup, test_setup_str);

    TCase *tc_extract = tcase_create("extract");
    tcase_add_loop_test(tc_extract, test_extract_p, 0, N_SEC_LEVELS);
    tcase_add_loop_test(tc_extract, test_extract_s, 0, N_SEC_LEVELS);
    tcase_add_loop_test(tc_extract, test_extract_relationship, 0, N_SEC_LEVELS);

    TCase *tc_delegate = tcase_create("delegate");
    tcase_add_test(tc_delegate, test_delegate);
    tcase_add_test(tc_delegate, test_delegate_pp);

    TCase *tc_del_verify = tcase_create("del_verify");
    tcase_add_test(tc_del_verify, test_del_verify);
    tcase_add_test(tc_del_verify, test_del_verify_pp);
    tcase_add_test(tc_del_verify, test_del_verify_str);
    tcase_add_test(tc_del_verify, test_del_verify_fail_from);
    tcase_add_test(tc_del_verify, test_del_verify_fail_to);

    TCase *tc_pk_sign = tcase_create("pk_sign");
    tcase_add_test(tc_pk_sign, test_pk_sign);
    tcase_add_test(tc_pk_sign, test_pk_sign_pp);

    suite_add_tcase(s, tc_hash);
    suite_add_tcase(s, tc_hash_element);
    suite_add_tcase(s, tc_calculate_beta);
    suite_add_tcase(s, tc_setup);
    suite_add_tcase(s, tc_extract);
    suite_add_tcase(s, tc_delegate);
    suite_add_tcase(s, tc_del_verify);
    suite_add_tcase(s, tc_pk_sign);

    return s;
}