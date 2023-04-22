#include "test-data.h"

#pragma region fixture

static sv_public_params_t public_p;
static sv_secret_params_t secret_p;
static delegation_t w;
static warrant_t m;
static element_t sk_a, sk_b, k_sign;
static proxy_signature_t p_sig;

static void data_setup_fixture()
{
    memcpy(m->from, TEST_IDENTITY, IDENTITY_SIZE);
    memcpy(m->to, TEST_IDENTITY_2, IDENTITY_SIZE);

    int sec_lvl = sec_levels[0];
    hash_type_t hash_type = hash_types[0];

    setup(public_p, secret_p, sec_lvl, hash_type);
    element_init_G1(sk_a, public_p->pairing);
    element_init_G1(sk_b, public_p->pairing);
    extract_s(sk_a, TEST_IDENTITY, secret_p);
    extract_s(sk_b, TEST_IDENTITY_2, secret_p);
    delegation_init(w, public_p);
    delegate(w, sk_a, m, public_p);
    pk_gen(k_sign, sk_b, w, public_p);
    proxy_signature_init(p_sig, public_p);
    p_sign(p_sig, k_sign, w, (uint8_t *)TEST_MESSAGE, strlen(TEST_MESSAGE), public_p);
}

static void data_teardown_fixture()
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

#pragma region serialize_warrant

START_TEST(test_serialize_warrant)
{
    serialized_warrant_t warrant_buffer;
    warrant_t m;

    for (size_t i = 0; i < IDENTITY_SIZE; i++)
    {
        m->from[i] = i;
        m->to[i] = i + IDENTITY_SIZE;
    }

    uint16_t size = serialize_warrant(warrant_buffer, m);

    ck_assert_int_eq(size, WARRANT_SIZE);
    ck_assert_mem_eq(warrant_buffer, m->from, IDENTITY_SIZE);
    ck_assert_mem_eq(warrant_buffer + IDENTITY_SIZE, m->to, IDENTITY_SIZE);
}
END_TEST

START_TEST(test_deserialize_warrant)
{
    serialized_warrant_t warrant_buffer;
    warrant_t m;

    for (size_t i = 0; i < WARRANT_SIZE; i++)
    {
        warrant_buffer[i] = i;
    }

    uint16_t size = deserialize_warrant(m, warrant_buffer);

    ck_assert_int_eq(size, WARRANT_SIZE);
    for (size_t i = 0; i < IDENTITY_SIZE; i++)
    {
        ck_assert_int_eq(m->from[i], i);
        ck_assert_int_eq(m->to[i], i + IDENTITY_SIZE);
    }
}
END_TEST

#pragma endregion

#pragma region serialize_delegation

START_TEST(test_serialize_delegation)
{
    uint8_t *data;

    serialize_delegation(&data, w);
    warrant_t m2;
    delegation_t w2;
    w2->m = m2;
    delegation_init(w2, public_p);
    deserialize_delegation(w2, data);
    ck_assert_int_eq(element_cmp(w->r, w2->r), 0);
    ck_assert_int_eq(element_cmp(w->S, w2->S), 0);
    ck_assert_mem_eq(w->m->from, w2->m->from, IDENTITY_SIZE);
    ck_assert_mem_eq(w->m->to, w2->m->to, IDENTITY_SIZE);

    delegation_clear(w2);
    free(data);
}
END_TEST

#pragma endregion

#pragma region serialize_proxy_signature

START_TEST(test_serialize_proxy_signature)
{
    uint8_t *data;

    serialize_proxy_signature(&data, p_sig);
    warrant_t m2;
    proxy_signature_t p_sig2;
    p_sig2->m = m2;
    proxy_signature_init(p_sig2, public_p);
    deserialize_proxy_signature(p_sig2, data);
    ck_assert_int_eq(element_cmp(p_sig->r, p_sig2->r), 0);
    ck_assert_int_eq(element_cmp(p_sig->U, p_sig2->U), 0);
    ck_assert_int_eq(element_cmp(p_sig->V, p_sig2->V), 0);
    ck_assert_mem_eq(p_sig->m->from, p_sig2->m->from, IDENTITY_SIZE);
    ck_assert_mem_eq(p_sig->m->to, p_sig2->m->to, IDENTITY_SIZE);

    proxy_signature_clear(p_sig2);
    free(data);
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
    delegation_init(w, public_p);
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
    delegation_init(w, public_p);
    delegate(w, sk, m, public_p);

    delegation_clear(w);
    delegation_clear(w);
    ck_assert(1);
}
END_TEST

#pragma endregion

Suite *data_suite()
{
    Suite *s = suite_create("data");

    TCase *tc_serialize_warrant = tcase_create("serialize_warrant");
    tcase_add_test(tc_serialize_warrant, test_serialize_warrant);
    tcase_add_test(tc_serialize_warrant, test_deserialize_warrant);

    TCase *tc_serialize_delegation = tcase_create("serialize_delegation");
    tcase_add_checked_fixture(tc_serialize_delegation, data_setup_fixture, data_teardown_fixture);
    tcase_add_test(tc_serialize_delegation, test_serialize_delegation);

    TCase *tc_serialize_proxy_signature = tcase_create("serialize_proxy_signature");
    tcase_add_checked_fixture(tc_serialize_proxy_signature, data_setup_fixture, data_teardown_fixture);
    tcase_add_test(tc_serialize_proxy_signature, test_serialize_proxy_signature);

    TCase *tc_clear = tcase_create("clear");
    tcase_add_test(tc_clear, test_public_params_clear);
    tcase_add_test_raise_signal(tc_clear, test_public_params_already_cleared, SIGSEGV);
    tcase_add_test_raise_signal(tc_clear, test_public_params_not_init, SIGSEGV);
    tcase_add_test(tc_clear, test_secret_params_clear);
    tcase_add_test(tc_clear, test_secret_params_already_cleared); // Elements can be cleared more than once
    tcase_add_test_raise_signal(tc_clear, test_secret_params_not_init, SIGSEGV);
    tcase_add_test(tc_clear, test_delegation_clear);
    tcase_add_test_raise_signal(tc_clear, test_delegation_already_cleared, SIGSEGV);

    suite_add_tcase(s, tc_serialize_warrant);
    suite_add_tcase(s, tc_serialize_delegation);
    suite_add_tcase(s, tc_serialize_proxy_signature);
    suite_add_tcase(s, tc_clear);

    return s;
}