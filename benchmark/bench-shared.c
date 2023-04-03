#include "bench-shared.h"

static uint8_t BENCH_IDENTITY[32] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};

static void bench_setup(bench_param_t bench_p)
{
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;

    perform_wc_time_sampling_period(
        bench_p->bench_stats, bench_p->max_sampling_time, bench_p->max_samples, tu_millis,
        { setup(public_p, secret_p, bench_p->sec_lvl, bench_p->hash_type); },
        {});

    printf_short_stats("\tsetup", bench_p->bench_stats, "");
    printf_stats("\tsetup", bench_p->bench_stats, "");
    printf(SEPARATOR);

    public_param_clear(public_p);
    secret_param_clear(secret_p);
}

static void bench_extract_p(bench_param_t bench_p)
{
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    element_t pk;

    setup(public_p, secret_p, bench_p->sec_lvl, bench_p->hash_type);
    perform_wc_time_sampling_period(
        bench_p->bench_stats, bench_p->max_sampling_time, bench_p->max_samples, tu_millis,
        { extract_p(pk, BENCH_IDENTITY, public_p); },
        {});

    printf_short_stats("\textract_p", bench_p->bench_stats, "");
    printf_stats("\textract_p", bench_p->bench_stats, "");
    printf(SEPARATOR);

    element_clear(pk);
    secret_param_clear(secret_p);
    public_param_clear(public_p);
}

static void bench_extract_s(bench_param_t bench_p)
{
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    element_t sk;

    setup(public_p, secret_p, bench_p->sec_lvl, bench_p->hash_type);
    perform_wc_time_sampling_period(
        bench_p->bench_stats, bench_p->max_sampling_time, bench_p->max_samples, tu_millis,
        { extract_s(sk, BENCH_IDENTITY, secret_p); },
        {});

    printf_short_stats("\textract_s", bench_p->bench_stats, "");
    printf_stats("\textract_s", bench_p->bench_stats, "");
    printf(SEPARATOR);

    element_clear(sk);
    secret_param_clear(secret_p);
    public_param_clear(public_p);
}

static void bench_delegate(bench_param_t bench_p)
{
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    element_t sk;
    warrant_t m;
    delegation_t w;

    setup(public_p, secret_p, bench_p->sec_lvl, bench_p->hash_type);
    extract_s(sk, BENCH_IDENTITY, secret_p);
    memcpy(m->from, BENCH_IDENTITY, IDENTITY_SIZE);
    memcpy(m->to, BENCH_IDENTITY, IDENTITY_SIZE);
    perform_wc_time_sampling_period(
        bench_p->bench_stats, bench_p->max_sampling_time, bench_p->max_samples, tu_millis,
        { delegate(w, sk, m, public_p); },
        {});

    printf_short_stats("\tdelegate", bench_p->bench_stats, "");
    printf_stats("\tdelegate", bench_p->bench_stats, "");
    printf(SEPARATOR);

    element_clear(sk);
    delegation_clear(w);
    secret_param_clear(secret_p);
    public_param_clear(public_p);
}

static void bench_pk_gen(bench_param_t bench_p)
{
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    warrant_t m;
    element_t sk, k_sign;
    delegation_t w;

    memcpy(m->from, BENCH_IDENTITY, IDENTITY_SIZE);
    memcpy(m->to, BENCH_IDENTITY, IDENTITY_SIZE);

    setup(public_p, secret_p, bench_p->sec_lvl, bench_p->hash_type);
    extract_s(sk, BENCH_IDENTITY, secret_p);
    delegate(w, sk, m, public_p);
    perform_wc_time_sampling_period(
        bench_p->bench_stats, bench_p->max_sampling_time, bench_p->max_samples, tu_millis,
        { pk_gen(k_sign, sk, w, public_p); },
        {});

    printf_short_stats("\tpk_gen", bench_p->bench_stats, "");
    printf_stats("\tpk_gen", bench_p->bench_stats, "");
    printf(SEPARATOR);

    element_clear(sk);
    element_clear(k_sign);
    secret_param_clear(secret_p);
    public_param_clear(public_p);
}

static void bench_del_verify(bench_param_t bench_p)
{
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    element_t sk;
    warrant_t m;
    delegation_t w;

    setup(public_p, secret_p, bench_p->sec_lvl, bench_p->hash_type);
    extract_s(sk, BENCH_IDENTITY, secret_p);
    memcpy(m->from, BENCH_IDENTITY, IDENTITY_SIZE);
    memcpy(m->to, BENCH_IDENTITY, IDENTITY_SIZE);
    delegate(w, sk, m, public_p);
    perform_wc_time_sampling_period(
        bench_p->bench_stats, bench_p->max_sampling_time, bench_p->max_samples, tu_millis,
        { del_verify(w, BENCH_IDENTITY, public_p); },
        {});

    printf_short_stats("\tdel_verify", bench_p->bench_stats, "");
    printf_stats("\tdel_verify", bench_p->bench_stats, "");
    printf(SEPARATOR);

    element_clear(sk);
    delegation_clear(w);
    secret_param_clear(secret_p);
    public_param_clear(public_p);
}

void bench_shared(bench_param_t bench_p)
{
    printf("Benchmarks for the shared parts of the SV scheme...\n");
    bench_setup(bench_p);
    bench_extract_p(bench_p);
    bench_extract_s(bench_p);
    bench_delegate(bench_p);
    bench_del_verify(bench_p);
    bench_pk_gen(bench_p);
}
