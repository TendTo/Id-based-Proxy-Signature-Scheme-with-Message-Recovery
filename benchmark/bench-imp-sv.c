#include "bench-imp-sv.h"

static uint8_t BENCH_IDENTITY[32] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};

static void bench_imp_p_sign(bench_param_t bench_p)
{
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    element_t sk, k_sign;
    warrant_t m;
    delegation_t w;
    proxy_signature_t p_sig;

    setup(public_p, secret_p, bench_p->sec_lvl, bench_p->hash_type);
    extract_s(sk, BENCH_IDENTITY, secret_p);
    memcpy(m->from, BENCH_IDENTITY, IDENTITY_SIZE);
    memcpy(m->to, BENCH_IDENTITY, IDENTITY_SIZE);
    delegate(w, sk, m, public_p);
    pk_gen(k_sign, sk, w, public_p);

    perform_wc_time_sampling_period(
        bench_p->bench_stats, bench_p->max_sampling_time, bench_p->max_samples, tu_millis,
        { imp_p_sign(p_sig, k_sign, w, BENCH_IDENTITY, 32, public_p); },
        {});

    printf_short_stats("\tp_sign", bench_p->bench_stats, "");
    printf_stats("\tp_sign", bench_p->bench_stats, "");
    printf(SEPARATOR);

    element_clear(sk);
    element_clear(k_sign);
    proxy_signature_clear(p_sig);
    delegation_clear(w);
    secret_param_clear(secret_p);
    public_param_clear(public_p);
}

static void bench_imp_sign_verify(bench_param_t bench_p)
{
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    element_t sk, k_sign;
    warrant_t m;
    delegation_t w;
    proxy_signature_t p_sig;

    setup(public_p, secret_p, bench_p->sec_lvl, bench_p->hash_type);
    extract_s(sk, BENCH_IDENTITY, secret_p);
    memcpy(m->from, BENCH_IDENTITY, IDENTITY_SIZE);
    memcpy(m->to, BENCH_IDENTITY, IDENTITY_SIZE);
    delegate(w, sk, m, public_p);
    pk_gen(k_sign, sk, w, public_p);
    imp_p_sign(p_sig, k_sign, w, BENCH_IDENTITY, 32, public_p);

    perform_wc_time_sampling_period(
        bench_p->bench_stats, bench_p->max_sampling_time, bench_p->max_samples, tu_millis,
        { imp_sign_verify(p_sig, public_p); },
        {});

    printf_short_stats("\tsign_verify", bench_p->bench_stats, "");
    printf_stats("\tsign_verify", bench_p->bench_stats, "");
    printf(SEPARATOR);

    element_clear(sk);
    element_clear(k_sign);
    proxy_signature_clear(p_sig);
    delegation_clear(w);
    secret_param_clear(secret_p);
    public_param_clear(public_p);
}

void bench_imp_sv(bench_param_t bench_p)
{
    printf("Benchmarks for the improved SV implementation...\n");
    bench_imp_p_sign(bench_p);
    bench_imp_sign_verify(bench_p);
}