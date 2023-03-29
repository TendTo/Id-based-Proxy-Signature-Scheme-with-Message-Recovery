#include "sv-scheme.h"

// #define SHA1_DIGEST_SIZE 20

void setup(sv_public_params_t public_p, sv_secret_params_t secret_p, int lambda)
{
    pbc_param_t pairing_p;
    select_pbc_param_by_security_level(pairing_p, pbc_pairing_type_a, lambda, NULL);
    pairing_init_pbc_param(public_p->pairing, pairing_p);
    pbc_param_clear(pairing_p);

    // secret params init
    element_init_Zr(secret_p->sk, public_p->pairing);

    // secret params setup
    element_random(secret_p->sk);
    secret_p->public_params = public_p;

    // public params init
    element_init_G1(public_p->P, public_p->pairing);
    element_init_G1(public_p->pk, public_p->pairing);

    // public params setup
    element_random(public_p->P);
    element_mul_zn(public_p->pk, public_p->P, secret_p->sk);
    public_p->q = pairing_length_in_bytes_x_only_G1(public_p->pairing) * 8;
    public_p->l1 = public_p->q / 2;
    public_p->l2 = public_p->q - public_p->l1;
}

void extract_p(element_t pk_id, sv_public_params_t public_p, const void *identity, int len)
{
    // Hashing
    struct sha1_ctx h;
    uint8_t digest[SHA1_DIGEST_SIZE];
    sha1_init(&h);
    sha1_update(&h, len, identity);
    sha1_digest(&h, SHA1_DIGEST_SIZE, digest);

    // Generating pk for the user
    element_init_G1(pk_id, public_p->pairing);
    element_from_hash(pk_id, digest, SHA1_DIGEST_SIZE);
}

void extract_s(element_t sk_id, sv_secret_params_t secret_p, const void *identity, int len)
{
    // Hashing
    struct sha1_ctx h;
    void *digest = NULL;
    sha1_init(&h);
    sha1_update(&h, len, identity);
    sha1_digest(&h, SHA1_DIGEST_SIZE, digest);

    // Generating sk for the user
    element_init_G1(sk_id, secret_p->public_params->pairing);
    element_from_hash(sk_id, digest, SHA1_DIGEST_SIZE);
    element_mul_zn(sk_id, secret_p->public_params->P, secret_p->sk);
}

void public_param_clear(sv_public_params_t public_p)
{
    element_clear(public_p->P);
    element_clear(public_p->pk);
    pairing_clear(public_p->pairing);
}

void secret_param_clear(sv_secret_params_t secret_p)
{
    element_clear(secret_p->sk);
}