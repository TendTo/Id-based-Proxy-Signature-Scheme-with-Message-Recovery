#include "sv-scheme.h"

unsigned short serialize_warrant(uint8_t buffer[WARRANT_SIZE], const warrant_t m)
{
    memcpy(buffer, m->from, IDENTITY_SIZE);
    memcpy(buffer + IDENTITY_SIZE, m->to, IDENTITY_SIZE);
    return WARRANT_SIZE;
}

unsigned short deserialize_warrant(warrant_t m, const uint8_t buffer[WARRANT_SIZE])
{
    memcpy(m->from, buffer, IDENTITY_SIZE);
    memcpy(m->to, buffer + IDENTITY_SIZE, IDENTITY_SIZE);
    return WARRANT_SIZE;
}

void hash_warrant_and_r(element_t h, delegation_t w, warrant_t m, hash_type_t hash_type)
{
    int size = element_length_in_bytes(w->r);
    uint8_t digest[MAX_DIGEST_SIZE];
    uint8_t h_buffer[WARRANT_SIZE + size];
    element_to_bytes(h_buffer + WARRANT_SIZE, w->r);
    serialize_warrant(h_buffer, m);
    unsigned short digest_size = hash(digest, h_buffer, WARRANT_SIZE + size, hash_type);
    element_from_hash(h, digest, digest_size);
}

void setup(sv_public_params_t public_p, sv_secret_params_t secret_p, int lambda, hash_type_t hash_type)
{
    pbc_param_t pairing_p;
    select_pbc_param_by_security_level(pairing_p, pbc_pairing_type_a, lambda, NULL);
    pairing_init_pbc_param(public_p->pairing, pairing_p);
    pbc_param_clear(pairing_p);

    // secret params init
    element_init_Zr(secret_p->msk, public_p->pairing);

    // secret params setup
    element_random(secret_p->msk);
    secret_p->public_params = public_p;

    // public params init
    element_init_G1(public_p->P, public_p->pairing);
    element_init_G1(public_p->pk, public_p->pairing);

    // public params setup
    element_random(public_p->P);
    element_mul_zn(public_p->pk, public_p->P, secret_p->msk);
    public_p->q = pairing_length_in_bytes_x_only_G1(public_p->pairing) * 8;
    public_p->l1 = public_p->q / 2;
    public_p->l2 = public_p->q - public_p->l1;
    public_p->hash_type = hash_type;
}

void extract_p(element_t pk_id, sv_public_params_t public_p, const sv_identity_t identity)
{
    // Hashing
    uint8_t digest[MAX_DIGEST_SIZE];
    unsigned short digest_len = hash(digest, identity, IDENTITY_SIZE, public_p->hash_type);

    // Generating pk for the user
    element_init_G1(pk_id, public_p->pairing);
    element_from_hash(pk_id, digest, digest_len);
}

void extract_s(element_t sk_id, sv_secret_params_t secret_p, const sv_identity_t identity)
{
    // Hashing
    uint8_t digest[MAX_DIGEST_SIZE];
    unsigned short digest_len = hash(digest, identity, IDENTITY_SIZE, secret_p->public_params->hash_type);

    // Generating sk for the user
    element_init_G1(sk_id, secret_p->public_params->pairing);
    element_from_hash(sk_id, digest, digest_len);
    element_mul_zn(sk_id, sk_id, secret_p->msk);
}

void delegate(delegation_t w, element_t sk, warrant_t m, sv_public_params_t public_p)
{
    w->m = m;

    element_t k, h, temp;
    element_init_Zr(k, public_p->pairing);
    element_init_Zr(h, public_p->pairing);
    element_init_GT(w->r, public_p->pairing);
    element_init_G1(w->S, public_p->pairing);
    element_init_G1(temp, public_p->pairing);

    // k <- Zr (random in Zr)
    element_random(k);

    // r = e(P, P)^k (in GT)
    element_pairing(w->r, public_p->P, public_p->P);
    element_pow_zn(w->r, w->r, k);

    // h = H(m, ra) (in Zr)
    hash_warrant_and_r(h, w, m, public_p->hash_type);

    // S = h * sk + k * P (in G1)
    element_mul_zn(w->S, sk, h);
    element_mul_zn(temp, public_p->P, k);
    element_add(w->S, w->S, temp);

    element_clear(k);
    element_clear(h);
    element_clear(temp);
}

int del_verify(delegation_t w, sv_identity_t identity, sv_public_params_t public_p)
{
    element_t h, pk, left_el, right_el;
    element_init_Zr(h, public_p->pairing);
    element_init_G1(pk, public_p->pairing);
    element_init_GT(left_el, public_p->pairing);
    element_init_GT(right_el, public_p->pairing);

    hash_warrant_and_r(h, w, w->m, public_p->hash_type);

    extract_p(pk, public_p, identity);

    // e(S, P) = e(Pub, pk)^h * r
    element_pairing(left_el, w->S, public_p->P);

    element_pairing(right_el, pk, public_p->pk);
    element_pow_zn(right_el, right_el, h);
    element_mul(right_el, right_el, w->r);

    int res = element_cmp(left_el, right_el);

    element_clear(h);
    element_clear(pk);
    element_clear(left_el);
    element_clear(right_el);

    return res == 0;
}

void pk_gen(element_t k_sign, element_t sk, delegation_t w, sv_public_params_t public_p)
{
    element_t h;
    element_init_Zr(h, public_p->pairing);
    element_init_G1(k_sign, public_p->pairing);

    hash_warrant_and_r(h, w, w->m, public_p->hash_type);

    element_mul_zn(k_sign, sk, h);
    element_add(k_sign, k_sign, w->S);
}

void sign(proxy_signature_t p_sig, element_t k_sign, delegation_t w, const uint8_t msg[], sv_public_params_t public_p)
{
    element_t k, r_b, v, alpha;
    element_init_GT(r_b, public_p->pairing);
    element_init_Zr(k, public_p->pairing);
    element_init_G1(v, public_p->pairing);
    element_init_Zr(alpha, public_p->pairing);
    element_init_Zr(p_sig->V, public_p->pairing);
    element_init_G1(p_sig->U, public_p->pairing);

    // Random element
    element_random(k);

    // r_b = e(P, P)^k
    element_pairing(r_b, public_p->P, public_p->P);
    element_pow_zn(r_b, r_b, k);

    // v = r * r_b
    element_mul(v, r_b, w->r);

    // beta = F1(msg) || F2(F1(msg)) (+) msg)
    uint8_t beta[public_p->l1 + public_p->l2];
    calculate_beta(beta, msg, public_p);

    // alpha = [beta]_10
    element_from_bytes(alpha, beta);

    // V = H(v) + alpha
    int v_size = element_length_in_bytes(v);
    uint8_t v_buffer[v_size], v_digest[MAX_DIGEST_SIZE];
    element_to_bytes(v_buffer, v);
    unsigned short v_digest_size = hash(v_digest, v_buffer, v_size, public_p->hash_type);
    element_from_hash(p_sig->V, v_digest, v_digest_size);
    element_add(p_sig->V, p_sig->V, alpha);

    // U = k * P + k_sign
    element_mul_zn(p_sig->U, public_p->P, k);
    element_add(p_sig->U, p_sig->U, k_sign);
}

void calculate_beta(uint8_t beta[], const uint8_t msg[], sv_public_params_t public_p)
{
    // beta_lefet = F1(msg)
    uint8_t beta_left[MAX_DIGEST_SIZE];
    // beta_right = F2(F1(msg)) (+) msg)
    hash(beta_left, msg, public_p->l2, public_p->hash_type);
    uint8_t beta_right[MAX_DIGEST_SIZE];
    hash(beta_right, msg, public_p->l2, public_p->hash_type);
    hash(beta_right, beta_right, public_p->l1, public_p->hash_type);
    for (int i = 0; i < public_p->l2; i++)
        beta_right[i] = beta_right[i] ^ msg[i];
    // beta = beta_left || beta_right
    memcpy(beta, beta_left, public_p->l1);
    memcpy(beta + public_p->l1, beta_right, public_p->l2);
}

void public_param_clear(sv_public_params_t public_p)
{
    element_clear(public_p->P);
    element_clear(public_p->pk);
    pairing_clear(public_p->pairing);
}

void secret_param_clear(sv_secret_params_t secret_p)
{
    element_clear(secret_p->msk);
}