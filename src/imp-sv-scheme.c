#include "imp-sv-scheme.h"

void imp_p_sign(proxy_signature_t p_sig, element_t k_sign, delegation_t w, const uint8_t msg[], size_t msg_size, sv_public_params_t public_p)
{
    memcpy(p_sig->m, w->m, sizeof(w->m));

    element_t k, r_b, alpha, temp;
    element_init_GT(r_b, public_p->pairing);
    element_init_Zr(k, public_p->pairing);
    element_init_Zr(alpha, public_p->pairing);
    element_init_G1(temp, public_p->pairing);

    element_set(p_sig->r, w->r);

    // Random element
    element_random(k);

    // r_b = e(P, P)^k
    if (public_p->precompute)
    {
        element_pp_pow_zn(r_b, k, public_p->PP_pp);
    }
    else
    {
        element_pairing(r_b, public_p->P, public_p->P);
        element_pow_zn(r_b, r_b, k);
    }

    // beta = F1(msg) || F2(F1(msg)) (+) msg)
    uint8_t beta[public_p->q];
    calculate_beta(beta, msg, msg_size, public_p);

    // alpha = [beta]_10
    element_from_bytes(alpha, beta);

    // V = H(v) + alpha
    uint8_t r_b_digest[MAX_DIGEST_SIZE];
    uint16_t v_digest_size = hash_element(r_b_digest, r_b, public_p->hash_type);
    element_from_hash(p_sig->V, r_b_digest, v_digest_size);
    element_add(p_sig->V, p_sig->V, alpha);

    // U = k * P + V * k_sign
    if (public_p->precompute)
        element_pp_pow_zn(p_sig->U, k, public_p->P_pp);
    else
        element_mul_zn(p_sig->U, public_p->P, k);
    element_mul_zn(temp, k_sign, p_sig->V);
    element_add(p_sig->U, p_sig->U, temp);

    element_clear(k);
    element_clear(r_b);
    element_clear(alpha);
    element_clear(temp);
}

uint16_t imp_sign_verify(uint8_t msg[], proxy_signature_t p_sig, sv_public_params_t public_p)
{
    element_t h, alpha, p_sum, p_1, p_2, V;
    element_init_Zr(h, public_p->pairing);
    element_init_Zr(alpha, public_p->pairing);
    element_init_G1(p_sum, public_p->pairing);
    element_init_GT(p_1, public_p->pairing);
    element_init_GT(p_2, public_p->pairing);
    element_init_Zr(V, public_p->pairing);

    sv_user_t from, to;
    user_init(from, p_sig->m->from, public_p);
    user_init(to, p_sig->m->to, public_p);
    extract_p(from, public_p);
    extract_p(to, public_p);

    hash_warrant_and_r(h, p_sig->r, p_sig->m, public_p->hash_type);

    // alpha = V - H(e(U, P) * e(qa + qb, Pub)^-Vh * r^-V)
    // p_1 = e(U, P)
    if (public_p->precompute)
        pairing_pp_apply(p_1, p_sig->U, public_p->eP_pp);
    else
        element_pairing(p_1, p_sig->U, public_p->P);
    // p_2 = e(pk_a + pk_b, Pub)^-Vh
    element_add(p_sum, from->pk, to->pk);
    if (public_p->precompute)
        pairing_pp_apply(p_2, p_sum, public_p->epk_pp);
    else
        element_pairing(p_2, p_sum, public_p->pk);
    element_neg(V, p_sig->V);
    element_mul(h, V, h);
    element_pow_zn(p_2, p_2, h);
    // p_1 = p_1 * p_2
    element_mul(p_1, p_1, p_2);
    // p_1 = p_1 * r^-V
    element_pow_zn(p_2, p_sig->r, V);
    element_mul(p_1, p_1, p_2);

    uint8_t p_1_digest[MAX_DIGEST_SIZE];
    uint16_t p_1_digest_size = hash_element(p_1_digest, p_1, public_p->hash_type);
    element_from_hash(alpha, p_1_digest, p_1_digest_size);
    element_sub(alpha, p_sig->V, alpha);

    // beta = [a]_2
    int alpha_size = element_length_in_bytes(alpha);
    uint8_t beta[alpha_size];
    element_to_bytes(beta, alpha);

    // msg = F2(l1|beta|) (+) |beta|l2
    uint8_t beta_digest[MAX_DIGEST_SIZE];
    hash(beta_digest, beta, public_p->l1, public_p->hash_type);
    for (int i = 0; i < public_p->l2; i++)
        msg[i] = beta_digest[i] ^ beta[i + public_p->l1];

    uint8_t msg_digest[MAX_DIGEST_SIZE];
    hash(msg_digest, msg, public_p->l2, public_p->hash_type);
    // Make sure msg_digest is in Zr
    msg_digest[0] = 0;
    int res = memcmp(msg_digest, beta, public_p->l1);

    user_clear(from);
    user_clear(to);
    element_clear(h);
    element_clear(alpha);
    element_clear(p_1);
    element_clear(p_2);
    element_clear(p_sum);
    element_clear(V);

    return res == 0;
}
