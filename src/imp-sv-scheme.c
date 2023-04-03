#include "imp-sv-scheme.h"

void imp_p_sign(proxy_signature_t p_sig, element_t k_sign, delegation_t w, const uint8_t msg[], size_t msg_size, sv_public_params_t public_p)
{
    p_sig->m = w->m;

    element_t k, r_b, alpha, temp;
    element_init_GT(r_b, public_p->pairing);
    element_init_Zr(k, public_p->pairing);
    element_init_Zr(alpha, public_p->pairing);
    element_init_G1(temp, public_p->pairing);
    element_init_Zr(p_sig->V, public_p->pairing);
    element_init_G1(p_sig->U, public_p->pairing);
    element_init_GT(p_sig->r, public_p->pairing);

    element_set(p_sig->r, w->r);

    // Random element
    element_random(k);

    // r_b = e(P, P)^k
    element_pairing(r_b, public_p->P, public_p->P);
    element_pow_zn(r_b, r_b, k);

    // beta = F1(msg) || F2(F1(msg)) (+) msg)
    uint8_t beta[public_p->q];
    calculate_beta(beta, msg, msg_size, public_p);

    // alpha = [beta]_10
    element_from_bytes(alpha, beta);

    // V = H(v) + alpha
    uint8_t r_b_digest[MAX_DIGEST_SIZE];
    unsigned short v_digest_size = hash_element(r_b_digest, r_b, public_p->hash_type);
    element_from_hash(p_sig->V, r_b_digest, v_digest_size);
    element_add(p_sig->V, p_sig->V, alpha);

    // U = k * P + V * k_sign
    element_mul_zn(p_sig->U, public_p->P, k);
    element_mul_zn(temp, k_sign, p_sig->V);
    element_add(p_sig->U, p_sig->U, temp);

    element_clear(k);
    element_clear(r_b);
    element_clear(alpha);
    element_clear(temp);
}

unsigned short imp_sign_verify(proxy_signature_t p_sig, sv_public_params_t public_p)
{
    element_t h, alpha, pk_a, pk_b, p_sum, p_1, p_2;
    element_init_Zr(h, public_p->pairing);
    element_init_Zr(alpha, public_p->pairing);
    element_init_G1(p_sum, public_p->pairing);
    element_init_GT(p_1, public_p->pairing);
    element_init_GT(p_2, public_p->pairing);

    extract_p(pk_a, p_sig->m->from, public_p);
    extract_p(pk_b, p_sig->m->to, public_p);

    hash_warrant_and_r(h, p_sig->r, p_sig->m, public_p->hash_type);

    // alpha = V - H(e(U, P) * e(qa + qb, Pub)^-h)
    // p_1 = e(U, P)
    element_pairing(p_1, p_sig->U, public_p->P);
    // p_2 = e(pk_a + pk_b, Pub)^-Vh
    element_add(p_sum, pk_a, pk_b);
    element_pairing(p_2, p_sum, public_p->pk);
    element_neg(p_sig->V, p_sig->V);
    element_mul(h, p_sig->V, h);
    element_pow_zn(p_2, p_2, h);
    // p_1 = p_1 * p_2
    element_mul(p_1, p_1, p_2);
    // p_1 = p_1 * r^-V
    element_pow_zn(p_1, p_1, p_sig->V);

    uint8_t p_1_digest[MAX_DIGEST_SIZE];
    unsigned short p_1_digest_size = hash_element(p_1_digest, p_1, public_p->hash_type);
    element_from_hash(alpha, p_1_digest, p_1_digest_size);
    element_sub(alpha, p_sig->V, alpha);

    // beta = [a]_2
    int alpha_size = element_length_in_bytes(alpha);
    uint8_t beta[alpha_size];
    element_to_bytes(beta, alpha);

    printf("Beta: ");
    for (int i = 0; i < alpha_size; i++)
        printf("%02x ", beta[i]);
    printf("\n");

    // msg = F2(l1|beta|) (+) |beta|l2
    uint8_t beta_digest[MAX_DIGEST_SIZE], msg[public_p->l2];
    hash(beta_digest, beta, public_p->l1, public_p->hash_type);
    for (int i = 0; i < public_p->l2; i++)
        msg[i] = beta_digest[i] ^ beta[i + public_p->l1];

    printf("Message: ");
    for (int i = 0; i < public_p->l2; i++)
        printf("%02x ", msg[i]);
    printf("\n");

    printf("Message: ");
    for (int i = 0; i < public_p->l2; i++)
        printf("%c ", msg[i]);
    printf("\n");

    uint8_t msg_digest[MAX_DIGEST_SIZE];
    hash(msg_digest, msg, public_p->l2, public_p->hash_type);
    int res = memcmp(msg_digest, beta, public_p->l1);

    element_clear(h);
    element_clear(alpha);
    element_clear(pk_a);
    element_clear(pk_b);
    element_clear(p_1);
    element_clear(p_2);

    return res == 0;
}