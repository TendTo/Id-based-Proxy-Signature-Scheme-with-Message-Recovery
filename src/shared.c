#include "shared.h"

unsigned int non_generic_dlog_secure_size_by_security_level(unsigned int level)
{
    /* NIST (2020) */
    if (level <= 80)
        return 1024;
    else if (level <= 112)
        return 2048;
    else if (level <= 128)
        return 3072;
    else if (level <= 192)
        return 7680;
    else
        return 15360;
}

uint16_t hash(uint8_t digest[MAX_DIGEST_SIZE], const void *data, size_t len, hash_type_t hash_type)
{
    switch (hash_type)
    {
    case sha_1:
        struct sha1_ctx h;
        sha1_init(&h);
        sha1_update(&h, len, data);
        sha1_digest(&h, SHA1_DIGEST_SIZE, digest);
        return SHA1_DIGEST_SIZE;
    case sha_256:
        struct sha256_ctx h256;
        sha256_init(&h256);
        sha256_update(&h256, len, data);
        sha256_digest(&h256, SHA256_DIGEST_SIZE, digest);
        return SHA256_DIGEST_SIZE;
    case sha_512:
        struct sha512_ctx h512;
        sha512_init(&h512);
        sha512_update(&h512, len, data);
        sha512_digest(&h512, SHA512_DIGEST_SIZE, digest);
        return SHA512_DIGEST_SIZE;
    default:
        return -1;
    }
}

uint16_t hash_element(uint8_t digest[MAX_DIGEST_SIZE], element_t e, hash_type_t hash_type)
{
    int len = element_length_in_bytes(e);
    uint8_t element_buffer[len];
    element_to_bytes(element_buffer, e);
    return hash(digest, element_buffer, len, hash_type);
}

void hash_warrant_and_r(element_t h, element_t r, warrant_t m, hash_type_t hash_type)
{
    int size = element_length_in_bytes(r);
    uint8_t digest[MAX_DIGEST_SIZE];
    uint8_t h_buffer[WARRANT_SIZE + size];
    element_to_bytes(h_buffer + WARRANT_SIZE, r);
    serialize_warrant(h_buffer, m);
    uint16_t digest_size = hash(digest, h_buffer, WARRANT_SIZE + size, hash_type);
    element_from_hash(h, digest, digest_size);
}

void calculate_beta(uint8_t beta[], const uint8_t raw_msg[], size_t msg_size, sv_public_params_t public_p)
{
    element_t temp;
    element_init_Zr(temp, public_p->pairing);

    // make sure the msg length is l2 and the last bytes are 0
    uint8_t msg[public_p->l2];
    if (msg_size > (size_t)public_p->l2)
        msg_size = public_p->l2;
    else
        memset(msg, 0, public_p->l2);
    memcpy(msg, raw_msg, msg_size);

    // beta_left = F1(msg)
    uint8_t beta_left[MAX_DIGEST_SIZE];
    hash(beta_left, msg, public_p->l2, public_p->hash_type);
    // Make sure beta_left is in Zr
    beta_left[0] = 0;

    // beta_right = F2(F1(msg)) (+) msg
    uint8_t beta_right[MAX_DIGEST_SIZE];
    hash(beta_right, beta_left, public_p->l1, public_p->hash_type);
    for (int i = 0; i < public_p->l2; i++)
        beta_right[i] = beta_right[i] ^ msg[i];

    // beta = beta_left || beta_right
    memcpy(beta, beta_left, public_p->l1);
    memcpy(beta + public_p->l1, beta_right, public_p->l2);
    element_clear(temp);
}

void params_init(pbc_param_t pairings_p, int lambda)
{
    pbc_param_init_a_gen(pairings_p, generic_dlog_secure_size_by_security_level(lambda), non_generic_dlog_secure_size_by_security_level(lambda) / 2);
}

void setup(sv_public_params_t public_p, sv_secret_params_t secret_p, int lambda, hash_type_t hash_type)
{
    pbc_param_t pairing_p;
    pbc_param_init_a_gen(pairing_p, generic_dlog_secure_size_by_security_level(lambda), non_generic_dlog_secure_size_by_security_level(lambda) / 2);
    setup_from_params(public_p, secret_p, hash_type, pairing_p);
    pbc_param_clear(pairing_p);
}

void setup_from_params(sv_public_params_t public_p, sv_secret_params_t secret_p, hash_type_t hash_type, pbc_param_t pairing_p)
{
    pairing_init_pbc_param(public_p->pairing, pairing_p);

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
    public_p->q = pairing_length_in_bytes_Zr(public_p->pairing);
    public_p->l1 = public_p->q / 2;
    public_p->l2 = public_p->q - public_p->l1;
    public_p->hash_type = hash_type;
}

void setup_from_str(sv_public_params_t public_p, sv_secret_params_t secret_p, char pairing_p_str[])
{
    pbc_param_t pairing_p;
    hash_type_t hash_type;
    pbc_param_init_set_str(pairing_p, pairing_p_str);
    pairing_init_pbc_param(public_p->pairing, pairing_p);

    char *pos, *new_line;
    pos = strstr(pairing_p_str, "hash_type ");
    new_line = strchr(pos, '\n');
    if (new_line)
        *new_line = '\0';
    hash_type = atoi(pos + 10);
    if (new_line)
        *new_line = '\n';
    pos = strstr(pairing_p_str, "P ");
    new_line = strchr(pos, '\n');
    if (new_line)
        *new_line = '\0';
    element_init_G1(public_p->P, public_p->pairing);
    element_set_str(public_p->P, pos + 2, 10);
    if (new_line)
        *new_line = '\n';
    pos = strstr(pairing_p_str, "pk ");
    new_line = strchr(pos, '\n');
    if (new_line)
        *new_line = '\0';
    element_init_G1(public_p->pk, public_p->pairing);
    element_set_str(public_p->pk, pos + 3, 10);
    if (new_line)
        *new_line = '\n';
    pos = strstr(pairing_p_str, "msk ");
    if (pos != NULL)
    {
        new_line = strchr(pos, '\n');
        if (new_line)
            *new_line = '\0';
        element_init_Zr(secret_p->msk, public_p->pairing);
        element_set_str(secret_p->msk, pos + 4, 10);
        secret_p->public_params = public_p;
        if (new_line)
            *new_line = '\n';
    }

    // public params setup
    public_p->q = pairing_length_in_bytes_x_only_G1(public_p->pairing);
    public_p->l1 = public_p->q / 2;
    public_p->l2 = public_p->q - public_p->l1;
    public_p->hash_type = hash_type;

    pbc_param_clear(pairing_p);
}

void extract_p(sv_user_t user, sv_public_params_t public_p)
{
    // Hashing
    uint8_t digest[MAX_DIGEST_SIZE];
    uint16_t digest_len = hash(digest, user->id, IDENTITY_SIZE, public_p->hash_type);

    // Generating pk for the user
    element_from_hash(user->pk, digest, digest_len);
}

void extract_s(sv_user_t user, sv_secret_params_t secret_p)
{
    // Hashing
    uint8_t digest[MAX_DIGEST_SIZE];
    uint16_t digest_len = hash(digest, user->id, IDENTITY_SIZE, secret_p->public_params->hash_type);

    // Generating sk for the user
    element_from_hash(user->sk, digest, digest_len);
    element_mul_zn(user->sk, user->sk, secret_p->msk);
}

void delegate(delegation_t w, sv_user_t from, sv_user_t to, sv_public_params_t public_p)
{
    memcpy(w->m->from, from->id, IDENTITY_SIZE);
    memcpy(w->m->to, to->id, IDENTITY_SIZE);

    element_t k, h, temp;
    element_init_Zr(k, public_p->pairing);
    element_init_Zr(h, public_p->pairing);
    element_init_G1(temp, public_p->pairing);

    // k <- Zr (random in Zr)
    element_random(k);

    // r = e(P, P)^k (in GT)
    element_pairing(w->r, public_p->P, public_p->P);
    element_pow_zn(w->r, w->r, k);

    // h = H(m, ra) (in Zr)
    hash_warrant_and_r(h, w->r, w->m, public_p->hash_type);

    // S = h * sk + k * P (in G1)
    element_mul_zn(w->S, from->sk, h);
    element_mul_zn(temp, public_p->P, k);
    element_add(w->S, w->S, temp);

    element_clear(k);
    element_clear(h);
    element_clear(temp);
}

int del_verify(delegation_t w, sv_public_params_t public_p)
{
    element_t h, left_el, right_el;
    element_init_Zr(h, public_p->pairing);
    element_init_GT(left_el, public_p->pairing);
    element_init_GT(right_el, public_p->pairing);

    // The user who supposedly created the warrant for the delegated user
    sv_user_t user;
    user_init(user, w->m->from, public_p);
    extract_p(user, public_p);

    hash_warrant_and_r(h, w->r, w->m, public_p->hash_type);

    // e(S, P) = e(Pub, pk)^h * r
    element_pairing(left_el, w->S, public_p->P);

    element_pairing(right_el, user->pk, public_p->pk);
    element_pow_zn(right_el, right_el, h);
    element_mul(right_el, right_el, w->r);

    int res = element_cmp(left_el, right_el);

    user_clear(user);
    element_clear(h);
    element_clear(left_el);
    element_clear(right_el);

    return res == 0;
}

void pk_gen(element_t k_sign, sv_user_t user, delegation_t w, sv_public_params_t public_p)
{
    element_t h;
    element_init_Zr(h, public_p->pairing);
    element_init_G1(k_sign, public_p->pairing);

    // h = H(m, r)
    hash_warrant_and_r(h, w->r, w->m, public_p->hash_type);

    // k_sig = h * sk + S
    element_mul_zn(k_sign, user->sk, h);
    element_add(k_sign, k_sign, w->S);

    element_clear(h);
}
