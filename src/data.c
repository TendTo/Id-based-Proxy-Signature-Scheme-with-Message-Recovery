#include "data.h"

long read_binary_file(uint8_t **data, const char file_path[])
{
    FILE *fp = fopen(file_path, "rb");
    if (fp == NULL)
    {
        fprintf(stderr, "Error opening file %s\n", file_path);
        exit(1);
    }
    fseek(fp, 0L, SEEK_END);
    long len = ftell(fp);
    rewind(fp);
    *data = malloc(len);
    if (fread(*data, len, 1, fp) != 1)
    {
        fprintf(stderr, "Error reading file %s", file_path);
        exit(1);
    }
    fclose(fp);
    return len;
}

void user_init(sv_user_t user, const sv_identity_t identity, sv_public_params_t public_p)
{
    if (identity)
        memcpy(user->id, identity, IDENTITY_SIZE);
    element_init_G1(user->pk, public_p->pairing);
    element_init_G1(user->sk, public_p->pairing);
    element_set0(user->pk);
    element_set0(user->sk);
    user->sk_pp->data = NULL;
}

void user_init_str(sv_user_t user, const char identity[], sv_public_params_t public_p)
{
    sv_identity_t id;
    memset(id, 0, IDENTITY_SIZE);
    memcpy(id, identity, STR_IDENTITY_SIZE(identity));
    user_init(user, id, public_p);
}

void delegation_init(delegation_t w, sv_public_params_t public_p)
{
    element_init_GT(w->r, public_p->pairing);
    element_init_G1(w->S, public_p->pairing);
}

void proxy_signature_init(proxy_signature_t p_sig, sv_public_params_t public_p)
{
    element_init_G1(p_sig->U, public_p->pairing);
    element_init_GT(p_sig->r, public_p->pairing);
    element_init_Zr(p_sig->V, public_p->pairing);
}

uint16_t serialize_warrant(uint8_t buffer[WARRANT_SIZE], const warrant_t m)
{
    memcpy(buffer, m->from, IDENTITY_SIZE);
    memcpy(buffer + IDENTITY_SIZE, m->to, IDENTITY_SIZE);
    return WARRANT_SIZE;
}

uint16_t deserialize_warrant(warrant_t m, const uint8_t buffer[WARRANT_SIZE])
{
    memcpy(m->from, buffer, IDENTITY_SIZE);
    memcpy(m->to, buffer + IDENTITY_SIZE, IDENTITY_SIZE);
    return WARRANT_SIZE;
}

int serialize_delegation(uint8_t **data, delegation_t w)
{
    int r_len = element_length_in_bytes(w->r);
    int S_len = element_length_in_bytes_compressed(w->S);
    int len = r_len + S_len + sizeof(w->m->from) + sizeof(w->m->to);
    *data = malloc(len);
    serialize_warrant(*data, w->m);
    int offset = sizeof(w->m->from) + sizeof(w->m->to);
    element_to_bytes(*data + offset, w->r);
    offset += r_len;
    element_to_bytes_compressed(*data + offset, w->S);
    return len;
}

void deserialize_delegation(delegation_t w, uint8_t data[])
{
    int r_len = element_length_in_bytes(w->r);
    deserialize_warrant(w->m, data);
    int offset = sizeof(w->m->from) + sizeof(w->m->to);
    element_from_bytes(w->r, data + offset);
    offset += r_len;
    element_from_bytes_compressed(w->S, data + offset);
}

void deserialize_delegation_from_file(delegation_t w, const char file_path[])
{
    VERBOSE_PRINT("Deserialized delegation from file '%s'\n", file_path);
    uint8_t *data = NULL;
    int len = read_binary_file(&data, file_path);
    deserialize_delegation(w, data);
    VERBOSE_PRINT("Expected size: %ld\nFile size: %d\n", sizeof(w->m->from) + sizeof(w->m->to) + element_length_in_bytes(w->r) + element_length_in_bytes_compressed(w->S), len);
    free(data);
}

void delegation_printf(delegation_t w)
{
    delegation_fprintf(stdout, w);
}

void delegation_fprintf(FILE *stream, delegation_t w)
{
    uint8_t *data = NULL;
    int len = serialize_delegation(&data, w);
    for (int i = 0; i < len; i++)
        fprintf(stream, "%c", data[i]);
    free(data);
}

int serialize_proxy_signature(uint8_t **data, proxy_signature_t p_sig)
{
    int r_len = element_length_in_bytes(p_sig->r);
    int U_len = element_length_in_bytes_compressed(p_sig->U);
    int V_len = element_length_in_bytes(p_sig->V);
    int len = r_len + U_len + V_len + sizeof(p_sig->m->from) + sizeof(p_sig->m->to);
    *data = malloc(len);
    serialize_warrant(*data, p_sig->m);
    int offset = sizeof(p_sig->m->from) + sizeof(p_sig->m->to);
    element_to_bytes(*data + offset, p_sig->r);
    offset += r_len;
    element_to_bytes_compressed(*data + offset, p_sig->U);
    offset += U_len;
    element_to_bytes(*data + offset, p_sig->V);
    return len;
}

void deserialize_proxy_signature(proxy_signature_t p_sig, uint8_t data[])
{
    int r_len = element_length_in_bytes(p_sig->r);
    int U_len = element_length_in_bytes_compressed(p_sig->U);
    VERBOSE_PRINT("Deserializing proxy signature");
    VERBOSE_PRINT("Expected size: %ld bytes", sizeof(p_sig->m->from) + sizeof(p_sig->m->to) + r_len + U_len + element_length_in_bytes(p_sig->V));
    deserialize_warrant(p_sig->m, data);
    int offset = sizeof(p_sig->m->from) + sizeof(p_sig->m->to);
    element_from_bytes(p_sig->r, data + offset);
    offset += r_len;
    element_from_bytes_compressed(p_sig->U, data + offset);
    offset += U_len;
    element_from_bytes(p_sig->V, data + offset);
}

void deserialize_proxy_signature_from_file(proxy_signature_t p_sig, const char file_path[])
{
    VERBOSE_PRINT("Reading proxy signature from file %s\n", file_path);
    uint8_t *data = NULL;
    int len = read_binary_file(&data, file_path);
    deserialize_proxy_signature(p_sig, data);
    VERBOSE_PRINT("Expected size: %ld\nFile size: %d bytes\n", sizeof(p_sig->m->from) + sizeof(p_sig->m->to) + element_length_in_bytes(p_sig->r) + element_length_in_bytes_compressed(p_sig->U) + element_length_in_bytes(p_sig->V), len);
    free(data);
}

void proxy_signature_printf(proxy_signature_t p_sign)
{
    proxy_signature_fprintf(stdout, p_sign);
}

void proxy_signature_fprintf(FILE *stream, proxy_signature_t p_sign)
{
    uint8_t *data = NULL;
    int len = serialize_proxy_signature(&data, p_sign);
    for (int i = 0; i < len; i++)
        fprintf(stream, "%c", data[i]);
    free(data);
}

void public_param_clear(sv_public_params_t public_p)
{
    element_clear(public_p->P);
    element_clear(public_p->pk);
    if (public_p->precompute)
    {
        pairing_pp_clear(public_p->eP_pp);
        pairing_pp_clear(public_p->epk_pp);
        element_pp_clear(public_p->PP_pp);
        element_pp_clear(public_p->P_pp);
        element_pp_clear(public_p->pk_pp);
    }
    pairing_clear(public_p->pairing);
}

void secret_param_clear(sv_secret_params_t secret_p)
{
    element_clear(secret_p->msk);
}

void user_clear(sv_user_t user)
{
    element_clear(user->sk);
    element_clear(user->pk);
    if (user->sk_pp->data)
        element_pp_clear(user->sk_pp);
}

void delegation_clear(delegation_t w)
{
    element_clear(w->r);
    element_clear(w->S);
}

void proxy_signature_clear(proxy_signature_t p_sig)
{
    element_clear(p_sig->r);
    element_clear(p_sig->U);
    element_clear(p_sig->V);
}
