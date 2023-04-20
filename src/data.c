#include "data.h"

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
    int S_len = element_length_in_bytes(w->S);
    int len = r_len + S_len + sizeof(w->m->from) + sizeof(w->m->to);
    int offset = 0;
    *data = malloc(len);
    serialize_warrant(*data, w->m);
    offset = sizeof(w->m->from) + sizeof(w->m->to);
    element_to_bytes(*data + offset, w->r);
    element_to_bytes(*data + offset + r_len, w->S);
    return len;
}

void deserialize_delegation(delegation_t w, uint8_t data[])
{
    int r_len = element_length_in_bytes_compressed(w->r);
    int offset = 0;
    deserialize_warrant(w->m, data);
    offset = sizeof(w->m->from) + sizeof(w->m->to);
    element_from_bytes_compressed(w->r, data + offset);
    offset += r_len;
    element_from_bytes_compressed(w->S, data + offset);
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
    int r_len = element_length_in_bytes_compressed(p_sig->r);
    int U_len = element_length_in_bytes_compressed(p_sig->U);
    int V_len = element_length_in_bytes_compressed(p_sig->V);
    int len = r_len + U_len + V_len + sizeof(p_sig->m->from) + sizeof(p_sig->m->to);
    int offset = 0;
    *data = malloc(len);
    serialize_warrant(*data, p_sig->m);
    offset = sizeof(p_sig->m->from) + sizeof(p_sig->m->to);
    element_to_bytes_compressed(*data + offset, p_sig->r);
    offset += r_len;
    element_to_bytes_compressed(*data + offset, p_sig->U);
    offset += U_len;
    element_to_bytes_compressed(*data + offset, p_sig->V);
    return len;
}

void deserialize_proxy_signature(proxy_signature_t p_sign, uint8_t data[])
{
    int r_len = element_length_in_bytes_compressed(p_sign->r);
    int U_len = element_length_in_bytes_compressed(p_sign->U);
    int offset = 0;
    deserialize_warrant(p_sign->m, data);
    offset = sizeof(p_sign->m->from) + sizeof(p_sign->m->to);
    element_from_bytes_compressed(p_sign->r, data + offset);
    offset += r_len;
    element_from_bytes_compressed(p_sign->U, data + offset);
    offset += U_len;
    element_from_bytes_compressed(p_sign->V, data + offset);
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
    pairing_clear(public_p->pairing);
}

void secret_param_clear(sv_secret_params_t secret_p)
{
    element_clear(secret_p->msk);
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
