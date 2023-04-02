#ifndef SV_SCHEME_H
#define SV_SCHEME_H

#include <string.h>
#include <pbc/pbc.h>
#include <nettle/sha1.h>
#include "shared.h"

struct proxy_signature_struct
{
    warrant_ptr m; // Warrant of the delegation.
    element_t r;   // r value used to verify the signature (in GT).
    element_t V;   // V value used to verify the signature (in Zr).
    element_t U;   // U value used to verify the signature (in G1).
};
typedef struct proxy_signature_struct *proxy_signature_ptr;
typedef struct proxy_signature_struct proxy_signature_t[1];

/**
 * @brief Produces a proxy signing key from a delegation.
 * If the delegate used accepts the delegation, it can produce a proxy signing key.
 * It does so by computing the following values:
 * - h = H1(m, r)
 * - psk = h * d + S
 *
 * @param k_sign proxy signing key to be created.
 * @param sk secret key of the user who is accepting the delegation.
 * @param w delegation that validates the proxy signing key.
 * @param public_p All the public parameters of the scheme.
 */
void pk_gen(element_t k_sign, element_t sk, delegation_t w, sv_public_params_t public_p);

/**
 * @brief The proxy signer signs a message m.
 * After choosing a random k in Zq*, the proxy signer computes the following values:
 * - r = e(P, P)^k
 * - v = ra * rb
 * - beta = F1(m)||(F2(F1(m))(+)m)
 * - alpha = [beta]10
 * - Vb = H2(v) + alpha
 * - U = k * P + d
 *
 * @param p_sig proxy signature to be created.
 * @param k_sign proxy signing key of the proxy signer.
 * @param w delegation from the original user to the proxy signer that validates the proxy signing key.
 * @param msg message to be signed.
 * @param msg_size size of the message to be signed in bytes.
 * @param public_p All the public parameters of the scheme.
 */
void p_sign(proxy_signature_t p_sig, element_t k_sign, delegation_t w, const uint8_t msg[], size_t msg_size, sv_public_params_t public_p);

/**
 * @brief Checks if the proxy signature is valid.
 * If so, the original message m is returned.
 *
 * @param ps proxy signature to be verified.
 * @param public_p All the public parameters of the scheme.
 */
unsigned short sign_verify(proxy_signature_t p_sig, sv_public_params_t public_p);

/**
 * @brief Clear the proxy signature struct.
 * Make sure all elements are cleared.
 *
 * @param p_sig Proxy signature to be cleared.
 */
void proxy_signature_clear(proxy_signature_t p_sig);

#endif // SV_SCHEME_H