#ifndef IMP_SV_SCHEME_H
#define IMP_SV_SCHEME_H

#include <pbc/pbc.h>
#include <nettle/sha1.h>
#include "shared.h"

/**
 * @brief The proxy signer signs a message m.
 * After choosing a random k in Zq*, the proxy signer computes the following values:
 * - rb = e(P, P)^k
 * - beta = F1(m)||(F2(F1(m))(+)m)
 * - alpha = [beta]10
 * - V = H(rb) + alpha
 * - U = k * P + V * d
 *
 * @param p_sig proxy signature to be created.
 * @param k_sign proxy signing key of the proxy signer.
 * @param w delegation from the original user to the proxy signer that validates the proxy signing key.
 * @param msg message to be signed.
 * @param msg_size size of the message to be signed in bytes.
 * @param public_p All the public parameters of the scheme.
 */
void imp_p_sign(proxy_signature_t p_sig, element_t k_sign, delegation_t w, const uint8_t msg[], size_t msg_size, sv_public_params_t public_p);

/**
 * @brief Checks if the proxy signature is valid.
 * If so, the original message m is returned.
 *
 * @param ps proxy signature to be verified.
 * @param public_p All the public parameters of the scheme.
 */
unsigned short imp_sign_verify(proxy_signature_t p_sig, sv_public_params_t public_p);

#endif // IMP_SV_SCHEME_H