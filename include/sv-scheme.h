#ifndef SV_SCHEME_H
#define SV_SCHEME_H

#include <pbc/pbc.h>
#include "lib-misc.h"

struct sv_shared_params_struct
{
    pairing_t pairing; // The pairing used by the scheme.
    element_t pk;      // The public key.
    element_t P;       // The generator of G1.
    int l1;            // Number of bits of an element in G1.
    int l2;            // Number of bits of an element in G2.
    int q;             // Order of the group.
};
typedef struct sv_shared_params_struct *sv_shared_params_ptr;
typedef struct sv_shared_params_struct sv_shared_params_t[1];

struct sv_private_params_struct
{
    element_t sk; // The master secret key.
};
typedef struct sv_private_params_struct *sv_private_params_ptr;
typedef struct sv_private_params_struct sv_private_params_t[1];

typedef struct
{

} identity_t;

typedef struct
{
} warrant_t;

typedef struct
{
} public_key_t;

typedef struct
{
} secret_key_t;

typedef struct
{

} delegation_t;

typedef struct
{

} proxy_signer_t;

typedef struct
{

} proxy_signature_t;

/**
 * @brief Initialization function for the scheme.
 * It takes as input a security parameter lambda and return a master key sk
 * and the system's parameters (G1, G2, H0, H1, H2, F1, F2, e, P, pk, q, l1, l2).
 *
 * @param shared_params All the public parameters created through the setup.
 * @param private_params Private parameters created through the setup.
 * @param lambda The security parameter.
 */
void setup(sv_shared_params_t shared_params, sv_private_params_t private_params, int lambda);

/**
 * @brief Produces the public key pk_id from an identity.
 * It uses the hash function H0 to map the any string {0, 1}*, representing the identity,
 * to an element of G1: pk_id = H0(identity).
 *
 * @param identity identity of the user.
 */
void extract_p(identity_t identity);

/**
 * @brief Produces the secret key sk_id from an identity.
 * It uses the hash function H0 to map the any string {0, 1}*, representing the identity,
 * to an element of G1.
 * Then multiplies the master key sk with the result of the hash function: sk_id = sk * H0(identity).
 *
 * @param identity identity of the user.
 * @param sk secret master key.
 */
void extract_s(identity_t identity, secret_key_t sk);

/**
 * @brief Delegates the right to sign messages to the identity id.
 * The original signer selects k in Zq* and computes the following values:
 * - r = e(P, P)^k
 * - h = H1(m, r)
 * - S = h * d + k * P
 * The resulting delegation is W = (m, r, S).
 *
 * @param sk_id secret key of the user who wants to delegate.
 * @param m warrant to be delegated.
 */
void delegate(secret_key_t sk_id, warrant_t m);

/**
 * @brief Verifies the validity of a delegation.
 * After receiving the delegation W = (m, r, S), the verifier computes the following values:
 * - h = H1(m, r)
 * - q = H0(identity)
 * The delegation is valid and 1 is returned if and only if the following equation holds:
 * e(S, P) = e(pk_id, P)^h * r.
 * In any other case, 0 is returned.
 *
 * @param w delegation to be verified.
 * @param id identity of the user who wants to delegate.
 * @return whether the delegation is valid (1) or not (0).
 */
int del_verify(delegation_t w, identity_t id);

/**
 * @brief Produces a proxy signing key from a delegation.
 * If the delegate used accepts the delegation, it can produce a proxy signing key.
 * It does so by computing the following values:
 * - h = H1(m, r)
 * - psk = h * d + S
 *
 * @param w delegation that validates the proxy signing key.
 */
void p_k_gen(delegation_t w);

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
 * @param message message to sign
 */
void p_sign(char *message);

/**
 * @brief Checks if the proxy signature is valid.
 * If so, the original message m is returned.
 *
 * @param ps proxy signature to be verified.
 */
void sign_verify(proxy_signature_t ps);

/**
 * @brief Get the identity of the user who signed created the warrant.
 *
 * @param m warrant to get the identity from.
 */
void get_id(warrant_t m);

/**
 * @brief Clear the shared param struct.
 * Makes sure all elements are cleared.
 *
 * @param shared_p Parameters shared publicly.
 */
void shared_param_clear(sv_shared_params_t shared_p);

/**
 * @brief Clear the private param struct.
 * Make sure all elements are cleared.
 *
 * @param private_p Parameters known only by the original signer.
 */
void private_param_clear(sv_private_params_t private_p);

#endif // SV_SCHEME_H