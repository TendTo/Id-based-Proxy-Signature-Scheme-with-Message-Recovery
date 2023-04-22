#ifndef SHARED_H
#define SHARED_H

#include <string.h>
#include <assert.h>
#include <pbc/pbc.h>
#include <nettle/sha1.h>
#include <nettle/sha2.h>
#include "data.h"

/**
 * @brief Get the size of the non generic dlog secure size based on the NIST suggestions.
 *
 * @param sec_lvl security expressed as a number of bits.
 * @return unsigned int secure size of elements in the group in bits.
 */
unsigned int non_generic_dlog_secure_size_by_security_level(unsigned int sec_lvl);

/**
 * @brief Generate the digest of the data using the hash_type algorithm.
 *
 * @param digest ouput digest obtained by applying the hash_type algorithm to data.
 * @param data data to be hashed.
 * @param len length of the data buffer in bytes.
 * @param hash_type hash algorithm to be used.
 * @return uint16_t length of the digest in bytes.
 */
uint16_t hash(uint8_t digest[MAX_DIGEST_SIZE], const void *data, size_t len, hash_type_t hash_type);

/**
 * @brief Generate the digest of the element using the hash_type algorithm
 *
 * @param digest output digest obtained by applying the hash_type algorithm to the element.
 * @param e element to be hashed.
 * @param hash_type hash algorithm to be used.
 * @return uint16_t length of the digest in bytes.
 */
uint16_t hash_element(uint8_t digest[MAX_DIGEST_SIZE], element_t e, hash_type_t hash_type);

/**
 * @brief hash both the warrant and the random value r and return the result in h, an element of Zq*.
 * @warning h must be initialized before calling this function.
 *
 * @param h element of Zq* where the hash is stored.
 * @param r element r that will be hashed.
 * @param m warrant to be hashed.
 * @param hash_type hash algorithm to be used.
 */
void hash_warrant_and_r(element_t h, element_t r, warrant_t m, hash_type_t hash_type);

/**
 * @brief Calculate the value of beta.
 * Starting from the message to be signed and the public parameters of the scheme, beta is obtained as:
 * beta = F1(msg) || F2(F1(msg)) (+) msg)
 *
 * @param beta output of the hash function.
 * @param msg message to be hashed.
 * @param msg_size size of the message to be signed in bytes.
 * @param public_p public parameters of the scheme.
 */
void calculate_beta(uint8_t beta[], const uint8_t msg[], size_t msg_size, sv_public_params_t public_p);

/**
 * @brief Initialize the pairings parameters.
 *
 * @param pairings_p Structure where the parameters are stored.
 * @param sec_lvl The security level the scheme is expected to have.
 */
void params_init(pbc_param_t pairings_p, int sec_lvl);

/**
 * @brief Initialization function for the scheme.
 * It takes as input a security parameter lambda and the hash function to use.
 * It will take care of generating the parameters of the pairing.
 * Produces the master key msk and the system's parameters (G1, G2, H0, H1, H2, F1, F2, e, P, pk, q, l1, l2).
 *
 * @param public_p All the public parameters created through the setup.
 * @param secret_p Secret parameters created through the setup.
 * @param sec_lvl The security level the scheme is expected to have.
 * @param hash_type The hash function used by the scheme.
 */
void setup(sv_public_params_t public_p, sv_secret_params_t secret_p, int sec_lvl, hash_type_t hash_type);

/**
 * @brief Initialization function for the scheme.
 * It takes as input the hash function to use and the parameters of the pairing.
 * Produces the master key msk and the system's parameters (G1, G2, H0, H1, H2, F1, F2, e, P, pk, q, l1, l2).
 *
 * @param public_p All the public parameters created through the setup.
 * @param secret_p Secret parameters created through the setup.
 * @param hash_type The hash function used by the scheme.
 * @param pairing_p Parameters of the pairing.
 */
void setup_from_params(sv_public_params_t public_p, sv_secret_params_t secret_p, hash_type_t hash_type, pbc_param_t pairing_p);

/**
 * @brief Initialization function for the scheme.
 * It takes as input the string representation of the parameters of the pairing, as well as the hash function to use.
 * Produces the master key msk and the system's parameters (G1, G2, H0, H1, H2, F1, F2, e, P, pk, q, l1, l2).
 * @warning If the string does not contain a master key msk, the secret parameters will not be initialized.
 * This is not a problem if the msk is not needed.
 *
 * @param public_p All the public parameters created through the setup.
 * @param secret_p Secret parameters created through the setup.
 * @param pairing_p_str String representation of the parameters of the pairing.
 */
void setup_from_str(sv_public_params_t public_p, sv_secret_params_t secret_p, char pairing_p_str[]);

/**
 * @brief Produces the public key pk_id from an identity.
 * It uses the hash function H0 to map the any string {0, 1}*, representing the identity,
 * to an element of G1: pk_id = H0(identity).
 *
 * @param user User struct that will contain the public key.
 * @param public_p All the public parameters of the scheme.
 */
void extract_p(sv_user_t user, sv_public_params_t public_p);

/**
 * @brief Produces the secret key sk_id from an identity.
 * It uses the hash function H0 to map the any string {0, 1}*, representing the identity,
 * to an element of G1.
 * Then multiplies the master key sk with the result of the hash function: sk_id = sk * H0(identity).
 *
 * @param user User struct that will contain the secret key.
 * @param secret_p All the secret parameters of the user.
 */
void extract_s(sv_user_t user, sv_secret_params_t secret_p);

/**
 * @brief Delegates the right to sign messages to the identity id.
 * The original signer selects k in Zq* and computes the following values:
 * - r = e(P, P)^k (in GT)
 * - h = H1(m, r) (in Zq*)
 * - S = h * sk + k * P (in G1)
 * The resulting delegation is W = (m, r, S).
 *
 * @param w delegation to be created.
 * @param from user creating a delegation. The sk must be initialized.
 * @param to user receiving the delegation.
 * @param public_p All the public parameters of the scheme.
 * @warning The secret key of the user creating the delegation must be initialized.
 */
void delegate(delegation_t w, sv_user_t from, sv_user_t to, sv_public_params_t public_p);

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
 * @param public_p All the public parameters of the scheme.
 * @return whether the delegation has been created by the `identity` user (1) or not (0).
 */
int del_verify(delegation_t w, sv_public_params_t public_p);

/**
 * @brief Produces a proxy signing key from a delegation.
 * If the delegate used accepts the delegation, it can produce a proxy signing key.
 * It does so by computing the following values:
 * - h = H1(m, r)
 * - psk = h * d + S
 *
 * @param k_sign proxy signing key to be created.
 * @param user delegated user who wants to sign a message. The sk must be initialized.
 * @param w delegation that validates the proxy signing key.
 * @param public_p All the public parameters of the scheme.
 * @warning The delegated user must have the secret key initialized.
 */
void pk_gen(element_t k_sign, sv_user_t user, delegation_t w, sv_public_params_t public_p);


#endif // SHARED_H
