#ifndef SHARED_H
#define SHARED_H

#include <string.h>
#include <assert.h>
#include <pbc/pbc.h>
#include <nettle/sha1.h>
#include <nettle/sha2.h>

#define IDENTITY_SIZE 32
#define WARRANT_SIZE 64
#define MAX_DIGEST_SIZE 64
#define generic_dlog_secure_size_by_security_level(level) ((level)*2)

typedef enum
{
    sha_1,
    sha_256,
    sha_512
} hash_type_t;

typedef uint8_t sv_identity_t[IDENTITY_SIZE];
typedef uint8_t serialized_warrant_t[WARRANT_SIZE];

struct sv_public_params_struct
{
    pairing_t pairing;     // The pairing used by the scheme.
    element_t pk;          // The public key.
    element_t P;           // The generator of G1.
    int l1;                // Half of number bits of an element in G1.
    int l2;                // Half of number bits of an element in G1.
    int q;                 // Order of the group.
    hash_type_t hash_type; // Hash algorithm used by the scheme.
};
typedef struct sv_public_params_struct *sv_public_params_ptr;
typedef struct sv_public_params_struct sv_public_params_t[1];

struct sv_secret_params_struct
{
    sv_public_params_ptr public_params; // Public parameters of the scheme.
    element_t msk;                      // The master secret key.
};
typedef struct sv_secret_params_struct *sv_secret_params_ptr;
typedef struct sv_secret_params_struct sv_secret_params_t[1];

struct warrant_struct
{
    sv_identity_t from; // Identity of the user that is delegating the signature.
    sv_identity_t to;   // Identity of the user that is invested with the signature.
};
typedef struct warrant_struct *warrant_ptr;
typedef struct warrant_struct warrant_t[1];

struct delegation_struct
{
    warrant_ptr m; // Warrant of the delegation.
    element_t r;   // r value used to verify the delegation (in GT).
    element_t S;   // S value used to verify the delegation (in G1).
};
typedef struct delegation_struct *delegation_ptr;
typedef struct delegation_struct delegation_t[1];

/**
 * @brief Get the size of the non generic dlog secure size based on the NIST suggestions.
 *
 * @param lvl security expressed as a number of bits.
 * @return unsigned int secure size of elements in the group in bits.
 */
unsigned int non_generic_dlog_secure_size_by_security_level(unsigned int lvl);

/**
 * @brief Generate the digest of the data using the hash_type algorithm
 *
 * @param digest ouput digest obtained by applying the hash_type algorithm to data
 * @param data data to be hashed
 * @param len length of ht data buffer in bytes
 * @param hash_type hash algorithm to be used
 * @return unsigned short length of the digest in bytes
 */
unsigned short hash(uint8_t digest[MAX_DIGEST_SIZE], const void *data, size_t len, hash_type_t hash_type);

/**
 * @brief Generate the digest of the element using the hash_type algorithm
 *
 * @param digest output digest obtained by applying the hash_type algorithm to the element
 * @param e element to be hashed
 * @param hash_type hash algorithm to be used
 * @return unsigned short length of the digest in bytes
 */
unsigned short hash_element(uint8_t digest[MAX_DIGEST_SIZE], element_t e, hash_type_t hash_type);

/**
 * @brief Serialize a warrant structure converting it into a byte array.
 * This allows for easy hashing and storage of the warrant.
 *
 * @param buffer buffer to store the serialized warrant. It must be at least IDENTITY_SIZE * 2 bytes long.
 * @param m warrant structure to be serialized.
 * @return unsigned short size of the serialized warrant.
 */
unsigned short serialize_warrant(uint8_t buffer[WARRANT_SIZE], const warrant_t m);

/**
 * @brief Deserialize a warrant structure converting it from a byte array.
 * This allows for easy hashing and storage of the warrant.
 *
 * @param buffer buffer to store the serialized warrant.
 * @param m warrant structure to be serialized.
 * @return unsigned short size of the serialized warrant.
 */
unsigned short deserialize_warrant(warrant_t m, const uint8_t buffer[WARRANT_SIZE]);

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
 * @brief Initialization function for the scheme.
 * It takes as input a security parameter lambda and return a master key sk
 * and the system's parameters (G1, G2, H0, H1, H2, F1, F2, e, P, pk, q, l1, l2).
 *
 * @param public_p All the public parameters created through the setup.
 * @param secret_p secret parameters created through the setup.
 * @param sec_lvl The security level the scheme is expected to have.
 * @param hash_type The hash function used by the scheme.
 */
void setup(sv_public_params_t public_p, sv_secret_params_t secret_p, int sec_lvl, hash_type_t hash_type);

/**
 * @brief Produces the public key pk_id from an identity.
 * It uses the hash function H0 to map the any string {0, 1}*, representing the identity,
 * to an element of G1: pk_id = H0(identity).
 *
 * @param pk_id Public key created for the user from their identifier.
 * @param identity Identity of the user of IDENTITY_SIZE bytes.
 * @param public_p All the public parameters of the scheme.
 */
void extract_p(element_t pk_id, const sv_identity_t identity, sv_public_params_t public_p);

/**
 * @brief Produces the secret key sk_id from an identity.
 * It uses the hash function H0 to map the any string {0, 1}*, representing the identity,
 * to an element of G1.
 * Then multiplies the master key sk with the result of the hash function: sk_id = sk * H0(identity).
 *
 * @param pk_id Private key created for the user from their identifier.
 * @param identity Identity of the user of IDENTITY_SIZE bytes.
 * @param secret_p All the secret parameters of the user.
 */
void extract_s(element_t sk_id, const sv_identity_t identity, sv_secret_params_t secret_p);

/**
 * @brief Delegates the right to sign messages to the identity id.
 * The original signer selects k in Zq* and computes the following values:
 * - r = e(P, P)^k (in GT)
 * - h = H1(m, r) (in Zq*)
 * - S = h * sk + k * P (in G1)
 * The resulting delegation is W = (m, r, S).
 *
 * @param w delegation to be created.
 * @param sk secret key of the user.
 * @param m warrant to be delegated.
 * @param public_p All the public parameters of the scheme.
 */
void delegate(delegation_t w, element_t sk, warrant_t m, sv_public_params_t public_p);

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
 * @param identity identity of the user who supposedly created the delegation.
 * @param public_p All the public parameters of the scheme.
 * @return whether the delegation has been created by the `identity` user (1) or not (0).
 */
int del_verify(delegation_t w, sv_identity_t identity, sv_public_params_t public_p);

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
 * @brief Clear the public param struct.
 * Makes sure all elements are cleared.
 *
 * @param public_p Parameters public publicly.
 */
void public_param_clear(sv_public_params_t public_p);

/**
 * @brief Clear the secret param struct.
 * Make sure all elements are cleared.
 *
 * @param secret_p Parameters known only by the original signer.
 */
void secret_param_clear(sv_secret_params_t secret_p);

/**
 * @brief Clear the warrant struct.
 * Make sure all elements are cleared.
 *
 * @param w Warrant to be cleared.
 */
void delegation_clear(delegation_t w);

#endif // SHARED_H
