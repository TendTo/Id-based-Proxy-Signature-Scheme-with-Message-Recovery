/**
 * @file data.h
 * @author TendTo (https://github.com/TendTo)
 *
 * @brief Header file containing the data structures used by the scheme and the functions used to manage them.
 */
#ifndef DATA_H
#define DATA_H

#include <string.h>
#include <pbc/pbc.h>
#include "define.h"

#define IDENTITY_SIZE 32
#define WARRANT_SIZE 64
#define MAX_DIGEST_SIZE 64
#define MAX_PARAM_LINE_SIZE 4096
#define generic_dlog_secure_size_by_security_level(level) ((level)*2)
#define STR_IDENTITY_SIZE(string) strlen(string) > IDENTITY_SIZE ? IDENTITY_SIZE : strlen(string)

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
    short precompute;      // Flag to indicate if the precomputation has been done.
    pairing_pp_t eP_pp;    // Precomputed value of P to speed up pairings e(P,.).
    pairing_pp_t epk_pp;   // Precomputed value of pk to speed up pairings e(pk,.).
    element_pp_t PP_pp;    // Precomputed value of e(P,P) to speed up powers e(P, P)^..
    element_pp_t P_pp;     // Precomputed value of P to speed up multiplications .P.
    element_pp_t pk_pp;    // Precomputed value of pk to speed up multiplications .pk.
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

struct sv_user_struct
{
    sv_identity_t id;   // Identity of the user.
    element_t sk;       // The secret key of the user.
    element_t pk;       // The public key of the user.
    element_pp_t sk_pp; // Precomputed value of sk to speed up multiplications .sk.
};
typedef struct sv_user_struct *sv_user_ptr;
typedef struct sv_user_struct sv_user_t[1];

struct warrant_struct
{
    sv_identity_t from; // Identity of the user that is delegating the signature.
    sv_identity_t to;   // Identity of the user that is invested with the signature.
};
typedef struct warrant_struct *warrant_ptr;
typedef struct warrant_struct warrant_t[1];

struct delegation_struct
{
    warrant_t m; // Warrant of the delegation.
    element_t r; // r value used to verify the delegation (in GT).
    element_t S; // S value used to verify the delegation (in G1).
};
typedef struct delegation_struct *delegation_ptr;
typedef struct delegation_struct delegation_t[1];

struct proxy_signature_struct
{
    warrant_t m; // Warrant of the delegation.
    element_t r; // r value used to verify the signature (in GT).
    element_t V; // V value used to verify the signature (in Zr).
    element_t U; // U value used to verify the signature (in G1).
};
typedef struct proxy_signature_struct *proxy_signature_ptr;
typedef struct proxy_signature_struct proxy_signature_t[1];

long read_binary_file(uint8_t **data, const char file_path[]);

/**
 * @brief Initialize the user struct.
 * Make sure all elements are initialized.
 * Both the secret and public keys are set to 0, so it is easy to check if they have been extracted.
 *
 * @param user User to be initialized.
 * @param identity Identity of the user.
 * @param public_p Public parameters of the scheme.
 */
void user_init(sv_user_t user, const sv_identity_t identity, sv_public_params_t public_p);

/**
 * @brief Initialize the user struct using a string as identity.
 * Make sure all elements are initialized.
 * Both the secret and public keys are set to 0, so it is easy to check if they have been extracted.
 *
 * @param user User to be initialized.
 * @param identity Identity of the user represented as a string.
 * @param public_p Public parameters of the scheme.
 */
void user_init_str(sv_user_t user, const char identity[], sv_public_params_t public_p);

/**
 * @brief Initialize the warrant struct.
 * Make sure all elements are initialized.
 *
 * @param w Warrant to be initialized.
 * @param public_p Public parameters of the scheme.
 */
void delegation_init(delegation_t w, sv_public_params_t public_p);

/**
 * @brief Initialize the proxy signature struct.
 * Make sure all elements are initialized.
 *
 * @param p_sig Proxy signature to be initialized.
 * @param public_p Public parameters of the scheme.
 */
void proxy_signature_init(proxy_signature_t p_sig, sv_public_params_t public_p);

/**
 * @brief Serialize a warrant structure converting it into a byte array.
 * This allows for easy hashing and storage of the warrant.
 *
 * @param buffer buffer to store the serialized warrant. It must be at least IDENTITY_SIZE * 2 bytes long.
 * @param m warrant structure to be serialized.
 * @return uint16_t size of the serialized warrant.
 */
uint16_t serialize_warrant(uint8_t buffer[WARRANT_SIZE], const warrant_t m);

/**
 * @brief Deserialize a warrant structure converting it from a byte array to a warrant structure.
 *
 * @param m warrant structure to be serialized.
 * @param buffer buffer to store the serialized warrant.
 * @return uint16_t size of the serialized warrant.
 */
uint16_t deserialize_warrant(warrant_t m, const uint8_t buffer[WARRANT_SIZE]);

/**
 * @brief Serialize the delegation structure converting it into a byte array.
 * The buffer is allocated inside the function and must be freed by the caller.
 *
 * @param data newly allocated buffer containing the serialized delegation.
 * @param w delegation structure to be serialized.
 * @return length of the serialized delegation.
 */
int serialize_delegation(uint8_t **data, delegation_t w);

/**
 * @brief Read a serialized delegation from a buffer and deserialize it, obtaining a delegation structure.
 *
 * @param w delegation structure read from the buffer.
 * @param data buffer containing the serialized delegation.
 */
void deserialize_delegation(delegation_t w, uint8_t data[]);

/**
 * @brief Read a serialized delegation from a file and deserialize it, obtaining a delegation structure.
 *
 * @param w delegation structure read from the file.
 * @param file_path path to the file containing the serialized delegation.
 */
void deserialize_delegation_from_file(delegation_t w, const char file_path[]);

/**
 * @brief Print the delegation structure to stdout in binary format.
 *
 * @param w delegation structure to be printed.
 */
void delegation_printf(delegation_t w);

/**
 * @brief Print the delegation structure to the provided stream in binary format.
 *
 * @param stream file stream where to print the delegation structure.
 * @param w delegation structure to be printed.
 */
void delegation_fprintf(FILE *stream, delegation_t w);

/**
 * @brief Serialize the proxy signature structure converting it into a byte array.
 * The buffer is allocated inside the function and must be freed by the caller.
 *
 * @param data buffer to store the serialized proxy signature.
 * @param p_sign proxy signature structure to be serialized.
 * @return length of the serialized proxy signature.
 */
int serialize_proxy_signature(uint8_t **data, proxy_signature_t p_sign);

/**
 * @brief Read a serialized proxy signature from a buffer and deserialize it, obtaining a proxy signature structure.
 *
 * @param p_sign proxy signature structure read from the buffer.
 * @param data buffer containing the serialized proxy signature.
 */
void deserialize_proxy_signature(proxy_signature_t p_sign, uint8_t data[]);

/**
 * @brief Read a serialized proxy signature from a file and deserialize it, obtaining a proxy signature structure.
 *
 * @param p_sig proxy signature structure read from the file.
 * @param file_path path to the file containing the serialized proxy signature.
 */
void deserialize_proxy_signature_from_file(proxy_signature_t p_sig, const char file_path[]);

/**
 * @brief Print the proxy signature structure to stdout in binary format.
 *
 * @param p_sign proxy signature structure to be printed.
 */
void proxy_signature_printf(proxy_signature_t p_sign);

/**
 * @brief Print the proxy signature structure to the provided stream in binary format.
 *
 * @param stream file stream where to print the proxy signature structure.
 * @param p_sign proxy signature structure to be printed.
 */
void proxy_signature_fprintf(FILE *stream, proxy_signature_t p_sign);

/**
 * @brief Clear the public param struct.
 * Makes sure all elements are cleared.
 *
 * @param public_p Public parameters of the scheme to be cleared.
 */
void public_param_clear(sv_public_params_t public_p);

/**
 * @brief Clear the secret param struct.
 * Make sure all elements are cleared.
 *
 * @param secret_p Secret parameters of the scheme to be cleared.
 */
void secret_param_clear(sv_secret_params_t secret_p);

/**
 * @brief Clear the user struct.
 * Make sure all elements are cleared.
 *
 * @param user User to be cleared.
 */
void user_clear(sv_user_t user);

/**
 * @brief Clear the warrant struct.
 * Make sure all elements are cleared.
 *
 * @param w Warrant to be cleared.
 */
void delegation_clear(delegation_t w);

/**
 * @brief Clear the proxy signature struct.
 * Make sure all elements are cleared.
 *
 * @param p_sig Proxy signature to be cleared.
 */
void proxy_signature_clear(proxy_signature_t p_sig);

#endif // DATA_H
