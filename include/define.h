/**
 * @file define.h
 * @author TendTo (https://github.com/TendTo)
 *
 * @brief Header file containing some utility macros and constants.
 */
#ifndef DEFINE_H
#define DEFINE_H

#ifndef VERSION
#define VERSION "0.1"
#endif
#ifndef PROJECT_NAME
#define PROJECT_NAME "IdSignature"
#endif

#define DEFAULT_SEC_LVL 80
#define DEFAULT_HASH_TYPE sha_1

// Usage tooltip
#define USAGE \
    "Usage: %s [options] <operation> [<input data> ...]\n\
Use -h to know more informations\n\
Operations:\n\
\tsetup                                                              -  generate all the parameters for the scheme and outputs them\n\
\tkeygen <pairing params> <identity> [identity ...]                  -  generate a new key pair for the provided identities\n\
\tdelegate <pairing params> <key> <from> <to>                        -  generate a delegation for the 'to' identity made valid through the use of the secret key belonging to the 'from' identity\n\
\tdel_verify <pairing params> <delegation file>                      -  checks if the delegation in the provided file is valid\n\
\tpk_gen <pairing params> <key> <delegation file>                    -  generate a signing key the delegated user can use to sign on behalf of the original user\n\
\tp_sign <pairing params> <delegation file>  <p_sig file> <message>  -  sign the provided message with the proxy key in the provided file\n\
\tsign_verify <pairing params> <delegation file> <signature file>    -  verify the signature in the provided file\n"

// Help tooltip
#define HELP_TOOLTIP \
    "---------------------------------------------------------------------\n\
" PROJECT_NAME ", version " VERSION "\n\
Usage: %s \n\
---------------------------------------------------------------------\n\
Operations:\n\
\tsetup                                                              -  generate all the parameters for the scheme and outputs them\n\
\tkeygen <pairing params> <identity> [identity ...]                  -  generate a new key pair for the provided identities\n\
\tdelegate <pairing params> <key> <from> <to>                        -  generate a delegation for the 'to' identity made valid through the use of the secret key belonging to the 'from' identity\n\
\tdel_verify <pairing params> <delegation file>                      -  checks if the delegation in the provided file is valid\n\
\tpk_gen <pairing params> <key> <delegation file>                    -  generate a signing key the delegated user can use to sign on behalf of the original user\n\
\tp_sign <pairing params> <delegation file>  <p_sig file> <message>  -  sign the provided message with the proxy key in the provided file\n\
\tsign_verify <pairing params> <delegation file> <signature file>    -  verify the signature in the provided file\n\
---------------------------------------------------------------------\n\
Options:\n\
\t-h  -  shows the help tooltip\n\
\t-v  -  use verbose output\n\
\t-p  -  use precomputation where possible\n\
\t-i  -  use the improved version of the scheme\n\
\t-a  -  hash algorithm [sha1, sha256, sha512] (sha1)\n\
\t-l  -  security level (80)\n\
\t-o  -  redirect output of the application to this file\n\
\t-s  -  if set, use the seed for random functions\n"

#ifndef NVERBOSE
#define VERBOSE_PRINT(...)   \
    if (verbose)             \
    {                        \
        printf(__VA_ARGS__); \
    }
#else
#define VERBOSE_PRINT(...)
#endif

#define PARAMS_ERROR(expected, actual, argv)                                   \
    if (actual < expected)                                                     \
    {                                                                          \
        fprintf(stderr, "Expected %d parameters, got %d\n", expected, actual); \
        fprintf(stderr, USAGE, argv[0]);                                       \
        exit(EXIT_FAILURE);                                                    \
    }

extern int verbose;

#endif // DEFINE_H
