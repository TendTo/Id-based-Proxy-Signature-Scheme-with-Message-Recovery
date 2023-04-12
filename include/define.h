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
    "Usage: %s [options] <operation> [<input_data> ...]\n\
Use -h to know more informations\n\
Operations:\n\
\tsetup                                             -  generate all the parameters for the scheme and outputs them\n\
\tkeygen <pairing params> <identity> identity ...]  -  generate a new key pair for the provided identities\n\
\tdelegate <pairing params> <key> <from> <to>       -  generate a delegation for the 'to' identity made valid through the use of the secret key belonging to the 'from' identity\n\
\tdel_verify <pairing params> <r> <S> <from> <to>   -  checks if the provided delegation has been issued by 'from' towards 'to'\n"

// Help tooltip
#define HELP_TOOLTIP \
    "---------------------------------------------------------------------\n\
" PROJECT_NAME ", version " VERSION "\n\
Usage: %s \n\
---------------------------------------------------------------------\n\
Operations:\n\
\tsetup                                             -  generate all the parameters for the scheme and outputs them\n\
\tkeygen <pairing params> <identity> identity ...]  -  generate a new key pair for the provided identities\n\
\tdelegate <pairing params> <key> <from> <to>       -  generate a delegation for the 'to' identity made valid through the use of the secret key belonging to the 'from' identity\n\
\tdel_verify <pairing params> <r> <S> <from> <to>   -  checks if the provided delegation has been issued by 'from' towards 'to'\n\
---------------------------------------------------------------------\n\
Options:\n\
\t-h  -  shows the help tooltip\n\
\t-v  -  use verbose output\n\
\t-a  -  hash algorithm [sha1, sha256, sha512] (sha1)\n\
\t-l  -  security level (80)\n\
\t-o  -  redirect standard output to the provided file\n\
\t-s  -  if set, use the seed for random functions\n"

#endif // DEFINE_H