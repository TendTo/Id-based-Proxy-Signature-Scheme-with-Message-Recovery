#include "IdSignature.h"

static FILE *out_stream = NULL;
static short p_flag = 0;

static void main_setup(int sec_lvl, hash_type_t hash_type)
{
    VERBOSE_PRINT("Setup with security level %d and hash type %d\n", sec_lvl, hash_type);
    pbc_param_t pairing_p;
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;

    params_init(pairing_p, sec_lvl);
    setup_from_params(public_p, secret_p, sec_lvl, pairing_p);

    pbc_param_out_str(out_stream, pairing_p);
    element_fprintf(out_stream, "hash_type %d\nP %B\npk %B\nmsk %B\n", hash_type, public_p->P, public_p->pk, secret_p->msk);

    secret_param_clear(secret_p);
    public_param_clear(public_p);
    pbc_param_clear(pairing_p);
    VERBOSE_PRINT("Setup successful and elements cleared!\n");
}

static void main_keygen(char pairing_p_str[], char *ids[], int ids_len)
{
    VERBOSE_PRINT("Generating %d identities with pairing params\n%s\n", ids_len, pairing_p_str);
    sv_user_t user;
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;

    setup_from_str(public_p, secret_p, pairing_p_str);
    if (p_flag)
        public_params_pp(public_p);
    user_init(user, NULL, public_p);
    VERBOSE_PRINT("Elements initialized!\n");

    for (int i = 0; i < ids_len; i++)
    {
        memset(user->id, 0, IDENTITY_SIZE);
        memcpy(user->id, ids[i], STR_IDENTITY_SIZE(ids[i]));
        extract_p(user, public_p);
        extract_s(user, secret_p);
        VERBOSE_PRINT("ID: %s generated\n", ids[i]);
        element_fprintf(out_stream, "ID: %s\nPublic key: %B\nPrivate key: %B\n", ids[i], user->pk, user->sk);
    }

    user_clear(user);
    secret_param_clear(secret_p);
    public_param_clear(public_p);
    VERBOSE_PRINT("Keygen successful and elements cleared!\n");
}

static void main_delegate(char pairing_p_str[], const char sk_str[], const char from_id[], const char to_id[])
{
    VERBOSE_PRINT("Delegating from '%.*s' to '%.*s' with msk %s\nand pairing params\n%s\n", IDENTITY_SIZE, from_id, IDENTITY_SIZE, to_id, sk_str, pairing_p_str);
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    sv_user_t from, to;
    delegation_t w;

    setup_from_str(public_p, secret_p, pairing_p_str);
    if (p_flag)
        public_params_pp(public_p);
    user_init_str(from, from_id, public_p);
    user_init_str(to, to_id, public_p);
    element_set_str(from->sk, sk_str, 10);
    if (p_flag)
        element_pp_init(from->sk_pp, from->sk);
    delegation_init(w, public_p);

    VERBOSE_PRINT("Elements initialized!\n");
    delegate(w, from, to, public_p);
    delegation_fprintf(out_stream, w);

    user_clear(from);
    user_clear(to);
    delegation_clear(w);
    secret_param_clear(secret_p);
    public_param_clear(public_p);
    VERBOSE_PRINT("Delegation successful and elements cleared!\n");
}

static void main_del_verify(char pairing_p_str[], const char delegation_file_path[])
{
    VERBOSE_PRINT("Verifying delegation from file '%s' with pairing params\n%s\n", delegation_file_path, pairing_p_str);
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    delegation_t w;

    setup_from_str(public_p, secret_p, pairing_p_str);
    if (p_flag)
        public_params_pp(public_p);
    delegation_init(w, public_p);
    deserialize_delegation_from_file(w, delegation_file_path);

    VERBOSE_PRINT("Elements initialized!\n");
    int res = del_verify(w, public_p);
    fprintf(out_stream, "Is the delegation from '%.*s' to '%.*s'? %s\n", IDENTITY_SIZE, w->m->from, IDENTITY_SIZE, w->m->to, res ? "YES" : "NO");

    delegation_clear(w);
    secret_param_clear(secret_p);
    public_param_clear(public_p);
    VERBOSE_PRINT("Delegation verification successful and elements cleared!\n");
}

static void main_pk_gen(char pairing_p_str[], const char sk_str[], const char delegation_file_path[])
{
    VERBOSE_PRINT("Generating proxy key with delegation from file '%s', secret key %s and pairing params\n%s\n", delegation_file_path, sk_str, pairing_p_str);
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    sv_user_t user;
    delegation_t w;
    element_t k_sign;

    setup_from_str(public_p, secret_p, pairing_p_str);
    if (p_flag)
        public_params_pp(public_p);
    user_init(user, NULL, public_p);
    element_set_str(user->sk, sk_str, 10);
    if (p_flag)
        element_pp_init(user->sk_pp, user->sk);
    delegation_init(w, public_p);
    deserialize_delegation_from_file(w, delegation_file_path);

    VERBOSE_PRINT("Elements initialized!\n");

    pk_gen(k_sign, user, w, public_p);

    element_fprintf(out_stream, "%B", k_sign);

    user_clear(user);
    delegation_clear(w);
    element_clear(k_sign);
    secret_param_clear(secret_p);
    public_param_clear(public_p);
    VERBOSE_PRINT("Proxy key generation successful and elements cleared!\n");
}

static void main_p_sign(char pairing_p_str[], const char delegation_file_path[], const char k_sig_str[], const char msg[], short imp_flag)
{
    VERBOSE_PRINT("Signing message '%s' with proxy key '%s', delegation from file '%s' and pairing params\n%s\n", msg, k_sig_str, delegation_file_path, pairing_p_str);
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    delegation_t w;
    element_t k_sign;
    proxy_signature_t p_sig;

    setup_from_str(public_p, secret_p, pairing_p_str);
    if (p_flag)
        public_params_pp(public_p);
    delegation_init(w, public_p);
    deserialize_delegation_from_file(w, delegation_file_path);
    element_init_G1(k_sign, public_p->pairing);
    element_set_str(k_sign, k_sig_str, 10);
    proxy_signature_init(p_sig, public_p);

    VERBOSE_PRINT("Elements initialized!\n");

    if (imp_flag)
        imp_p_sign(p_sig, k_sign, w, (uint8_t *)msg, strlen(msg), public_p);
    else
        p_sign(p_sig, k_sign, w, (uint8_t *)msg, strlen(msg), public_p);

    proxy_signature_fprintf(out_stream, p_sig);

    element_clear(k_sign);
    delegation_clear(w);
    proxy_signature_clear(p_sig);
    secret_param_clear(secret_p);
    public_param_clear(public_p);
    VERBOSE_PRINT("Proxy signature successful and elements cleared!\n");
}

static void main_sign_verify(char pairing_p_str[], const char delegation_file_path[], const char p_sig_file_path[], short imp_flag)
{
    VERBOSE_PRINT("Verifying proxy signature from file '%s' with delegation from file '%s' and pairing params\n%s\n", p_sig_file_path, delegation_file_path, pairing_p_str);
    sv_public_params_t public_p;
    sv_secret_params_t secret_p;
    delegation_t w;
    proxy_signature_t p_sig;

    setup_from_str(public_p, secret_p, pairing_p_str);
    if (p_flag)
        public_params_pp(public_p);
    delegation_init(w, public_p);
    deserialize_delegation_from_file(w, delegation_file_path);
    proxy_signature_init(p_sig, public_p);
    deserialize_proxy_signature_from_file(p_sig, p_sig_file_path);

    VERBOSE_PRINT("Elements initialized!\n");

    uint8_t message[public_p->l2];
    int res = 0;
    if (imp_flag)
        res = imp_sign_verify(message, p_sig, public_p);
    else
        res = sign_verify(message, p_sig, public_p);

    fprintf(out_stream, "Is the proxy signature valid? %s\n", res ? "YES" : "NO");
    if (res)
        fprintf(out_stream, "The signed message was: %.*s\n", public_p->l2, message);

    delegation_clear(w);
    proxy_signature_clear(p_sig);
    secret_param_clear(secret_p);
    public_param_clear(public_p);
    VERBOSE_PRINT("Proxy signature verification successful and elements cleared!\n");
}

int main(int argc, char *argv[])
{
    int opt;
    char *op = NULL;
    int sec_lvl = DEFAULT_SEC_LVL, seed = 0, imp_flag = 0;
    hash_type_t hash_type = DEFAULT_HASH_TYPE;

    // Handle inputs
    while ((opt = getopt(argc, argv, ":hvipl:a:s:f:t:o:")) != -1)
    {
        switch (opt)
        {
        case 'h':
            printf(HELP_TOOLTIP, argv[0]);
            exit(EXIT_SUCCESS);
            break;
        case 'v':
            verbose = 1;
            break;
        case 'i':
            imp_flag = 1;
            break;
        case 'p':
            p_flag = 1;
            break;
        case 'l':
            sec_lvl = atoi(optarg);
            break;
        case 'a':
            if (strcmp(optarg, "sha1") == 0)
                hash_type = sha_1;
            else if (strcmp(optarg, "sha256") == 0)
                hash_type = sha_256;
            else if (strcmp(optarg, "sha512") == 0)
                hash_type = sha_512;
            else
            {
                fprintf(stderr, "%s: Invalid hash type: %s\n", argv[0], optarg);
                exit(EXIT_FAILURE);
            }
            break;
        case 's':
            seed = atoi(optarg);
            break;
        case 'o':
            if ((out_stream = fopen(optarg, "w")) == NULL)
            {
                fprintf(stderr, "%s: Could not open file: %s\n", argv[0], optarg);
                exit(EXIT_FAILURE);
            }
            break;
        case '?':
            fprintf(stderr, "%s: Unexpected option: %c\n", argv[0], optopt);
            exit(EXIT_FAILURE);
        case ':':
            fprintf(stderr, "%s: Missing value for: %c\n", argv[0], optopt);
            exit(EXIT_FAILURE);
        default:
            fprintf(stderr, USAGE, argv[0]);
            exit(EXIT_FAILURE);
        }
    }
    PARAMS_ERROR(1, argc - optind, argv);
    op = argv[optind];

    // Random
    if (seed > 0)
    {
        VERBOSE_PRINT("Using seed: %d\n", seed);
        pbc_random_set_deterministic((unsigned int)seed);
    }
    // Redirect output
    if (!out_stream)
    {
        // Set out_stream to stdout
        out_stream = stdout;
    }

    // Operation parsing
    if (strcmp(op, "setup") == 0)
    {
        main_setup(sec_lvl, hash_type);
    }
    else if (strcmp(op, "keygen") == 0)
    {
        PARAMS_ERROR(3, argc - optind, argv);
        main_keygen(argv[optind + 1], argv + optind + 2, argc - optind - 2);
    }
    else if (strcmp(op, "delegate") == 0)
    {
        PARAMS_ERROR(5, argc - optind, argv);
        main_delegate(argv[optind + 1], argv[optind + 2], argv[optind + 3], argv[optind + 4]);
    }
    else if (strcmp(op, "del_verify") == 0)
    {
        PARAMS_ERROR(3, argc - optind, argv);
        main_del_verify(argv[optind + 1], argv[optind + 2]);
    }
    else if (strcmp(op, "pk_gen") == 0)
    {
        PARAMS_ERROR(4, argc - optind, argv);
        main_pk_gen(argv[optind + 1], argv[optind + 2], argv[optind + 3]);
    }
    else if (strcmp(op, "p_sign") == 0)
    {
        PARAMS_ERROR(5, argc - optind, argv);
        main_p_sign(argv[optind + 1], argv[optind + 2], argv[optind + 3], argv[optind + 4], imp_flag);
    }
    else if (strcmp(op, "sign_verify") == 0)
    {
        PARAMS_ERROR(4, argc - optind, argv);
        main_sign_verify(argv[optind + 1], argv[optind + 2], argv[optind + 3], imp_flag);
    }
    else
    {
        fprintf(stderr, "%s: Invalid operation: %s\n", argv[0], op);
        exit(EXIT_FAILURE);
    }

    if (out_stream != stdout)
        fclose(out_stream);

    return EXIT_SUCCESS;
}